using System.Collections.Concurrent;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Tests;

public sealed class HostWorkloadRecoveryTests
{
    [Test]
    public async Task Lease_loss_during_durable_write_prevents_the_later_native_dispatch()
    {
        using var lease = new CancellationTokenSource();
        using var release = new ManualResetEventSlim();
        var writing = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var block = false;
        await using var files = new HostInventoryFixture(afterWrite: stage =>
        {
            if (block && stage == HostInventoryWriteStage.FileFlushed)
            {
                writing.TrySetResult();
                if (!release.Wait(TimeSpan.FromSeconds(5))) throw new IOException("Test write barrier expired.");
            }
        });
        var native = new Native();
        await using var lifetime = new HostWorkloadLifetime(native, lease.Token, files.Inventory, native,
            shutdownTimeout: TimeSpan.FromMilliseconds(150));
        await lifetime.RequireRecoveredAsync(CancellationToken.None);
        block = true;
        var start = lifetime.ConvergeAsync(files.Plan(), CancellationToken.None);
        try
        {
            await writing.Task.WaitAsync(TimeSpan.FromSeconds(2));
            lease.Cancel();
            await Assert.That(() => start).Throws<OperationCanceledException>();
            await lifetime.Completion.WaitAsync(TimeSpan.FromSeconds(2));
            await Assert.That(lifetime.OwnershipReleased.IsCompleted).IsFalse();
            await Assert.That(native.Starts).IsEqualTo(0);
        }
        finally { release.Set(); }
        await lifetime.OwnershipReleased.WaitAsync(TimeSpan.FromSeconds(2));
        await Assert.That(native.Starts).IsEqualTo(0);
    }

    [Test]
    public async Task Recovery_stops_both_drivers_of_the_same_allocation_before_accepting_new_work()
    {
        await using var files = new HostInventoryFixture();
        var native = new Native();
        var systemd = files.Plan();
        var container = files.Plan(driver: RuntimeDriver.OciContainer);
        foreach (var plan in new[] { systemd, container }) { files.Inventory.Record(plan); native.Seed(plan); }
        await using var lifetime = new HostWorkloadLifetime(native, CancellationToken.None, files.Inventory, native);
        await lifetime.RequireRecoveredAsync(CancellationToken.None);
        await Assert.That(lifetime.RecoverySnapshot.DiscoveredAllocations).IsEqualTo(2);
        await Assert.That(lifetime.RecoverySnapshot.StoppedAllocations).IsEqualTo(2);
        await Assert.That(native.Stops).IsEqualTo(2);
        await Assert.That(native.Entries).IsEmpty();
        await Assert.That(files.Inventory.Plans).IsEmpty();
        await lifetime.ConvergeAsync(systemd, CancellationToken.None);
        await Assert.That(native.Starts).IsEqualTo(1);
    }

    [Test]
    public async Task Recovery_preserves_evidence_for_a_stopped_object_that_still_exists()
    {
        await using var files = new HostInventoryFixture();
        var native = new Native { RetainStopped = true };
        files.Inventory.Record(files.Plan());
        native.Seed(files.Plan());
        await using var lifetime = new HostWorkloadLifetime(native, CancellationToken.None, files.Inventory, native);
        await lifetime.RequireRecoveredAsync(CancellationToken.None);
        await Assert.That(files.Inventory.Plans.Count).IsEqualTo(1);
        await Assert.That(native.Entries.Values.Single().State).IsEqualTo(SystemdAllocationState.Stopped);
    }

    [Test]
    [Arguments("foreign")]
    [Arguments("missing-record")]
    [Arguments("partial-coverage")]
    [Arguments("duplicates")]
    [Arguments("stopped-with-pid")]
    public async Task Unexplained_or_incomplete_native_inventory_never_becomes_ready(string fault)
    {
        await using var files = new HostInventoryFixture();
        var native = new Native { RetainStopped = fault == "stopped-with-pid", RetainPid = fault == "stopped-with-pid" };
        var plan = files.Plan();
        if (fault != "missing-record") files.Inventory.Record(plan);
        native.Seed(fault == "foreign" ? files.Plan(digest: 'b') : plan);
        var probe = new HostInventoryFixture.Probe { Read = async (identity, token) =>
        {
            var snapshot = await native.ReadAsync(identity, token);
            return fault switch
            {
                "partial-coverage" => snapshot with { Drivers = [RuntimeDriver.NativeSystemd] },
                "duplicates" => snapshot with { Allocations = [.. snapshot.Allocations, .. snapshot.Allocations] },
                _ => snapshot
            };
        } };
        await using var lifetime = new HostWorkloadLifetime(native, CancellationToken.None, files.Inventory, probe,
            shutdownTimeout: TimeSpan.FromMilliseconds(200), recoveryTimeout: TimeSpan.FromMilliseconds(250));
        await Assert.That((await lifetime.RecoveryCompletion.WaitAsync(TimeSpan.FromSeconds(3))).Ready).IsFalse();
        await Assert.That(() => lifetime.ConvergeAsync(plan, CancellationToken.None)).Throws<InvalidOperationException>();
        await Assert.That(native.Starts).IsEqualTo(0);
        if (fault is "foreign" or "missing-record") await Assert.That(native.Stops).IsEqualTo(0);
        await lifetime.OwnershipReleased.WaitAsync(TimeSpan.FromSeconds(3));
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    public async Task A_durability_failure_never_dispatches_native_work(int stage)
    {
        var fail = false;
        await using var files = new HostInventoryFixture(afterWrite: reached =>
        {
            if (fail && (int)reached == stage) throw new IOException("injected persistence failure");
        });
        var native = new Native();
        await using var lifetime = new HostWorkloadLifetime(native, CancellationToken.None, files.Inventory, native);
        await lifetime.RequireRecoveredAsync(CancellationToken.None);
        fail = true;
        var rejected = false;
        try { await lifetime.ConvergeAsync(files.Plan(), CancellationToken.None); }
        catch (Exception exception) when (exception is IOException or OperationCanceledException) { rejected = true; }
        await Assert.That(rejected).IsTrue();
        await lifetime.OwnershipReleased.WaitAsync(TimeSpan.FromSeconds(2));
        await Assert.That(native.Starts).IsEqualTo(0);
        await Assert.That(lifetime.Snapshot.Need).IsEqualTo("restart-inventory-recovery");
        using var recovered = HostWorkloadInventory.Open(files.Directory, files.Identity);
        await Assert.That(recovered.Plans.Count).IsEqualTo(stage == 0 ? 0 : 1);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Late_native_stop_retains_ownership_beyond_the_public_shutdown_receipt(bool duringRecovery)
    {
        await using var files = new HostInventoryFixture();
        using var lease = new CancellationTokenSource();
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var native = new Native { StopBarrier = release.Task };
        if (duringRecovery) { files.Inventory.Record(files.Plan()); native.Seed(files.Plan()); }
        await using var lifetime = new HostWorkloadLifetime(native, lease.Token, files.Inventory, native,
            shutdownTimeout: TimeSpan.FromMilliseconds(150), recoveryTimeout: TimeSpan.FromMilliseconds(150));
        try
        {
            if (!duringRecovery)
            {
                await lifetime.ConvergeAsync(files.Plan(), CancellationToken.None);
                lease.Cancel();
            }
            await native.Stopping.Task.WaitAsync(TimeSpan.FromSeconds(2));
            var receipt = await lifetime.Completion.WaitAsync(TimeSpan.FromSeconds(2));
            await Assert.That(receipt.State).IsEqualTo("unconfirmed");
            await lifetime.DisposeAsync();
            await Assert.That(lifetime.OwnershipReleased.IsCompleted).IsFalse();
            await Assert.That(HostWorkloadInventoryTests.Rejected(() => HostWorkloadInventory.Open(files.Directory, files.Identity))).IsTrue();
        }
        finally { release.TrySetResult(); }
        await lifetime.OwnershipReleased.WaitAsync(TimeSpan.FromSeconds(2));
        using var next = HostWorkloadInventory.Open(files.Directory, files.Identity);
        await Assert.That(native.Entries).IsEmpty();
        await Assert.That((await lifetime.Completion).State).IsEqualTo("unconfirmed");
    }

    [Test]
    public async Task Recovery_deadline_does_not_release_ownership_beneath_a_non_cooperative_probe()
    {
        await using var files = new HostInventoryFixture();
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var native = new Native();
        var probe = new HostInventoryFixture.Probe { Read = async (identity, token) =>
        {
            await release.Task;
            return await native.ReadAsync(identity, token);
        } };
        await using var lifetime = new HostWorkloadLifetime(native, CancellationToken.None, files.Inventory, probe,
            shutdownTimeout: TimeSpan.FromMilliseconds(150), recoveryTimeout: TimeSpan.FromMilliseconds(150));
        try
        {
            await Assert.That((await lifetime.RecoveryCompletion.WaitAsync(TimeSpan.FromSeconds(2))).Need).IsEqualTo("recovery-deadline-exceeded");
            await lifetime.Completion.WaitAsync(TimeSpan.FromSeconds(2));
            await Assert.That(lifetime.OwnershipReleased.IsCompleted).IsFalse();
        }
        finally { release.TrySetResult(); }
        await lifetime.OwnershipReleased.WaitAsync(TimeSpan.FromSeconds(2));
        await Assert.That(lifetime.RecoverySnapshot.Ready).IsFalse();
    }

    [Test]
    public async Task Explicit_replacement_uses_the_previous_recorded_owner_after_a_failed_candidate()
    {
        await using var files = new HostInventoryFixture();
        var native = new Native();
        await using var lifetime = new HostWorkloadLifetime(native, CancellationToken.None, files.Inventory, native);
        await lifetime.ConvergeAsync(files.Plan(), CancellationToken.None);
        await Assert.That(() => lifetime.ConvergeAsync(files.Plan(digest: 'b'), CancellationToken.None)).Throws<InvalidOperationException>();
        await lifetime.StopAsync(files.Plan(digest: 'b'), CancellationToken.None);
        await Assert.That(native.Stops).IsEqualTo(1);
        await lifetime.ConvergeAsync(files.Plan(digest: 'b'), CancellationToken.None);
        await Assert.That(native.Entries.Values.Single().Fingerprint).IsEqualTo(CanonicalPlanFingerprint.Compute(files.Plan(digest: 'b')));
    }

    internal sealed class Native : IHostRuntimeConverger, IHostNativeInventoryProbe
    {
        internal ConcurrentDictionary<(RuntimeDriver, string), HostNativeAllocation> Entries { get; } = new();
        internal TaskCompletionSource Stopping { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal Task? StopBarrier { get; init; }
        internal bool RetainStopped { get; init; }
        internal bool RetainPid { get; init; }
        internal int Starts;
        internal int Stops;
        internal void Seed(HostRuntimePlan plan) => Entries[(plan.Driver, plan.AllocationId.Value)] = new(plan.Driver,
            plan.AllocationId.Value, CanonicalPlanFingerprint.Compute(plan), SystemdAllocationState.Running, 123,
            plan.Oci?.ImageReference, plan.Oci?.Platform);
        public Task ConvergeAsync(HostRuntimePlan plan, CancellationToken cancellationToken)
        {
            if (Entries.TryGetValue((plan.Driver, plan.AllocationId.Value), out var found) && !found.Matches(plan))
                throw new InvalidOperationException("different owner");
            Interlocked.Increment(ref Starts);
            Seed(plan);
            return Task.CompletedTask;
        }
        public async Task StopAsync(HostRuntimePlan plan, CancellationToken cancellationToken)
        {
            var key = (plan.Driver, plan.AllocationId.Value);
            if (!Entries.TryGetValue(key, out var found)) return;
            if (!found.Matches(plan)) throw new InvalidOperationException("different owner");
            Interlocked.Increment(ref Stops);
            Stopping.TrySetResult();
            if (StopBarrier is not null) await StopBarrier;
            if (RetainStopped) Entries[key] = found with { State = SystemdAllocationState.Stopped, MainProcessId = RetainPid ? 123 : null };
            else Entries.TryRemove(key, out _);
        }
        public Task<SystemdAllocationObservation> ObserveAsync(HostRuntimePlan plan, CancellationToken cancellationToken)
        {
            var found = Entries.GetValueOrDefault((plan.Driver, plan.AllocationId.Value));
            return Task.FromResult(new SystemdAllocationObservation(plan.Systemd?.UnitName ?? plan.Oci!.ContainerId,
                found?.State ?? SystemdAllocationState.Absent, found?.MainProcessId, "test"));
        }
        public Task<HostNativeInventorySnapshot> ReadAsync(HostWorkloadIdentity identity, CancellationToken cancellationToken) =>
            Task.FromResult(new HostNativeInventorySnapshot([RuntimeDriver.NativeSystemd, RuntimeDriver.OciContainer], Entries.Values.ToArray()));
    }
}
