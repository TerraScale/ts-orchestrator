using System.Collections.Concurrent;
using System.Diagnostics;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Tests;

public sealed class HostWorkloadLifetimeTests
{
    [Test]
    public async Task Lease_loss_stops_and_observes_an_actual_owned_child_process()
    {
        using var lease = new CancellationTokenSource();
        using var native = new ChildProcess();
        await using var lifetime = new HostWorkloadLifetime(native, lease.Token);
        await lifetime.ConvergeAsync(Plan(AdmittedRole.TerraBaseMember), CancellationToken.None);
        await Assert.That(native.Exited).IsFalse();
        lease.Cancel();
        var result = await lifetime.Completion.WaitAsync(TimeSpan.FromSeconds(3));
        await Assert.That(result.State).IsEqualTo("stopped");
        await Assert.That(native.Exited).IsTrue();
    }

    [Test]
    public async Task Lease_loss_stops_both_roles_with_fresh_cleanup_tokens_and_denies_new_work()
    {
        using var lease = new CancellationTokenSource();
        var native = new Native();
        await using var lifetime = new HostWorkloadLifetime(native, lease.Token);
        await lifetime.ConvergeAsync(Plan(AdmittedRole.TerraBaseMember), CancellationToken.None);
        await lifetime.ConvergeAsync(Plan(AdmittedRole.Authentication), CancellationToken.None);
        lease.Cancel();
        var stopped = await lifetime.Completion.WaitAsync(TimeSpan.FromSeconds(2));
        await Assert.That(stopped.State).IsEqualTo("stopped");
        await Assert.That(stopped.StoppedAllocations).IsEqualTo(2);
        await Assert.That(native.StopCalls.Count).IsEqualTo(2);
        await Assert.That(native.Running.Values.All(value => !value)).IsTrue();
        await Assert.That(() => lifetime.ConvergeAsync(Plan(AdmittedRole.Authentication), CancellationToken.None)).Throws<OperationCanceledException>();
        await Task.WhenAll(lifetime.DisposeAsync().AsTask(), lifetime.DisposeAsync().AsTask());
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task A_non_cooperative_start_holds_its_slot_until_it_finishes_then_queued_cleanup_stops_it(bool synchronous)
    {
        using var lease = new CancellationTokenSource();
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var releaseSynchronous = new ManualResetEventSlim();
        var native = new Native { StartBarrier = synchronous ? null : release.Task,
            BeforeStart = synchronous ? () => releaseSynchronous.Wait(TimeSpan.FromSeconds(5)) : null };
        await using var lifetime = new HostWorkloadLifetime(native, lease.Token, TimeSpan.FromMilliseconds(150));
        var start = lifetime.ConvergeAsync(Plan(AdmittedRole.TerraBaseMember), CancellationToken.None);
        await native.Started.Task.WaitAsync(TimeSpan.FromSeconds(2));
        lease.Cancel();
        try
        {
            await Assert.That(() => start.WaitAsync(TimeSpan.FromSeconds(2))).Throws<OperationCanceledException>();
            var uncertain = await lifetime.Completion.WaitAsync(TimeSpan.FromSeconds(2));
            await Assert.That(uncertain.State).IsEqualTo("unconfirmed");
            await Assert.That(uncertain.Need).IsEqualTo("shutdown-deadline-exceeded");
            await Assert.That(native.StopCalls).IsEmpty();
            await lifetime.DisposeAsync();
        }
        finally { release.TrySetResult(); releaseSynchronous.Set(); }
        await UntilAsync(() => lifetime.Snapshot.State == "stopped");
        await Assert.That(native.StopCalls.Count).IsEqualTo(1);
        await Assert.That(native.Running.Values.All(value => !value)).IsTrue();
        await Assert.That((await lifetime.Completion).State).IsEqualTo("unconfirmed");
    }

    [Test]
    [Arguments((int)SystemdAllocationState.Running, 321)]
    [Arguments((int)SystemdAllocationState.Stopping, 321)]
    [Arguments((int)SystemdAllocationState.Stopped, 321)]
    [Arguments((int)SystemdAllocationState.Failed, null)]
    public async Task A_stop_command_without_a_stopped_observation_never_proves_shutdown(int state, int? pid)
    {
        using var lease = new CancellationTokenSource();
        var native = new Native { ForcedObservation = new("unit", (SystemdAllocationState)state, pid, "test") };
        await using var lifetime = new HostWorkloadLifetime(native, lease.Token, TimeSpan.FromMilliseconds(150));
        await lifetime.ConvergeAsync(Plan(AdmittedRole.TerraBaseMember), CancellationToken.None);
        lease.Cancel();
        var result = await lifetime.Completion.WaitAsync(TimeSpan.FromSeconds(2));
        await Assert.That(result.State).IsEqualTo("unconfirmed");
        await Assert.That(result.StoppedAllocations).IsEqualTo(0);
        await Assert.That(native.StopCalls.Count).IsEqualTo(1);
    }

    [Test]
    public async Task One_failed_stop_does_not_prevent_the_other_role_from_stopping()
    {
        using var lease = new CancellationTokenSource();
        var native = new Native { FailingRole = AdmittedRole.TerraBaseMember };
        await using var lifetime = new HostWorkloadLifetime(native, lease.Token);
        await lifetime.ConvergeAsync(Plan(AdmittedRole.TerraBaseMember), CancellationToken.None);
        await lifetime.ConvergeAsync(Plan(AdmittedRole.Authentication), CancellationToken.None);
        lease.Cancel();
        var result = await lifetime.Completion.WaitAsync(TimeSpan.FromSeconds(2));
        await Assert.That(result.State).IsEqualTo("unconfirmed");
        await Assert.That(result.StoppedAllocations).IsEqualTo(1);
        await Assert.That(native.Running[Plan(AdmittedRole.TerraBaseMember).AllocationId.Value]).IsTrue();
        await Assert.That(native.Running[Plan(AdmittedRole.Authentication).AllocationId.Value]).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Cleanup_uses_the_exact_previous_container_plan_and_never_stops_a_foreign_allocation(bool foreign)
    {
        using var lease = new CancellationTokenSource();
        var previous = Plan(AdmittedRole.Authentication);
        var client = new ExistingContainer(previous, foreign);
        await using var lifetime = new HostWorkloadLifetime(new ContainerdHostRuntimeConverger(client), lease.Token);
        if (foreign)
            await Assert.That(() => lifetime.ConvergeAsync(previous, CancellationToken.None)).Throws<InvalidOperationException>();
        else
            await lifetime.ConvergeAsync(previous, CancellationToken.None);
        await Assert.That(() => lifetime.ConvergeAsync(Plan(AdmittedRole.Authentication, 'b'), CancellationToken.None))
            .Throws<InvalidOperationException>();
        lease.Cancel();
        var result = await lifetime.Completion.WaitAsync(TimeSpan.FromSeconds(2));
        await Assert.That(result.State).IsEqualTo(foreign ? "unconfirmed" : "stopped");
        await Assert.That(client.Stops).IsEqualTo(foreign ? 0 : 1);
        await Assert.That(client.Deletes).IsEqualTo(foreign ? 0 : 1);
    }

    [Test]
    public async Task Disposal_stops_work_without_a_lease_callback_or_report_and_an_empty_runtime_is_stopped()
    {
        var native = new Native();
        var lifetime = new HostWorkloadLifetime(native, CancellationToken.None);
        await lifetime.ConvergeAsync(Plan(AdmittedRole.Authentication), CancellationToken.None);
        await lifetime.DisposeAsync();
        await Assert.That((await lifetime.Completion).State).IsEqualTo("stopped");
        await Assert.That(native.StopCalls.Count).IsEqualTo(1);
        var empty = new HostWorkloadLifetime(native, CancellationToken.None);
        await empty.DisposeAsync();
        await Assert.That((await empty.Completion).StoppedAllocations).IsEqualTo(0);
        await Assert.That((await empty.Completion).State).IsEqualTo("stopped");
    }

    private static HostRuntimePlan Plan(AdmittedRole role, char digest = 'a') => HostRuntimePlan.Create(role,
        AdmittedRoleCatalog.Get(role).DefaultDriver, new("shutdown-" + role.ToString().ToLowerInvariant()),
        new(new string(digest, 64)), HostArchitecture.X64);

    private static async Task UntilAsync(Func<bool> condition)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        while (!condition()) await Task.Delay(5, deadline.Token);
    }

    private sealed class Native : IHostRuntimeConverger
    {
        internal ConcurrentDictionary<string, bool> Running { get; } = new();
        internal ConcurrentQueue<string> StopCalls { get; } = new();
        internal TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal Task? StartBarrier { get; init; }
        internal Action? BeforeStart { get; init; }
        internal SystemdAllocationObservation? ForcedObservation { get; init; }
        internal AdmittedRole? FailingRole { get; init; }

        public async Task ConvergeAsync(HostRuntimePlan plan, CancellationToken cancellationToken)
        {
            Started.TrySetResult();
            BeforeStart?.Invoke();
            if (StartBarrier is { } barrier) await barrier;
            Running[plan.AllocationId.Value] = true;
        }

        public Task StopAsync(HostRuntimePlan plan, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            StopCalls.Enqueue(plan.AllocationId.Value);
            if (plan.Role == FailingRole) throw new IOException("Injected native stop failure.");
            Running[plan.AllocationId.Value] = false;
            return Task.CompletedTask;
        }

        public Task<SystemdAllocationObservation> ObserveAsync(HostRuntimePlan plan, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var running = Running.GetValueOrDefault(plan.AllocationId.Value);
            return Task.FromResult(ForcedObservation ?? new(plan.Systemd?.UnitName ?? plan.Oci!.ContainerId,
                running ? SystemdAllocationState.Running : SystemdAllocationState.Absent, running ? 123 : null, "test"));
        }
    }

    internal sealed class ChildProcess : IHostRuntimeConverger, IDisposable
    {
        private Process? child;
        internal bool Exited => child?.HasExited ?? true;
        public Task ConvergeAsync(HostRuntimePlan plan, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            child = Process.Start(new ProcessStartInfo("sleep") { ArgumentList = { "30" }, UseShellExecute = false })
                ?? throw new InvalidOperationException("The owned test child could not start.");
            return Task.CompletedTask;
        }
        public async Task StopAsync(HostRuntimePlan plan, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (child is null || child.HasExited) return;
            child.Kill(entireProcessTree: true);
            await child.WaitForExitAsync(cancellationToken);
        }
        public Task<SystemdAllocationObservation> ObserveAsync(HostRuntimePlan plan, CancellationToken cancellationToken) =>
            Task.FromResult(new SystemdAllocationObservation(plan.Systemd!.UnitName,
                Exited ? SystemdAllocationState.Absent : SystemdAllocationState.Running, Exited ? null : child!.Id, "owned-test-child"));
        public void Dispose()
        {
            if (child is null) return;
            if (!child.HasExited) { child.Kill(entireProcessTree: true); child.WaitForExit(2000); }
            child.Dispose();
        }
    }

    private sealed class ExistingContainer(HostRuntimePlan owner, bool foreign) : IContainerdClient
    {
        private ContainerdAllocationObservation observation = new(owner.Oci!.ContainerId, ContainerdAllocationState.Running,
            owner.Oci.ImageReference, owner.Oci.Platform, foreign ? new string('f', 64) : CanonicalPlanFingerprint.Compute(owner), 123, "test");
        internal int Stops { get; private set; }
        internal int Deletes { get; private set; }
        public Task<ContainerdAllocationObservation> ObserveAsync(string @namespace, string containerId, CancellationToken cancellationToken) =>
            Task.FromResult(observation);
        public Task<string> PullAsync(string @namespace, string imageReference, string platform, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
        public Task CreateAsync(ContainerdCreateRequest request, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task StartAsync(string @namespace, string containerId, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task StopAsync(string @namespace, string containerId, CancellationToken cancellationToken)
        {
            Stops++;
            observation = observation with { State = ContainerdAllocationState.Stopped, ProcessId = null };
            return Task.CompletedTask;
        }
        public Task DeleteAsync(string @namespace, string containerId, CancellationToken cancellationToken)
        {
            Deletes++;
            observation = observation with { State = ContainerdAllocationState.Absent };
            return Task.CompletedTask;
        }
    }
}
