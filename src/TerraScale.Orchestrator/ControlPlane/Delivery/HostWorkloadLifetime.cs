using System.Diagnostics;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

internal sealed record HostAllocationShutdownSnapshot(string AllocationId, RuntimeDriver Driver, string State, string? Need);
internal sealed record HostWorkloadShutdownSnapshot(string State, string? Need, int TotalAllocations,
    int StoppedAllocations, IReadOnlyList<HostAllocationShutdownSnapshot> Allocations);
internal sealed record HostWorkloadRecoverySnapshot(string State, string? Need, int DiscoveredAllocations, int StoppedAllocations)
{
    internal bool Ready => State == "ready";
}

/// <summary>
/// Holds exclusive local supervisor ownership through discovery, recovery, dispatch and cleanup.
/// Public deadlines bound receipts, never the lifetime of underlying native mutations or their lock.
/// This local inventory does not establish physical cgroup or storage-writer fencing.
/// </summary>
internal sealed class HostWorkloadLifetime : IHostRuntimeConverger, IAsyncDisposable
{
    private readonly object gate = new();
    private readonly IHostRuntimeConverger native;
    private readonly HostWorkloadInventory inventory;
    private readonly IHostNativeInventoryProbe probe;
    private readonly TimeSpan shutdownTimeout;
    private readonly TimeSpan recoveryTimeout;
    private readonly CancellationTokenSource execution = new();
    private readonly CancellationToken executionToken;
    private readonly CancellationTokenRegistration shutdownRegistration;
    private readonly Dictionary<(RuntimeDriver Driver, string Id), Allocation> allocations = new();
    private readonly TaskCompletionSource<HostWorkloadShutdownSnapshot> completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource<HostWorkloadRecoverySnapshot> recoveryCompletion = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource ownershipReleased = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Task recovery;
    private HostWorkloadRecoverySnapshot recoverySnapshot = new("recovering", "discover-and-stop-recorded-work", 0, 0);
    private Task? cleanup;
    private Task? disposal;
    private bool closed;
    private bool deadlineExceeded;
    private string? failureNeed;
    private long shutdownStarted;

    internal HostWorkloadLifetime(IHostRuntimeConverger native, CancellationToken executionToken,
        HostWorkloadInventory inventory, IHostNativeInventoryProbe probe,
        TimeSpan? shutdownTimeout = null, TimeSpan? recoveryTimeout = null)
    {
        this.native = native ?? throw new ArgumentNullException(nameof(native));
        this.inventory = inventory ?? throw new ArgumentNullException(nameof(inventory));
        this.probe = probe ?? throw new ArgumentNullException(nameof(probe));
        this.shutdownTimeout = shutdownTimeout ?? RegionalHostSessionLease.ShutdownReserve;
        this.recoveryTimeout = recoveryTimeout ?? TimeSpan.FromSeconds(30);
        if (this.shutdownTimeout <= TimeSpan.Zero || this.shutdownTimeout > RegionalHostSessionLease.ShutdownReserve)
            throw new ArgumentOutOfRangeException(nameof(shutdownTimeout));
        if (this.recoveryTimeout <= TimeSpan.Zero || this.recoveryTimeout > TimeSpan.FromMinutes(2))
            throw new ArgumentOutOfRangeException(nameof(recoveryTimeout));
        foreach (var plan in inventory.Plans) Track(plan).Plans.Add(CanonicalPlanFingerprint.Compute(plan), plan);
        inventory.Claim();
        this.executionToken = execution.Token;
        // Publish the task before any failure can schedule cleanup that must await it.
        lock (gate) recovery = Task.Run(RecoverAsync);
        _ = BoundRecoveryAsync();
        shutdownRegistration = executionToken.UnsafeRegister(static state => ((HostWorkloadLifetime)state!).BeginShutdown(), this);
    }

    /// <summary>The result inside the original shutdown budget. A late stop never rewrites this receipt.</summary>
    internal Task<HostWorkloadShutdownSnapshot> Completion => completion.Task;
    internal Task<HostWorkloadRecoverySnapshot> RecoveryCompletion => recoveryCompletion.Task;
    internal Task OwnershipReleased => ownershipReleased.Task;
    internal HostWorkloadShutdownSnapshot Snapshot { get { lock (gate) return SnapshotLocked(); } }
    internal HostWorkloadRecoverySnapshot RecoverySnapshot { get { lock (gate) return recoverySnapshot; } }

    internal async Task RequireRecoveredAsync(CancellationToken cancellationToken)
    {
        var result = await recoveryCompletion.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        if (!result.Ready) throw new InvalidOperationException("Host workload recovery is blocked: " + result.Need);
        executionToken.ThrowIfCancellationRequested();
    }

    private async Task BoundRecoveryAsync()
    {
        try { await recovery.WaitAsync(recoveryTimeout).ConfigureAwait(false); }
        catch (TimeoutException)
        {
            lock (gate)
            {
                recoverySnapshot = recoverySnapshot with { State = "blocked", Need = "recovery-deadline-exceeded" };
                recoveryCompletion.TrySetResult(recoverySnapshot);
            }
            BeginShutdown();
        }
    }

    private async Task RecoverAsync()
    {
        // Synchronize with publication of recovery in the constructor.
        lock (gate) { }
        using var deadline = new CancellationTokenSource(recoveryTimeout);
        try
        {
            var first = await ScanAsync(deadline.Token).ConfigureAwait(false);
            lock (gate) recoverySnapshot = recoverySnapshot with { DiscoveredAllocations = first.Allocations.Count };
            foreach (var found in first.Allocations)
            {
                deadline.Token.ThrowIfCancellationRequested();
                var allocation = allocations[(found.Driver, found.AllocationId)];
                var plan = allocation.Plans.Values.Single(found.Matches);
                await StopAndObserveAsync(plan, deadline.Token).ConfigureAwait(false);
                lock (gate) recoverySnapshot = recoverySnapshot with { StoppedAllocations = recoverySnapshot.StoppedAllocations + 1 };
            }
            var final = await ScanAsync(deadline.Token).ConfigureAwait(false);
            if (final.Allocations.Any(value => value.State != SystemdAllocationState.Stopped || value.MainProcessId is not null))
                throw new InvalidDataException("Native recovery left an unconfirmed allocation.");
            foreach (var allocation in allocations.Values)
            {
                if (!final.Allocations.Any(value => value.Driver == allocation.Driver && value.AllocationId == allocation.Id))
                    ForgetAbsent(allocation);
                lock (gate) allocation.Status = new(allocation.Id, allocation.Driver, "stopped", null);
            }
            lock (gate)
            {
                if (recoveryCompletion.Task.IsCompleted) return;
                recoverySnapshot = recoverySnapshot with { State = "ready", Need = null };
                recoveryCompletion.TrySetResult(recoverySnapshot);
            }
        }
        catch (Exception)
        {
            lock (gate)
            {
                recoverySnapshot = recoverySnapshot with { State = "blocked", Need = deadline.IsCancellationRequested
                    ? "recovery-deadline-exceeded" : "verify-native-inventory-and-recovery" };
                recoveryCompletion.TrySetResult(recoverySnapshot);
            }
            BeginShutdown();
        }
    }

    private async Task<HostNativeInventorySnapshot> ScanAsync(CancellationToken cancellationToken)
    {
        _ = inventory.Plans; // Recheck local storage before attributing any native object.
        var snapshot = await probe.ReadAsync(inventory.Identity, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (snapshot.Drivers.Count != 2 || !snapshot.Drivers.ToHashSet().SetEquals([RuntimeDriver.NativeSystemd, RuntimeDriver.OciContainer]) ||
            snapshot.Allocations.Count > 32 || snapshot.Allocations.Select(value => (value.Driver, value.AllocationId)).Distinct().Count() != snapshot.Allocations.Count)
            throw new InvalidDataException("Native inventory coverage is incomplete or ambiguous.");
        foreach (var found in snapshot.Allocations)
            if (!allocations.TryGetValue((found.Driver, found.AllocationId), out var allocation) ||
                !Enum.IsDefined(found.State) || found.State == SystemdAllocationState.Absent || found.MainProcessId is <= 0 ||
                !allocation.Plans.Values.Any(found.Matches))
                throw new InvalidDataException("An unexplained native allocation blocks recovery.");
        return snapshot;
    }

    public Task ConvergeAsync(HostRuntimePlan plan, CancellationToken cancellationToken) =>
        RunAsync(plan, async (_, canonical, token) =>
        {
            await native.ConvergeAsync(canonical, token).ConfigureAwait(false);
            return true;
        }, cancellationToken);

    public Task StopAsync(HostRuntimePlan plan, CancellationToken cancellationToken) =>
        RunAsync(plan, async (allocation, _, token) =>
        {
            await StopRecordedAsync(allocation, token).ConfigureAwait(false);
            return true;
        }, cancellationToken);

    public Task<SystemdAllocationObservation> ObserveAsync(HostRuntimePlan plan, CancellationToken cancellationToken) =>
        RunAsync(plan, async (allocation, canonical, token) =>
        {
            var observation = await native.ObserveAsync(canonical, token).ConfigureAwait(false);
            if (observation.State == SystemdAllocationState.Absent && observation.MainProcessId is null) ForgetAbsent(allocation);
            return observation;
        }, cancellationToken);

    private async Task<T> RunAsync<T>(HostRuntimePlan plan, Func<Allocation, HostRuntimePlan, CancellationToken, Task<T>> operation,
        CancellationToken cancellationToken)
    {
        var snapshot = HostRuntimePlanSnapshot.Copy(plan);
        inventory.Identity.RequirePlan(snapshot);
        await RequireRecoveredAsync(cancellationToken).ConfigureAwait(false);
        Allocation allocation;
        lock (gate)
        {
            if (closed) throw new OperationCanceledException(executionToken);
            allocation = Track(snapshot);
        }
        using var work = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, executionToken);
        var workToken = work.Token;
        // The native task retains the slot when cancellation has already returned to its caller.
        return await Task.Run(() => RunSerializedAsync(allocation, snapshot, operation, workToken), workToken)
            .WaitAsync(workToken).ConfigureAwait(false);
    }

    private Allocation Track(HostRuntimePlan plan)
    {
        var key = (plan.Driver, plan.AllocationId.Value);
        if (!allocations.TryGetValue(key, out var allocation))
        {
            if (allocations.Count >= 32) throw new InvalidOperationException("The host allocation inventory is full.");
            allocations.Add(key, allocation = new(plan.Driver, plan.AllocationId.Value));
        }
        return allocation;
    }

    private async Task<T> RunSerializedAsync<T>(Allocation allocation, HostRuntimePlan plan,
        Func<Allocation, HostRuntimePlan, CancellationToken, Task<T>> operation, CancellationToken cancellationToken)
    {
        await allocation.Serial.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            executionToken.ThrowIfCancellationRequested();
            cancellationToken.ThrowIfCancellationRequested();
            HostRuntimePlan canonical;
            try { canonical = inventory.Record(plan); }
            catch { CloseForInventoryFailure(); throw; }
            allocation.Plans[CanonicalPlanFingerprint.Compute(canonical)] = canonical;
            executionToken.ThrowIfCancellationRequested();
            cancellationToken.ThrowIfCancellationRequested();
            lock (gate) allocation.Status = new(allocation.Id, allocation.Driver, "tracked", null);
            return await operation(allocation, canonical, cancellationToken).ConfigureAwait(false);
        }
        finally { allocation.Serial.Release(); }
    }

    private void ForgetAbsent(Allocation allocation)
    {
        try { inventory.ForgetAbsent(allocation.Driver, allocation.Id); }
        catch { CloseForInventoryFailure(); throw; }
        allocation.Plans.Clear();
    }

    private void CloseForInventoryFailure()
    {
        lock (gate)
        {
            failureNeed = "restart-inventory-recovery";
            BeginShutdown();
        }
    }

    private void BeginShutdown()
    {
        lock (gate)
        {
            if (closed) return;
            closed = true;
            shutdownStarted = Stopwatch.GetTimestamp();
            _ = ObserveCancellationAsync(execution.CancelAsync());
            var owned = allocations.Values.ToArray();
            cleanup = Task.Run(async () =>
            {
                // Recovery may contain a non-cooperative scan or stop. It still owns the host.
                await recovery.ConfigureAwait(false);
                await Task.WhenAll(owned.Select(allocation => Task.Run(() => StopAllocationAsync(allocation)))).ConfigureAwait(false);
                inventory.ReleaseSupervisor();
                ownershipReleased.TrySetResult();
            });
            _ = CompleteWithinBudgetAsync(cleanup);
        }
    }

    private static async Task ObserveCancellationAsync(Task cancellation)
    {
        try { await cancellation.ConfigureAwait(false); }
        catch (Exception) { /* Consumer callbacks cannot prevent local cleanup. */ }
    }

    private async Task CompleteWithinBudgetAsync(Task stopping)
    {
        try
        {
            var remaining = shutdownTimeout - Stopwatch.GetElapsedTime(shutdownStarted);
            if (remaining <= TimeSpan.Zero) throw new TimeoutException();
            await stopping.WaitAsync(remaining).ConfigureAwait(false);
        }
        catch (TimeoutException) { lock (gate) deadlineExceeded = true; }
        lock (gate)
        {
            deadlineExceeded |= Stopwatch.GetElapsedTime(shutdownStarted) >= shutdownTimeout;
            var result = SnapshotLocked();
            completion.TrySetResult(deadlineExceeded
                ? result with { State = "unconfirmed", Need = "shutdown-deadline-exceeded" } : result);
        }
    }

    private async Task StopAllocationAsync(Allocation allocation)
    {
        lock (gate) allocation.Status = new(allocation.Id, allocation.Driver, "stopping", null);
        await allocation.Serial.WaitAsync().ConfigureAwait(false);
        try
        {
            using var deadline = new CancellationTokenSource(shutdownTimeout);
            // Never abandon this task with WaitAsync: a late stop could otherwise hit the next supervisor's work.
            await StopRecordedAsync(allocation, deadline.Token).ConfigureAwait(false);
            lock (gate) allocation.Status = new(allocation.Id, allocation.Driver, "stopped", null);
        }
        catch (Exception)
        {
            lock (gate) allocation.Status = new(allocation.Id, allocation.Driver, "unconfirmed", "verify-native-stop");
        }
        finally { allocation.Serial.Release(); }
    }

    private async Task StopRecordedAsync(Allocation allocation, CancellationToken cancellationToken)
    {
        Exception? failure = null;
        foreach (var plan in allocation.Plans.Values.Reverse())
        {
            try
            {
                var observation = await StopAndObserveAsync(plan, cancellationToken).ConfigureAwait(false);
                if (observation.State == SystemdAllocationState.Absent) ForgetAbsent(allocation);
                return;
            }
            catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
            {
                // Exact previous plans may own this allocation after a failed upgrade.
                failure = exception;
            }
        }
        cancellationToken.ThrowIfCancellationRequested();
        if (failure is not null) throw new InvalidOperationException("No recorded plan confirmed native shutdown.", failure);
    }

    private async Task<SystemdAllocationObservation> StopAndObserveAsync(HostRuntimePlan plan, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await native.StopAsync(plan, cancellationToken).ConfigureAwait(false);
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var observation = await native.ObserveAsync(plan, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (observation.State is SystemdAllocationState.Absent or SystemdAllocationState.Stopped && observation.MainProcessId is null)
                return observation;
            await Task.Delay(TimeSpan.FromMilliseconds(50), cancellationToken).ConfigureAwait(false);
        }
    }

    private HostWorkloadShutdownSnapshot SnapshotLocked()
    {
        var observations = allocations.Values.Select(value => value.Status).OrderBy(value => value.AllocationId, StringComparer.Ordinal)
            .ThenBy(value => value.Driver).ToArray();
        var stopped = observations.Count(value => value.State == "stopped");
        var confirmed = closed && stopped == observations.Length && recoverySnapshot.Ready;
        return new(!closed ? "active" : confirmed ? "stopped" : deadlineExceeded || recoverySnapshot.State == "blocked" || observations.Any(value => value.State == "unconfirmed")
                ? "unconfirmed" : "stopping",
            failureNeed ?? (!closed || confirmed ? null : deadlineExceeded ? "shutdown-deadline-exceeded" : "verify-native-stop"),
            observations.Length, stopped, observations);
    }

    public ValueTask DisposeAsync() { lock (gate) return new(disposal ??= DisposeCoreAsync()); }

    private async Task DisposeCoreAsync()
    {
        BeginShutdown();
        await completion.Task.ConfigureAwait(false);
        await shutdownRegistration.DisposeAsync().ConfigureAwait(false);
        _ = DisposeAfterCleanupAsync();
    }

    private async Task DisposeAfterCleanupAsync()
    {
        await cleanup!.ConfigureAwait(false);
        execution.Dispose();
    }

    private sealed class Allocation(RuntimeDriver driver, string id)
    {
        internal RuntimeDriver Driver { get; } = driver;
        internal string Id { get; } = id;
        internal SemaphoreSlim Serial { get; } = new(1, 1);
        internal Dictionary<string, HostRuntimePlan> Plans { get; } = new(StringComparer.Ordinal);
        internal HostAllocationShutdownSnapshot Status { get; set; } = new(id, driver, "tracked", null);
    }
}
