using System.Diagnostics;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

internal sealed record HostAllocationShutdownSnapshot(string AllocationId, string State, string? Need);
internal sealed record HostWorkloadShutdownSnapshot(string State, string? Need, int TotalAllocations,
    int StoppedAllocations, IReadOnlyList<HostAllocationShutdownSnapshot> Allocations);

/// <summary>
/// Serializes native operations against local shutdown. A cancelled caller never releases
/// an operation's slot while the underlying mutation is still in flight. This inventory is
/// process-local; restart recovery and storage writer fencing require separate evidence.
/// </summary>
internal sealed class HostWorkloadLifetime : IHostRuntimeConverger, IAsyncDisposable
{
    private readonly object gate = new();
    private readonly IHostRuntimeConverger native;
    private readonly TimeSpan shutdownTimeout;
    private readonly CancellationTokenSource execution = new();
    private readonly CancellationToken executionToken;
    private readonly CancellationTokenRegistration shutdownRegistration;
    private readonly Dictionary<string, Allocation> allocations = new(StringComparer.Ordinal);
    private readonly TaskCompletionSource<HostWorkloadShutdownSnapshot> completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private Task? cleanup;
    private Task? disposal;
    private bool closed;
    private bool deadlineExceeded;
    private long shutdownStarted;

    internal HostWorkloadLifetime(IHostRuntimeConverger native, CancellationToken executionToken,
        TimeSpan? shutdownTimeout = null)
    {
        this.native = native ?? throw new ArgumentNullException(nameof(native));
        this.shutdownTimeout = shutdownTimeout ?? RegionalHostSessionLease.ShutdownReserve;
        if (this.shutdownTimeout <= TimeSpan.Zero || this.shutdownTimeout > RegionalHostSessionLease.ShutdownReserve)
            throw new ArgumentOutOfRangeException(nameof(shutdownTimeout));
        this.executionToken = execution.Token;
        shutdownRegistration = executionToken.UnsafeRegister(static state => ((HostWorkloadLifetime)state!).BeginShutdown(), this);
    }

    /// <summary>The result inside the original shutdown budget. A late stop never rewrites this receipt.</summary>
    internal Task<HostWorkloadShutdownSnapshot> Completion => completion.Task;
    internal HostWorkloadShutdownSnapshot Snapshot { get { lock (gate) return SnapshotLocked(); } }

    public Task ConvergeAsync(HostRuntimePlan plan, CancellationToken cancellationToken) =>
        RunAsync(plan, async (allocation, token) =>
        {
            await native.ConvergeAsync(plan, token).ConfigureAwait(false);
            return true;
        }, cancellationToken);

    public Task StopAsync(HostRuntimePlan plan, CancellationToken cancellationToken) =>
        RunAsync(plan, async (allocation, token) =>
        {
            await StopAndObserveAsync(plan, token).ConfigureAwait(false);
            allocation.Plans.Clear();
            return true;
        }, cancellationToken);

    public Task<SystemdAllocationObservation> ObserveAsync(HostRuntimePlan plan, CancellationToken cancellationToken) =>
        RunAsync(plan, async (allocation, token) =>
        {
            var observation = await native.ObserveAsync(plan, token).ConfigureAwait(false);
            if (Stopped(observation)) allocation.Plans.Clear();
            return observation;
        }, cancellationToken);

    private async Task<T> RunAsync<T>(HostRuntimePlan plan, Func<Allocation, CancellationToken, Task<T>> operation,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        Allocation allocation;
        lock (gate)
        {
            if (closed) throw new OperationCanceledException(executionToken);
            if (!allocations.TryGetValue(plan.AllocationId.Value, out allocation!))
            {
                if (allocations.Count >= 32) throw new InvalidOperationException("The host allocation inventory is full.");
                allocations.Add(plan.AllocationId.Value, allocation = new(plan.AllocationId.Value));
            }
        }
        using var work = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, executionToken);
        // Only the underlying operation releases the slot. WaitAsync bounds the caller,
        // while cleanup remains queued behind any non-cooperative native mutation.
        var workToken = work.Token;
        return await Task.Run(() => RunSerializedAsync(allocation, plan, operation, workToken), workToken)
            .WaitAsync(workToken).ConfigureAwait(false);
    }

    private async Task<T> RunSerializedAsync<T>(Allocation allocation, HostRuntimePlan plan,
        Func<Allocation, CancellationToken, Task<T>> operation, CancellationToken cancellationToken)
    {
        await allocation.Serial.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            executionToken.ThrowIfCancellationRequested();
            cancellationToken.ThrowIfCancellationRequested();
            var fingerprint = CanonicalPlanFingerprint.Compute(plan);
            if (allocation.Plans.Count >= 32 && !allocation.Plans.ContainsKey(fingerprint))
                throw new InvalidOperationException("The host allocation has too many unresolved plans.");
            // Record before dispatch: a lost response or report ACK cannot erase ownership.
            allocation.Plans[fingerprint] = plan;
            return await operation(allocation, cancellationToken).ConfigureAwait(false);
        }
        finally { allocation.Serial.Release(); }
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
            // Run outside cancellation callbacks and the inventory lock. NATS, desired
            // state, report acknowledgements and the cancelled work token are unnecessary.
            cleanup = Task.WhenAll(owned.Select(allocation => Task.Run(() => StopAllocationAsync(allocation))));
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
        lock (gate) allocation.Status = new(allocation.Id, "stopping", null);
        // Do not pretend a timed-out start is finished. Keep cleanup queued even after
        // the public shutdown budget expires, so a late start is followed by a stop.
        await allocation.Serial.WaitAsync().ConfigureAwait(false);
        try
        {
            using var deadline = new CancellationTokenSource(shutdownTimeout);
            var confirmed = allocation.Plans.Count == 0;
            foreach (var plan in allocation.Plans.Values.Reverse())
            {
                try
                {
                    await StopAndObserveAsync(plan, deadline.Token).WaitAsync(deadline.Token).ConfigureAwait(false);
                    confirmed = true;
                    break;
                }
                catch (Exception) when (!deadline.IsCancellationRequested)
                {
                    // An exact previous plan may own this allocation after a failed upgrade.
                    // Each adapter must enforce ownership before performing any stop.
                }
                catch (OperationCanceledException) when (deadline.IsCancellationRequested) { break; }
            }
            if (confirmed) allocation.Plans.Clear();
            lock (gate) allocation.Status = new(allocation.Id,
                confirmed ? "stopped" : "unconfirmed", confirmed ? null : "verify-native-stop");
        }
        catch (Exception)
        {
            lock (gate) allocation.Status = new(allocation.Id, "unconfirmed", "verify-native-stop");
        }
        finally { allocation.Serial.Release(); }
    }

    private async Task StopAndObserveAsync(HostRuntimePlan plan, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await native.StopAsync(plan, cancellationToken).ConfigureAwait(false);
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var observation = await native.ObserveAsync(plan, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (Stopped(observation)) return;
            await Task.Delay(TimeSpan.FromMilliseconds(50), cancellationToken).ConfigureAwait(false);
        }
    }

    private static bool Stopped(SystemdAllocationObservation observation) =>
        observation.State is SystemdAllocationState.Absent or SystemdAllocationState.Stopped && observation.MainProcessId is null;

    private HostWorkloadShutdownSnapshot SnapshotLocked()
    {
        var observations = allocations.Values.Select(value => value.Status).OrderBy(value => value.AllocationId, StringComparer.Ordinal).ToArray();
        var stopped = observations.Count(value => value.State == "stopped");
        var confirmed = closed && stopped == observations.Length;
        return new(!closed ? "active" : confirmed ? "stopped" : deadlineExceeded || observations.Any(value => value.State == "unconfirmed")
                ? "unconfirmed" : "stopping",
            !closed || confirmed ? null : deadlineExceeded ? "shutdown-deadline-exceeded" : "verify-native-stop",
            observations.Length, stopped, observations);
    }

    public ValueTask DisposeAsync() { lock (gate) return new(disposal ??= DisposeCoreAsync()); }

    private async Task DisposeCoreAsync()
    {
        BeginShutdown();
        await completion.Task.ConfigureAwait(false);
        await shutdownRegistration.DisposeAsync().ConfigureAwait(false);
        // A non-cooperative mutation may outlive Dispose. Its queued cleanup still needs
        // the execution source and slot; release them only after it has actually settled.
        _ = DisposeAfterCleanupAsync();
    }

    private async Task DisposeAfterCleanupAsync()
    {
        await cleanup!.ConfigureAwait(false);
        execution.Dispose();
        // Async-only semaphores have no wait handle. Let them be collected after any
        // cancelled queued callers unwind, instead of disposing beneath their Release.
    }

    private sealed class Allocation(string id)
    {
        internal string Id { get; } = id;
        internal SemaphoreSlim Serial { get; } = new(1, 1);
        internal Dictionary<string, HostRuntimePlan> Plans { get; } = new(StringComparer.Ordinal);
        internal HostAllocationShutdownSnapshot Status { get; set; } = new(id, "tracked", null);
    }
}
