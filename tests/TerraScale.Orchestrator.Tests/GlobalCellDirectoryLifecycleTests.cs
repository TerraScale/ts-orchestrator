using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

public sealed class GlobalCellDirectoryLifecycleTests
{
    [Test]
    public async Task InitialFailureRetriesAndRunningDirectoryIsObservable()
    {
        using var cancellation = new CancellationTokenSource();
        var firstRetry = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var secondStart = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var failures = new List<Exception>();
        var attempts = 0;
        var running = new FakeDirectoryRuntime(HealthySnapshot());
        await using var lifecycle = GlobalCellDirectoryLifecycle.StartForTesting(
            async token =>
            {
                if (Interlocked.Increment(ref attempts) == 1)
                    throw new InvalidOperationException("directory unavailable");
                secondStart.SetResult();
                return running;
            },
            null,
            static _ => TimeSpan.Zero,
            async (_, token) =>
            {
                firstRetry.SetResult();
                await Task.Yield();
            },
            cancellation.Token,
            failures.Add);

        await firstRetry.Task.WaitAsync(TimeSpan.FromSeconds(1));
        await secondStart.Task.WaitAsync(TimeSpan.FromSeconds(1));
        await EventuallyAsync(() => lifecycle.Health == GlobalCellDirectoryCondition.Healthy);

        await Assert.That(attempts).IsEqualTo(2);
        await Assert.That(failures).HasSingleItem();
        await Assert.That(lifecycle.Snapshot.ActiveCells).IsEqualTo(1);
        await Assert.That(lifecycle.Snapshot.StaleCells).IsEqualTo(0);
    }

    [Test]
    public async Task CompletionFaultDisposesServiceAndDirectoryBeforeRestart()
    {
        using var cancellation = new CancellationTokenSource();
        var firstStart = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var secondStart = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var first = new FakeDirectoryRuntime(HealthySnapshot());
        var second = new FakeDirectoryRuntime(HealthySnapshot());
        var firstService = new FakeServiceRuntime();
        var secondService = new FakeServiceRuntime();
        var attempts = 0;
        await using var lifecycle = GlobalCellDirectoryLifecycle.StartForTesting(
            token =>
            {
                if (Interlocked.Increment(ref attempts) == 1)
                {
                    firstStart.SetResult();
                    return Task.FromResult<IGlobalCellDirectoryRuntimeInstance>(first);
                }

                secondStart.SetResult();
                return Task.FromResult<IGlobalCellDirectoryRuntimeInstance>(second);
            },
            (runtime, token) => Task.FromResult<IGlobalCellDirectoryServiceRuntimeInstance?>(
                ReferenceEquals(runtime, first) ? firstService : secondService),
            static _ => TimeSpan.Zero,
            static (_, _) => Task.CompletedTask,
            cancellation.Token);

        await firstStart.Task.WaitAsync(TimeSpan.FromSeconds(1));
        first.Stop(new InvalidOperationException("watcher stopped"));
        await secondStart.Task.WaitAsync(TimeSpan.FromSeconds(1));
        await EventuallyAsync(() => first.DisposalCount == 1 && firstService.DisposalCount == 1);
        await Assert.That(lifecycle.Health).IsEqualTo(GlobalCellDirectoryCondition.Healthy);

        await lifecycle.DisposeAsync();
        await Assert.That(second.DisposalCount).IsEqualTo(1);
        await Assert.That(secondService.DisposalCount).IsEqualTo(1);
    }

    [Test]
    public async Task CancellationStopsRetryDelayAndLeavesDirectoryUnavailable()
    {
        using var cancellation = new CancellationTokenSource();
        var delayEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var attempts = 0;
        await using var lifecycle = GlobalCellDirectoryLifecycle.StartForTesting(
            token =>
            {
                Interlocked.Increment(ref attempts);
                return Task.FromException<IGlobalCellDirectoryRuntimeInstance>(
                    new InvalidOperationException("directory unavailable"));
            },
            null,
            static _ => TimeSpan.FromHours(1),
            async (_, token) =>
            {
                delayEntered.SetResult();
                await Task.Delay(Timeout.InfiniteTimeSpan, token);
            },
            cancellation.Token);

        await delayEntered.Task.WaitAsync(TimeSpan.FromSeconds(1));
        await cancellation.CancelAsync();
        await lifecycle.Completion.WaitAsync(TimeSpan.FromSeconds(1));
        await lifecycle.Snapshot.ValidateUnavailableAsync();
        await Assert.That(attempts).IsEqualTo(1);
    }

    [Test]
    public async Task FailureObserverCannotStopBoundedRetrySupervision()
    {
        using var cancellation = new CancellationTokenSource();
        var retryEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var secondStart = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var attempts = 0;
        await using var lifecycle = GlobalCellDirectoryLifecycle.StartForTesting(
            token =>
            {
                if (Interlocked.Increment(ref attempts) == 1)
                    return Task.FromException<IGlobalCellDirectoryRuntimeInstance>(
                        new InvalidOperationException("directory unavailable"));

                secondStart.SetResult();
                return Task.FromResult<IGlobalCellDirectoryRuntimeInstance>(
                    new FakeDirectoryRuntime(HealthySnapshot()));
            },
            null,
            static _ => TimeSpan.Zero,
            async (_, token) =>
            {
                retryEntered.SetResult();
                await Task.Yield();
            },
            cancellation.Token,
            _ => throw new InvalidOperationException("observer failed"));

        await retryEntered.Task.WaitAsync(TimeSpan.FromSeconds(1));
        await secondStart.Task.WaitAsync(TimeSpan.FromSeconds(1));
        await EventuallyAsync(() => lifecycle.Health == GlobalCellDirectoryCondition.Healthy);
        await Assert.That(attempts).IsEqualTo(2);
    }

    [Test]
    public async Task CancellationSuppressesInstanceDisposeCancellation()
    {
        using var cancellation = new CancellationTokenSource();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var directory = new FakeDirectoryRuntime(HealthySnapshot(),
            new OperationCanceledException("directory shutdown"));
        var service = new FakeServiceRuntime(new OperationCanceledException("service shutdown"));
        await using var lifecycle = GlobalCellDirectoryLifecycle.StartForTesting(
            token =>
            {
                started.SetResult();
                return Task.FromResult<IGlobalCellDirectoryRuntimeInstance>(directory);
            },
            (runtime, token) => Task.FromResult<IGlobalCellDirectoryServiceRuntimeInstance?>(service),
            static _ => TimeSpan.Zero,
            static (_, _) => Task.CompletedTask,
            cancellation.Token);

        await started.Task.WaitAsync(TimeSpan.FromSeconds(1));
        await cancellation.CancelAsync();
        await lifecycle.Completion.WaitAsync(TimeSpan.FromSeconds(1));
        await Assert.That(directory.DisposalCount).IsEqualTo(1);
        await Assert.That(service.DisposalCount).IsEqualTo(1);
    }

    private static async Task EventuallyAsync(Func<bool> condition)
    {
        for (var attempt = 0; attempt < 100; attempt++)
        {
            if (condition()) return;
            await Task.Delay(TimeSpan.FromMilliseconds(10));
        }

        throw new TimeoutException("The supervised directory state did not converge.");
    }

    private static GlobalCellDirectorySnapshot HealthySnapshot()
    {
        var now = DateTimeOffset.UtcNow;
        var health = new RegionalRuntimeMembershipHealth(
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            1,
            true,
            0,
            RegionalRuntimeMembershipCondition.Healthy,
            now);
        var entry = new GlobalCellDirectoryEntry(
            "sfo",
            "orchestrator-control-sfo",
            "sfo-regional",
            1,
            1,
            1,
            ["runtime"],
            health,
            now,
            now.Add(GlobalCellAdvertisement.SemanticLease),
            false,
            ["tls://control-sfo.internal:4222"]);
        return new(
            1,
            now,
            1,
            0,
            0,
            GlobalCellDirectoryCondition.Healthy,
            [entry]);
    }

    private sealed class FakeDirectoryRuntime(GlobalCellDirectorySnapshot snapshot)
        : IGlobalCellDirectoryRuntimeInstance
    {
        private readonly TaskCompletionSource completion =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        private readonly Exception? disposalFailure;

        internal FakeDirectoryRuntime(GlobalCellDirectorySnapshot snapshot, Exception? disposalFailure = null)
        {
            Snapshot = snapshot;
            this.disposalFailure = disposalFailure;
        }

        internal int DisposalCount { get; private set; }

        public GlobalCellDirectorySnapshot Snapshot { get; }

        public Task Completion => completion.Task;

        internal void Stop(Exception exception) => completion.SetException(exception);

        public ValueTask DisposeAsync()
        {
            DisposalCount++;
            if (disposalFailure is not null)
                return ValueTask.FromException(disposalFailure);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class FakeServiceRuntime : IGlobalCellDirectoryServiceRuntimeInstance
    {
        private readonly Exception? disposalFailure;

        internal FakeServiceRuntime(Exception? disposalFailure = null) => this.disposalFailure = disposalFailure;

        internal int DisposalCount { get; private set; }

        public ValueTask DisposeAsync()
        {
            DisposalCount++;
            if (disposalFailure is not null)
                return ValueTask.FromException(disposalFailure);
            return ValueTask.CompletedTask;
        }
    }
}

internal static class GlobalCellDirectorySnapshotAssertions
{
    internal static async Task ValidateUnavailableAsync(this GlobalCellDirectorySnapshot snapshot)
    {
        await Assert.That(snapshot.Condition).IsEqualTo(GlobalCellDirectoryCondition.Unavailable);
        await Assert.That(snapshot.ActiveCells).IsEqualTo(0);
        await Assert.That(snapshot.StaleCells).IsEqualTo(0);
        await Assert.That(snapshot.Cells).IsEmpty();
    }
}
