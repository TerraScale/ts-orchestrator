namespace TerraScale.Orchestrator.Messaging;

internal interface IGlobalCellDirectoryRuntimeInstance : IAsyncDisposable
{
    GlobalCellDirectorySnapshot Snapshot { get; }

    Task Completion { get; }
}

internal interface IGlobalCellDirectoryServiceRuntimeInstance : IAsyncDisposable
{
}

/// <summary>
/// Supervises the optional global directory without making regional startup
/// depend on its availability. A running instance is replaced after an
/// unexpected completion, while the last failure remains observable.
/// </summary>
internal sealed class GlobalCellDirectoryLifecycle : IAsyncDisposable
{
    internal static readonly TimeSpan InitialRetryDelay = TimeSpan.FromMilliseconds(250);
    internal static readonly TimeSpan MaximumRetryDelay = TimeSpan.FromSeconds(5);

    private readonly Func<CancellationToken, Task<IGlobalCellDirectoryRuntimeInstance>> startDirectory;
    private readonly Func<IGlobalCellDirectoryRuntimeInstance, CancellationToken,
        Task<IGlobalCellDirectoryServiceRuntimeInstance?>>? startService;
    private readonly Func<int, TimeSpan> retryDelay;
    private readonly Func<TimeSpan, CancellationToken, Task> delay;
    private readonly Action<Exception>? observeFailure;
    private readonly CancellationTokenSource stopping;
    private readonly Task supervision;
    private IGlobalCellDirectoryRuntimeInstance? activeDirectory;
    private Exception? lastFailure;
    private int disposed;

    private GlobalCellDirectoryLifecycle(
        Func<CancellationToken, Task<IGlobalCellDirectoryRuntimeInstance>> startDirectory,
        Func<IGlobalCellDirectoryRuntimeInstance, CancellationToken,
            Task<IGlobalCellDirectoryServiceRuntimeInstance?>>? startService,
        Func<int, TimeSpan> retryDelay,
        Func<TimeSpan, CancellationToken, Task> delay,
        Action<Exception>? observeFailure,
        CancellationToken cancellationToken)
    {
        this.startDirectory = startDirectory;
        this.startService = startService;
        this.retryDelay = retryDelay;
        this.delay = delay;
        this.observeFailure = observeFailure;
        stopping = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        supervision = SuperviseAsync(stopping.Token);
    }

    internal Task Completion => supervision;

    internal GlobalCellDirectorySnapshot Snapshot =>
        Volatile.Read(ref activeDirectory)?.Snapshot ?? UnavailableSnapshot();

    internal GlobalCellDirectoryCondition Health => Snapshot.Condition;

    internal Exception? LastFailure => Volatile.Read(ref lastFailure);

    internal static GlobalCellDirectoryLifecycle Start(
        GlobalDirectoryNatsConfiguration directoryConfiguration,
        GlobalDirectoryServiceNatsConfiguration? serviceConfiguration,
        Func<RegionalRuntimeMembershipSnapshot> membership,
        Func<RegionalAuthoritySnapshot> authority,
        bool publishEnabled,
        CancellationToken cancellationToken,
        Action<Exception>? observeFailure = null)
    {
        ArgumentNullException.ThrowIfNull(directoryConfiguration);
        ArgumentNullException.ThrowIfNull(membership);
        ArgumentNullException.ThrowIfNull(authority);

        return new(
            async token => await GlobalCellDirectoryRuntime.StartAsync(
                directoryConfiguration,
                membership,
                authority,
                publishEnabled,
                token),
            serviceConfiguration is null
                ? null
                : async (runtime, token) => await GlobalCellDirectoryServiceRuntime.StartAsync(
                    serviceConfiguration,
                    () => runtime.Snapshot,
                    token),
            RetryDelay,
            static (duration, token) => Task.Delay(duration, token),
            observeFailure,
            cancellationToken);
    }

    internal static GlobalCellDirectoryLifecycle StartForTesting(
        Func<CancellationToken, Task<IGlobalCellDirectoryRuntimeInstance>> startDirectory,
        Func<IGlobalCellDirectoryRuntimeInstance, CancellationToken,
            Task<IGlobalCellDirectoryServiceRuntimeInstance?>>? startService,
        Func<int, TimeSpan> retryDelay,
        Func<TimeSpan, CancellationToken, Task> delay,
        CancellationToken cancellationToken,
        Action<Exception>? observeFailure = null)
    {
        ArgumentNullException.ThrowIfNull(startDirectory);
        ArgumentNullException.ThrowIfNull(retryDelay);
        ArgumentNullException.ThrowIfNull(delay);
        return new(
            startDirectory,
            startService,
            retryDelay,
            delay,
            observeFailure,
            cancellationToken);
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        await stopping.CancelAsync();
        try
        {
            await supervision;
        }
        catch (OperationCanceledException) when (stopping.IsCancellationRequested)
        {
        }
        finally
        {
            stopping.Dispose();
        }
    }

    private async Task SuperviseAsync(CancellationToken cancellationToken)
    {
        for (var attempt = 1; ; attempt++)
        {
            IGlobalCellDirectoryRuntimeInstance? directory = null;
            IGlobalCellDirectoryServiceRuntimeInstance? service = null;
            Exception? failure = null;
            try
            {
                directory = await startDirectory(cancellationToken);
                ArgumentNullException.ThrowIfNull(directory);
                service = startService is null
                    ? null
                    : await startService(directory, cancellationToken);
                Volatile.Write(ref activeDirectory, directory);
                await directory.Completion.WaitAsync(cancellationToken);
                failure = new InvalidOperationException(
                    "The global cell directory runtime stopped unexpectedly.");
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception exception)
            {
                failure = exception;
            }
            finally
            {
                Volatile.Write(ref activeDirectory, null);
                await DisposeInstancesAsync(service, directory, cancellationToken);
            }

            if (failure is null) continue;
            Volatile.Write(ref lastFailure, failure);
            // Failure reporting is deliberately best-effort. The directory is an
            // optional regional dependency, so a logger/metric callback must not
            // terminate supervision and turn a transient WAN outage into a
            // permanent loss of retries.
            try
            {
                observeFailure?.Invoke(failure);
            }
            catch
            {
                // Keep the original runtime failure as LastFailure and continue
                // through the bounded retry path.
            }
            try
            {
                await delay(retryDelay(attempt), cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
        }
    }

    private static async Task DisposeInstancesAsync(
        IGlobalCellDirectoryServiceRuntimeInstance? service,
        IGlobalCellDirectoryRuntimeInstance? directory,
        CancellationToken cancellationToken)
    {
        Exception? cleanupFailure = null;
        try
        {
            if (service is not null)
                await service.DisposeAsync();
        }
        catch (Exception exception) when (exception is not OperationCanceledException ||
                                          cancellationToken.IsCancellationRequested)
        {
            cleanupFailure = exception;
        }
        finally
        {
            try
            {
                if (directory is not null)
                    await directory.DisposeAsync();
            }
            catch (Exception exception) when (exception is not OperationCanceledException ||
                                              cancellationToken.IsCancellationRequested)
            {
                cleanupFailure ??= exception;
            }
        }

        // Disposal failures must not terminate regional control or stop a
        // transient global-directory retry. The failed instance is no longer
        // published through Snapshot, and the original start/completion error
        // remains the primary LastFailure signal.
        _ = cleanupFailure;
    }

    private static TimeSpan RetryDelay(int attempt)
    {
        var exponent = Math.Min(attempt - 1, 4);
        var milliseconds = InitialRetryDelay.TotalMilliseconds * Math.Pow(2, exponent);
        return TimeSpan.FromMilliseconds(Math.Min(milliseconds, MaximumRetryDelay.TotalMilliseconds));
    }

    private static GlobalCellDirectorySnapshot UnavailableSnapshot()
    {
        var observedAt = DateTimeOffset.UtcNow;
        return new(
            1,
            observedAt,
            0,
            0,
            0,
            GlobalCellDirectoryCondition.Unavailable,
            Array.Empty<GlobalCellDirectoryEntry>());
    }
}
