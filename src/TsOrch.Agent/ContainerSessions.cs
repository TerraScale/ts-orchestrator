using System.Collections.Concurrent;

namespace TsOrch.Agent;

public sealed class ContainerSessions(
    DockerEngineClient docker,
    AgentOutbox outbox,
    AgentOptions options,
    ILogger<ContainerSessions> logger)
{
    private const int MaxSessions = 32;
    private const int MaxTail = 10_000;
    private const int MaxExecSeconds = 300;

    private readonly ConcurrentDictionary<string, CancellationTokenSource> _logStreams = [with(StringComparer.Ordinal)];
    private int _active;

    public async ValueTask StartLogsAsync(StreamLogs request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var source = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (!_logStreams.TryAdd(request.RequestId, source))
        {
            source.Dispose();
            await outbox.EnqueueAsync(new LogChunk(request.RequestId, LogChannel.Stderr, $"ts-orch: log stream {request.RequestId} is already running."), cancellationToken);
            return;
        }

        if (!TryReserve())
        {
            _logStreams.TryRemove(request.RequestId, out _);
            source.Dispose();
            await outbox.EnqueueAsync(new LogChunk(request.RequestId, LogChannel.Stderr, "ts-orch: too many concurrent sessions on this node."), cancellationToken);
            return;
        }

        Track(request.RequestId, RunLogsAsync(request, source));
    }

    public ValueTask StopLogsAsync(StopLogs request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (_logStreams.TryGetValue(request.RequestId, out var source))
        {
            return new ValueTask(source.CancelAsync());
        }

        return ValueTask.CompletedTask;
    }

    public async ValueTask StartExecAsync(ExecCommand request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!TryReserve())
        {
            await outbox.EnqueueAsync(new ExecResult(request.RequestId, -1, string.Empty, "ts-orch: too many concurrent sessions on this node."), cancellationToken);
            return;
        }

        Track(request.RequestId, RunExecAsync(request, cancellationToken));
    }

    private bool TryReserve()
    {
        if (Interlocked.Increment(ref _active) <= MaxSessions)
        {
            return true;
        }

        Interlocked.Decrement(ref _active);
        return false;
    }

    private void Track(string requestId, Task session) =>
        session.ContinueWith(
            completed =>
            {
                Interlocked.Decrement(ref _active);
                if (completed.Exception is { } exception)
                {
                    AgentLog.SessionFaulted(logger, requestId, exception.GetBaseException());
                }
            },
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);

    private async Task RunLogsAsync(StreamLogs request, CancellationTokenSource source)
    {
        try
        {
            var cancellationToken = source.Token;
            var failure = await FindContainerAsync(request.ContainerName, cancellationToken) switch
            {
                ManagedContainer container => await docker.StreamLogsAsync(
                    container.Id,
                    Math.Clamp(request.Tail, 0, MaxTail),
                    request.Follow,
                    (channel, line, lineToken) => outbox.EnqueueAsync(new LogChunk(request.RequestId, channel, line), lineToken),
                    cancellationToken) switch
                {
                    Done => null,
                    NotFound streamFailure => streamFailure.Message,
                    Unavailable streamFailure => streamFailure.Message,
                    InternalFailure streamFailure => streamFailure.Message,
                },
                NotFound findFailure => findFailure.Message,
                Unavailable findFailure => findFailure.Message,
                InternalFailure findFailure => findFailure.Message,
            };
            if (failure is not null)
            {
                await outbox.EnqueueAsync(new LogChunk(request.RequestId, LogChannel.Stderr, $"ts-orch: {failure}"), cancellationToken);
            }
        }
        catch (OperationCanceledException) when (source.IsCancellationRequested)
        {
            AgentLog.SessionStopped(logger, request.RequestId);
        }
        finally
        {
            _logStreams.TryRemove(request.RequestId, out _);
            source.Dispose();
        }
    }

    private async Task RunExecAsync(ExecCommand request, CancellationToken cancellationToken)
    {
        var result = await FindContainerAsync(request.ContainerName, cancellationToken) switch
        {
            ManagedContainer container => await ExecAsync(request, container, cancellationToken),
            NotFound failure => Failed(request, failure.Message),
            Unavailable failure => Failed(request, failure.Message),
            InternalFailure failure => Failed(request, failure.Message),
        };
        await outbox.EnqueueAsync(result, cancellationToken);
    }

    private async Task<ExecResult> ExecAsync(ExecCommand request, ManagedContainer container, CancellationToken cancellationToken)
    {
        var timeout = TimeSpan.FromSeconds(Math.Clamp(request.TimeoutSeconds, 1, MaxExecSeconds));
        AgentLog.ExecStarted(logger, request.RequestId, container.Name);
        return await docker.ExecOnceAsync(container.Id, request.Command, timeout, cancellationToken) switch
        {
            ExecOutput output => new ExecResult(request.RequestId, output.ExitCode, output.Stdout, output.Stderr),
            Validation failure => Failed(request, failure.Message),
            NotFound failure => Failed(request, failure.Message),
            Conflict failure => Failed(request, failure.Message),
            RequestTimeout failure => Failed(request, failure.Message),
            Unavailable failure => Failed(request, failure.Message),
            InternalFailure failure => Failed(request, failure.Message),
        };
    }

    private static ExecResult Failed(ExecCommand request, string message) => new(request.RequestId, -1, string.Empty, $"ts-orch: {message}");

    private async Task<Result<ManagedContainer, NotFound, Unavailable, InternalFailure>> FindContainerAsync(string containerName, CancellationToken cancellationToken) =>
        await docker.ListManagedContainersAsync(options.LabelPrefix, cancellationToken) switch
        {
            IReadOnlyList<ManagedContainer> containers => containers
                .Where(static container => container.Running)
                .FirstOrDefault(container => container.Name == containerName || container.PlacementId == containerName || container.ServiceName == containerName) is { } match
                ? match
                : new NotFound($"No running managed container matches {containerName}."),
            Unavailable failure => failure,
            InternalFailure failure => failure,
        };
}
