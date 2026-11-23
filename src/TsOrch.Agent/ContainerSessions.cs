using System.Collections.Concurrent;
using Microsoft.Extensions.Options;

namespace TsOrch.Agent;

public sealed class ContainerSessions(
    DockerEngineClient docker,
    AgentOutbox outbox,
    IOptions<AgentOptions> options,
    ILogger<ContainerSessions> logger)
{
    private const int MaxSessions = 32;
    private const int MaxTail = 10_000;
    private const int MaxExecSeconds = 300;

    private readonly AgentOptions _options = options.Value;
    private readonly ConcurrentDictionary<string, CancellationTokenSource> _logStreams = new(StringComparer.Ordinal);
    private int _active;

    public async ValueTask StartLogsAsync(StreamLogs request, CancellationToken sessionToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var source = CancellationTokenSource.CreateLinkedTokenSource(sessionToken);
        if (!_logStreams.TryAdd(request.RequestId, source))
        {
            source.Dispose();
            await outbox.EnqueueAsync(new LogChunk(request.RequestId, LogChannel.Stderr, $"ts-orch: log stream {request.RequestId} is already running."), sessionToken);
            return;
        }

        if (!TryReserve())
        {
            _logStreams.TryRemove(request.RequestId, out _);
            source.Dispose();
            await outbox.EnqueueAsync(new LogChunk(request.RequestId, LogChannel.Stderr, "ts-orch: too many concurrent sessions on this node."), sessionToken);
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

    public async ValueTask StartExecAsync(ExecCommand request, CancellationToken sessionToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!TryReserve())
        {
            await outbox.EnqueueAsync(new ExecResult(request.RequestId, -1, string.Empty, "ts-orch: too many concurrent sessions on this node."), sessionToken);
            return;
        }

        Track(request.RequestId, RunExecAsync(request, sessionToken));
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
                    logger.SessionFaulted(requestId, exception.GetBaseException());
                }
            },
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);

    private async Task RunLogsAsync(StreamLogs request, CancellationTokenSource source)
    {
        try
        {
            var token = source.Token;
            var resolved = await FindContainerAsync(request.ContainerName, token);
            if (!resolved.TryGetValue(out var container, out var error))
            {
                await outbox.EnqueueAsync(new LogChunk(request.RequestId, LogChannel.Stderr, $"ts-orch: {error.Message}"), token);
                return;
            }

            var streamed = await docker.StreamLogsAsync(
                container.Id,
                Math.Clamp(request.Tail, 0, MaxTail),
                request.Follow,
                (channel, line, lineToken) => outbox.EnqueueAsync(new LogChunk(request.RequestId, channel, line), lineToken),
                token);
            if (streamed is OrchError streamError)
            {
                await outbox.EnqueueAsync(new LogChunk(request.RequestId, LogChannel.Stderr, $"ts-orch: {streamError.Message}"), token);
            }
        }
        catch (OperationCanceledException) when (source.IsCancellationRequested)
        {
            logger.SessionStopped(request.RequestId);
        }
        finally
        {
            _logStreams.TryRemove(request.RequestId, out _);
            source.Dispose();
        }
    }

    private async Task RunExecAsync(ExecCommand request, CancellationToken sessionToken)
    {
        var resolved = await FindContainerAsync(request.ContainerName, sessionToken);
        if (!resolved.TryGetValue(out var container, out var error))
        {
            await outbox.EnqueueAsync(new ExecResult(request.RequestId, -1, string.Empty, $"ts-orch: {error.Message}"), sessionToken);
            return;
        }

        var timeout = TimeSpan.FromSeconds(Math.Clamp(request.TimeoutSeconds, 1, MaxExecSeconds));
        logger.ExecStarted(request.RequestId, container.Name);
        var executed = await docker.ExecOnceAsync(container.Id, request.Command, timeout, sessionToken);
        var result = executed switch
        {
            ExecOutput output => new ExecResult(request.RequestId, output.ExitCode, output.Stdout, output.Stderr),
            OrchError failure => new ExecResult(request.RequestId, -1, string.Empty, $"ts-orch: {failure.Message}"),
        };
        await outbox.EnqueueAsync(result, sessionToken);
    }

    private async Task<OrchResult<ManagedContainer>> FindContainerAsync(string containerName, CancellationToken cancellationToken)
    {
        var listed = await docker.ListManagedContainersAsync(_options.LabelPrefix, cancellationToken);
        if (!listed.TryGetValue(out var containers, out var error))
        {
            return error;
        }

        var match = containers
            .Where(static container => container.Running)
            .FirstOrDefault(container => container.Name == containerName || container.PlacementId == containerName || container.ServiceName == containerName);
        return match is null
            ? new NotFound($"No running managed container matches {containerName}.")
            : match;
    }
}
