using System.Buffers;
using System.Net;
using System.Net.WebSockets;
using System.Text.Json;
using Microsoft.Extensions.Hosting;

namespace TsOrch.Agent;

public sealed class BackplaneDispatcher(
    ContainerReconciler reconciler,
    NodeMaintenance maintenance,
    EdgeConfigWriter edge,
    ContainerSessions sessions)
{
    public void SetNodeIdentity(string nodeId, string region) => reconciler.SetNodeIdentity(nodeId, region);

    public async ValueTask DispatchAsync(BackplaneMessage message, NodeSession session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(session);
        var handled = message switch
        {
            SyncDesired desired => ApplyDesired(desired),
            SyncRoutes routes => edge.WriteRoutesAsync(routes, cancellationToken),
            SyncTls tls => edge.WriteTlsAsync(tls, cancellationToken),
            RefreshSecrets refresh => RefreshSecrets(refresh),
            Drain drain => maintenance.EnqueueAsync(new DrainWork(session.NodeId, drain.Reason), cancellationToken),
            GrowVolume grow => maintenance.EnqueueAsync(new GrowVolumeWork(session.NodeId, grow.MountPath), cancellationToken),
            StreamLogs logs => sessions.StartLogsAsync(logs, cancellationToken),
            StopLogs stop => sessions.StopLogsAsync(stop),
            ExecCommand exec => sessions.StartExecAsync(exec, cancellationToken),
            UpgradeAgent upgrade => maintenance.EnqueueAsync(new UpgradeAgentWork(upgrade.Version, upgrade.Url, upgrade.Sha256), cancellationToken),
        };
        await handled;
    }

    private ValueTask ApplyDesired(SyncDesired desired)
    {
        reconciler.ApplyDesired(desired);
        return ValueTask.CompletedTask;
    }

    private ValueTask RefreshSecrets(RefreshSecrets refresh)
    {
        reconciler.RefreshSecrets(refresh.ServiceName);
        return ValueTask.CompletedTask;
    }
}

public sealed class NodeAgentRunner(
    NodeEnrollment enrollment,
    BackplaneDispatcher dispatcher,
    AgentOutbox outbox,
    NodeReportComposer reports,
    AgentOptions options,
    TimeProvider timeProvider,
    ILogger<NodeAgentRunner> logger) : BackgroundService
{
    private const int MaxMessageBytes = 16 * 1024 * 1024;
    private static readonly TimeSpan InitialBackoff = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(20);
    private static readonly TimeSpan CloseTimeout = TimeSpan.FromSeconds(5);
    private static readonly byte[] PingFrame = "ping"u8.ToArray();

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var failures = 0;
        while (!stoppingToken.IsCancellationRequested)
        {
            var outcome = await enrollment.EnsureEnrolledAsync(stoppingToken);
            failures = outcome switch
            {
                NodeSession session => await CountSessionFailuresAsync(session, failures, stoppingToken),
                NodeIdentityIncomplete failure => EnrollFailed(failures, "identity_incomplete", failure.Message),
                EnrollmentMetadataUnreadable failure => EnrollFailed(failures, "metadata_unreadable", failure.Message),
                EnrollmentSecretUnconfigured failure => EnrollFailed(failures, "enrollment_secret_unconfigured", failure.Message),
                EnrollmentSecretUnreadable failure => EnrollFailed(failures, "enrollment_secret_unreadable", failure.Message),
                NodeRegistrationRejected failure => EnrollFailed(failures, "registration_rejected", failure.Message),
                EnrollmentBackplaneUnavailable failure => EnrollFailed(failures, "backplane_unavailable", failure.Message),
                EnrollmentResponseInvalid failure => EnrollFailed(failures, "response_invalid", failure.Message),
                EnrollmentStateWriteFailed failure => EnrollFailed(failures, "state_write_failed", failure.Message),
            };
            await DelayAsync(Math.Max(1, failures), stoppingToken);
        }
    }

    private async Task<int> CountSessionFailuresAsync(NodeSession session, int failures, CancellationToken cancellationToken)
    {
        var outcome = await RunSessionAsync(session, cancellationToken);
        return outcome switch
        {
            SessionRejected => Forget(failures),
            SessionUnreachable => failures + 1,
            SessionDisconnected => 0,
        };
    }

    private int Forget(int failures)
    {
        enrollment.Forget();
        return failures + 1;
    }

    private int EnrollFailed(int failures, string code, string reason)
    {
        AgentLog.EnrollFailed(logger, code, reason);
        return failures + 1;
    }

    private async Task DelayAsync(int attempt, CancellationToken cancellationToken)
    {
        var exponent = Math.Min(attempt - 1, 16);
        var ceiling = Math.Min(options.ReconnectMaxDelay.TotalMilliseconds, InitialBackoff.TotalMilliseconds * Math.Pow(2, exponent));
        var delay = TimeSpan.FromMilliseconds(ceiling * (0.8 + (Random.Shared.NextDouble() * 0.4)));
        AgentLog.Reconnecting(logger, delay);
        await Task.Delay(delay, timeProvider, cancellationToken);
    }

    private async Task<SessionOutcome> RunSessionAsync(NodeSession session, CancellationToken cancellationToken)
    {
        dispatcher.SetNodeIdentity(session.NodeId, session.Identity.Region);
        using var socket = new ClientWebSocket();
        socket.Options.SetRequestHeader("Authorization", $"Bearer {session.Token}");
        socket.Options.KeepAliveInterval = TimeSpan.Zero;
        socket.Options.CollectHttpResponseDetails = true;
        AgentLog.Connecting(logger, session.WebSocketUrl);
        using (var connectTimeout = new CancellationTokenSource(ConnectTimeout, timeProvider))
        using (var connectToken = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, connectTimeout.Token))
        {
            try
            {
                await socket.ConnectAsync(session.WebSocketUrl, connectToken.Token);
            }
            catch (Exception exception) when (exception is WebSocketException or HttpRequestException or IOException)
            {
                if (socket.HttpStatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
                {
                    AgentLog.ConnectRejected(logger, (int)socket.HttpStatusCode);
                    return new SessionRejected();
                }

                AgentLog.ConnectFailed(logger, exception.Message);
                return new SessionUnreachable();
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                AgentLog.ConnectFailed(logger, "WebSocket connect timed out.");
                return new SessionUnreachable();
            }
        }

        AgentLog.Connected(logger, session.NodeId);
        using var sendGate = new SemaphoreSlim(1, 1);
        using var sessionSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var token = sessionSource.Token;
        var sender = new FrameSender(socket, sendGate);
        var hello = Serialize(await reports.ComposeHelloAsync(session, token));
        try
        {
            await sender.SendAsync(hello, token);
        }
        catch (Exception exception) when (exception is WebSocketException or IOException)
        {
            AgentLog.ConnectFailed(logger, exception.Message);
            return new SessionUnreachable();
        }

        var activity = new SessionActivity(timeProvider.GetTimestamp());
        Task[] loops =
        [
            ReceiveLoopAsync(socket, session, activity, token),
            PumpOutboxAsync(sender, token),
            KeepAliveLoopAsync(sender, activity, token),
            HeartbeatLoopAsync(sender, token),
        ];
        await Task.WhenAny(loops);
        await sessionSource.CancelAsync();
        await Task.WhenAll(loops).ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
        foreach (var loop in loops)
        {
            if (loop.Exception?.GetBaseException() is { } failure and not (WebSocketException or IOException))
            {
                AgentLog.SessionLoopFaulted(logger, failure);
            }
        }

        await CloseAsync(socket);
        cancellationToken.ThrowIfCancellationRequested();
        AgentLog.SessionEnded(logger, session.NodeId);
        return new SessionDisconnected();
    }

    private async Task ReceiveLoopAsync(ClientWebSocket socket, NodeSession session, SessionActivity activity, CancellationToken cancellationToken)
    {
        var buffer = new ArrayBufferWriter<byte>(64 * 1024);
        while (true)
        {
            buffer.ResetWrittenCount();
            ValueWebSocketReceiveResult received;
            do
            {
                received = await socket.ReceiveAsync(buffer.GetMemory(16 * 1024), cancellationToken);
                activity.Touch(timeProvider.GetTimestamp());
                if (received.MessageType == WebSocketMessageType.Close)
                {
                    return;
                }

                buffer.Advance(received.Count);
                if (buffer.WrittenCount > MaxMessageBytes)
                {
                    AgentLog.MessageTooLarge(logger, buffer.WrittenCount);
                    await socket.CloseOutputAsync(WebSocketCloseStatus.MessageTooBig, "message too large", cancellationToken);
                    return;
                }
            }
            while (!received.EndOfMessage);

            if (received.MessageType != WebSocketMessageType.Text || buffer.WrittenSpan.SequenceEqual("pong"u8))
            {
                continue;
            }

            BackplaneMessage? message;
            try
            {
                message = JsonSerializer.Deserialize(buffer.WrittenSpan, WireJsonContext.Default.BackplaneMessage);
            }
            catch (JsonException exception)
            {
                AgentLog.BackplaneMessageInvalid(logger, exception.Message);
                continue;
            }

            if (message is not null)
            {
                await dispatcher.DispatchAsync(message, session, cancellationToken);
            }
        }
    }

    private async Task PumpOutboxAsync(FrameSender sender, CancellationToken cancellationToken)
    {
        while (await outbox.Reader.WaitToReadAsync(cancellationToken))
        {
            while (outbox.Reader.TryPeek(out var message))
            {
                await sender.SendAsync(Serialize(message), cancellationToken);
                outbox.Reader.TryRead(out _);
            }
        }
    }

    private async Task KeepAliveLoopAsync(FrameSender sender, SessionActivity activity, CancellationToken cancellationToken)
    {
        var watchdogLimit = TimeSpan.FromTicks((long)(options.KeepAliveInterval.Ticks * 2.5));
        using var timer = new PeriodicTimer(options.KeepAliveInterval, timeProvider);
        while (await timer.WaitForNextTickAsync(cancellationToken))
        {
            if (timeProvider.GetElapsedTime(activity.LastReceivedTimestamp) > watchdogLimit)
            {
                AgentLog.SessionWatchdogExpired(logger, watchdogLimit);
                return;
            }

            await sender.SendAsync(PingFrame, cancellationToken);
        }
    }

    private async Task HeartbeatLoopAsync(FrameSender sender, CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(options.HeartbeatInterval, timeProvider);
        do
        {
            await sender.SendAsync(Serialize(await reports.ComposeHeartbeatAsync(cancellationToken)), cancellationToken);
        }
        while (await timer.WaitForNextTickAsync(cancellationToken));
    }

    private async Task CloseAsync(ClientWebSocket socket)
    {
        if (socket.State is not (WebSocketState.Open or WebSocketState.CloseReceived))
        {
            return;
        }

        using var timeout = new CancellationTokenSource(CloseTimeout, timeProvider);
        try
        {
            await socket.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "agent session ended", timeout.Token);
        }
        catch (Exception exception) when (exception is WebSocketException or IOException or OperationCanceledException)
        {
            AgentLog.CloseFailed(logger, exception.Message);
        }
    }

    private static byte[] Serialize(AgentMessage message) =>
        JsonSerializer.SerializeToUtf8Bytes(message, WireJsonContext.Default.AgentMessage);

    private closed record class SessionOutcome;

    private sealed record class SessionRejected : SessionOutcome;

    private sealed record class SessionUnreachable : SessionOutcome;

    private sealed record class SessionDisconnected : SessionOutcome;

    private sealed class SessionActivity(long initialTimestamp)
    {
        private long _lastReceivedTimestamp = initialTimestamp;

        public long LastReceivedTimestamp => Volatile.Read(ref _lastReceivedTimestamp);

        public void Touch(long timestamp) => Volatile.Write(ref _lastReceivedTimestamp, timestamp);
    }

    private sealed class FrameSender(ClientWebSocket socket, SemaphoreSlim gate)
    {
        public async Task SendAsync(ReadOnlyMemory<byte> frame, CancellationToken cancellationToken)
        {
            await gate.WaitAsync(cancellationToken);
            try
            {
                await socket.SendAsync(frame, WebSocketMessageType.Text, endOfMessage: true, cancellationToken);
            }
            finally
            {
                gate.Release();
            }
        }
    }
}
