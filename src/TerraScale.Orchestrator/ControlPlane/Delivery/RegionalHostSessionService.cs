using System.Text;
using System.Text.Json;
using NATS.Client.Core;
using TerraScale.Orchestrator.Protocol.Messaging;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

/// <summary>A host uses only its bounded observation/command subjects; it never opens controller stores.</summary>
internal sealed class NatsRegionalHostSessionClient(INatsConnection connection, string cell, string nodeId)
{
    internal async Task<RegionalHostSessionResponse> SendAsync(RegionalHostSessionRequest request, CancellationToken cancellationToken)
    {
        if (request.Enrollment.Region != cell.ToUpperInvariant() || request.Enrollment.NodeId != nodeId)
            throw new InvalidOperationException("The host session request does not match this client identity.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(5));
        var reply = RegionalHostSessionRequest.ReplySubject(cell, nodeId, request.RequestId);
        await using var subscription = await connection.SubscribeCoreAsync<string>(reply,
            opts: new NatsSubOpts { MaxMsgs = 1 }, cancellationToken: deadline.Token).ConfigureAwait(false);
        // NATS.Net 2.7.2 does not observe cancellation while awaiting the PONG itself.
        await connection.PingAsync(deadline.Token).AsTask().WaitAsync(deadline.Token).ConfigureAwait(false);
        await connection.PublishAsync(RegionalHostSessionRequest.Subject(cell, nodeId), request.Serialize(),
            replyTo: reply, cancellationToken: deadline.Token).ConfigureAwait(false);
        var message = await subscription.Msgs.ReadAsync(deadline.Token).ConfigureAwait(false);
        if (message.Data is not { Length: > 0 and <= 4096 } json || Encoding.UTF8.GetByteCount(json) > 4096)
            throw new InvalidDataException("The controller session response exceeds its bounds.");
        var response = JsonSerializer.Deserialize<RegionalHostSessionResponse>(json, RegionalHostSessionAuthority.JsonOptions);
        if (response is null || response.SchemaVersion != 2 || response.RequestId != request.RequestId ||
            response.RequestDigest != request.RequestDigest || response.Generation != request.Enrollment.BootstrapGeneration ||
            !Enum.IsDefined(response.Decision) ||
            (response.Accepted
                ? response.Epoch == 0 || response.ExpiresAt != request.IssuedAt + RegionalHostSessionAuthority.LeaseLifetime ||
                    (request.Operation == RegionalHostSessionOperation.Renew && response.Epoch != request.Epoch)
                : response.Epoch != 0 || response.ExpiresAt is not null))
            throw new InvalidDataException("The controller session response is not bound to the exact request and lease.");
        return response;
    }
}

internal sealed record RegionalHostSessionServiceSnapshot(long Acquired, long Renewed, long Rejected, long Failed, bool RetryPending);

/// <summary>Regional controllers share ingress; durable CAS decides ownership across handlers and restarts.</summary>
internal sealed class RegionalHostSessionService : IAsyncDisposable
{
    private readonly INatsConnection connection;
    private readonly RegionalHostSessionAuthority authority;
    private readonly INatsSub<string> subscription;
    private readonly CancellationTokenSource stopping = new();
    private readonly Task loop;
    private long acquired;
    private long renewed;
    private long rejected;
    private long failed;
    private int retryPending;
    private readonly HashSet<string> failedNodes = new(StringComparer.Ordinal);
    private bool overflowedFailures;

    private RegionalHostSessionService(INatsConnection connection, RegionalHostSessionAuthority authority, INatsSub<string> subscription)
    {
        this.connection = connection;
        this.authority = authority;
        this.subscription = subscription;
        loop = RunAsync();
    }

    internal Task Completion => loop;
    internal RegionalHostSessionServiceSnapshot Snapshot => new(Interlocked.Read(ref acquired), Interlocked.Read(ref renewed),
        Interlocked.Read(ref rejected), Interlocked.Read(ref failed), Volatile.Read(ref retryPending) != 0);

    internal static async Task<RegionalHostSessionService> StartAsync(INatsConnection connection,
        RegionalHostSessionAuthority authority, CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(5));
        INatsSub<string>? subscription = null;
        try
        {
            await authority.ValidateStoreAsync(deadline.Token).ConfigureAwait(false);
            var pattern = NatsSubjectTaxonomy.RegionalRoot(authority.Cell) + "." + NatsSubjectTaxonomy.RegionalAgentPrefixSegment +
                ".*." + NatsSubjectTaxonomy.ObservationFamilySegment + ".enrollment";
            subscription = await connection.SubscribeCoreAsync<string>(pattern, queueGroup: "host-session-authority",
                cancellationToken: deadline.Token).ConfigureAwait(false);
            await connection.PingAsync(deadline.Token).AsTask().WaitAsync(deadline.Token).ConfigureAwait(false);
            return new(connection, authority, subscription);
        }
        catch (Exception exception)
        {
            if (subscription is not null) await subscription.DisposeAsync().ConfigureAwait(false);
            // Program treats caller cancellation as a clean shutdown. An internal startup
            // deadline is a failed start and must not escape through that success path.
            if (exception is OperationCanceledException && !cancellationToken.IsCancellationRequested)
                throw new TimeoutException("The regional host-session service startup timed out.", exception);
            throw;
        }
    }

    private async Task RunAsync()
    {
        try
        {
            await foreach (var message in subscription.Msgs.ReadAllAsync(stopping.Token).ConfigureAwait(false))
            {
                if (!RegionalHostSessionRequest.TryRead(message.Data, message.Subject, message.ReplyTo,
                        authority.Cell, authority.Now, out var request))
                {
                    Interlocked.Increment(ref rejected);
                    continue;
                }
                try
                {
                    var response = await authority.ProcessAsync(request!, stopping.Token).ConfigureAwait(false);
                    await connection.PublishAsync(message.ReplyTo!, JsonSerializer.Serialize(response, RegionalHostSessionAuthority.JsonOptions),
                        cancellationToken: stopping.Token).ConfigureAwait(false);
                    if (response.Decision is RegionalHostSessionDecision.InvalidStore or RegionalHostSessionDecision.StoreUnavailable or RegionalHostSessionDecision.Contention)
                    {
                        RecordFailure(request!.Enrollment.NodeId);
                        continue;
                    }
                    failedNodes.Remove(request!.Enrollment.NodeId);
                    Volatile.Write(ref retryPending, overflowedFailures || failedNodes.Count > 0 ? 1 : 0);
                    if (!response.Accepted) Interlocked.Increment(ref rejected);
                    else if (request.Operation == RegionalHostSessionOperation.Acquire) Interlocked.Increment(ref acquired);
                    else Interlocked.Increment(ref renewed);
                }
                catch (NatsException) { RecordFailure(request!.Enrollment.NodeId); }
            }
        }
        catch (OperationCanceledException) when (stopping.IsCancellationRequested) { }
    }

    private void RecordFailure(string nodeId)
    {
        Interlocked.Increment(ref failed);
        if (!failedNodes.Contains(nodeId))
        {
            if (failedNodes.Count < 512) failedNodes.Add(nodeId);
            else overflowedFailures = true;
        }
        Volatile.Write(ref retryPending, 1);
    }

    public async ValueTask DisposeAsync()
    {
        stopping.Cancel();
        try { await loop.ConfigureAwait(false); }
        finally
        {
            await subscription.DisposeAsync().ConfigureAwait(false);
            stopping.Dispose();
        }
    }
}
