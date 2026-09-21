using System.Text.Json;
using System.Threading.Channels;
using NATS.Client.Core;
using TerraScale.Orchestrator.Protocol.Messaging;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

internal sealed record RegionalHostArtifactSnapshot(long Chunks, long Bytes, long Rejected, long Failed, bool RetryPending, bool InFlight, long CacheBytes, int CacheEntries, bool Downloading);

/// <summary>A separate bounded queue keeps a stalled artifact store away from session renewal.</summary>
internal sealed class RegionalHostArtifactService : IAsyncDisposable
{
    private readonly INatsConnection connection;
    private readonly RegionalHostArtifactAuthority authority;
    private readonly INatsSub<string> subscription;
    private readonly CancellationTokenSource stopping = new();
    private readonly Task loop;
    private readonly HashSet<string> failedNodes = new(StringComparer.Ordinal);
    private bool overflowedFailures;
    private long chunks;
    private long bytes;
    private long rejected;
    private long failed;
    private int retryPending;
    private Task<RegionalHostArtifactResponse>? pending;

    private RegionalHostArtifactService(INatsConnection connection, RegionalHostArtifactAuthority authority, INatsSub<string> subscription)
    {
        this.connection = connection;
        this.authority = authority;
        this.subscription = subscription;
        loop = RunAsync();
    }

    internal Task Completion => loop;
    internal RegionalHostArtifactSnapshot Snapshot
    {
        get
        {
            var cache = authority.CacheSnapshot;
            return new(Interlocked.Read(ref chunks), Interlocked.Read(ref bytes), Interlocked.Read(ref rejected),
                Interlocked.Read(ref failed), Volatile.Read(ref retryPending) != 0,
                Volatile.Read(ref pending) is { IsCompleted: false }, cache.Bytes, cache.Entries, cache.Downloading);
        }
    }

    internal static async Task<RegionalHostArtifactService> StartAsync(INatsConnection connection,
        RegionalHostArtifactAuthority authority, CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(5));
        INatsSub<string>? subscription = null;
        try
        {
            var pattern = NatsSubjectTaxonomy.RegionalRoot(authority.Cell) + "." + NatsSubjectTaxonomy.RegionalAgentPrefixSegment +
                ".*." + NatsSubjectTaxonomy.ObservationFamilySegment + ".artifact";
            subscription = await connection.SubscribeCoreAsync<string>(pattern, queueGroup: "host-artifact",
                opts: new NatsSubOpts { ChannelOpts = new NatsSubChannelOpts { Capacity = 16, FullMode = BoundedChannelFullMode.DropWrite } },
                cancellationToken: deadline.Token).ConfigureAwait(false);
            await connection.PingAsync(deadline.Token).AsTask().WaitAsync(deadline.Token).ConfigureAwait(false);
            return new(connection, authority, subscription);
        }
        catch (Exception exception)
        {
            if (subscription is not null) await subscription.DisposeAsync().ConfigureAwait(false);
            if (exception is OperationCanceledException && !cancellationToken.IsCancellationRequested)
                throw new TimeoutException("The regional artifact service startup timed out.", exception);
            throw;
        }
    }

    private async Task RunAsync()
    {
        try
        {
            await foreach (var message in subscription.Msgs.ReadAllAsync(stopping.Token).ConfigureAwait(false))
            {
                if (!RegionalHostArtifactRequest.TryRead(message.Data, message.Subject, message.ReplyTo,
                        authority.Cell, authority.Now, out var parsed))
                {
                    Interlocked.Increment(ref rejected);
                    continue;
                }
                var request = parsed!;
                var response = RegionalHostArtifactResponse.Deny(request, RegionalHostSessionDecision.StoreUnavailable);
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(stopping.Token);
                deadline.CancelAfter(TimeSpan.FromSeconds(3));
                if (pending is null || pending.IsCompleted)
                {
                    // Even a synchronous store implementation cannot block the service loop. Keep at most
                    // one unfinished operation when a dependency ignores cancellation; never accumulate retries.
                    var token = deadline.Token;
                    pending = Task.Run(() => authority.ReadAsync(request, token), CancellationToken.None);
                    _ = pending.ContinueWith(static task => _ = task.Exception, CancellationToken.None,
                        TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
                    try { response = await pending.WaitAsync(deadline.Token).ConfigureAwait(false); }
                    catch (OperationCanceledException) when (!stopping.IsCancellationRequested) { }
                    catch (Exception) when (!stopping.IsCancellationRequested) { }
                }
                try
                {
                    // Storage consumed its own deadline. The response gets a separate bounded delivery window.
                    using var deliveryDeadline = CancellationTokenSource.CreateLinkedTokenSource(stopping.Token);
                    deliveryDeadline.CancelAfter(TimeSpan.FromSeconds(1));
                    await connection.PublishAsync(message.ReplyTo!, JsonSerializer.Serialize(response, RegionalHostSessionAuthority.JsonOptions),
                        cancellationToken: deliveryDeadline.Token).AsTask().WaitAsync(deliveryDeadline.Token).ConfigureAwait(false);
                    if (response.Decision is RegionalHostSessionDecision.StoreUnavailable or RegionalHostSessionDecision.InvalidStore or RegionalHostSessionDecision.Contention)
                        RecordFailure(request.Enrollment.NodeId);
                    else
                    {
                        failedNodes.Remove(request.Enrollment.NodeId);
                        Volatile.Write(ref retryPending, overflowedFailures || failedNodes.Count > 0 ? 1 : 0);
                        if (!response.Accepted) Interlocked.Increment(ref rejected);
                        else
                        {
                            Interlocked.Increment(ref chunks);
                            Interlocked.Add(ref bytes, response.Bytes!.Length);
                        }
                    }
                }
                catch (Exception exception) when (exception is NatsException or OperationCanceledException or TimeoutException)
                { RecordFailure(request.Enrollment.NodeId); }
            }
        }
        catch (OperationCanceledException) when (stopping.IsCancellationRequested) { }
    }

    private void RecordFailure(string nodeId)
    {
        Interlocked.Increment(ref failed);
        if (failedNodes.Count < 1024) failedNodes.Add(nodeId);
        else if (!failedNodes.Contains(nodeId)) overflowedFailures = true;
        Volatile.Write(ref retryPending, 1);
    }

    public async ValueTask DisposeAsync()
    {
        stopping.Cancel();
        try { await loop.ConfigureAwait(false); }
        finally { await subscription.DisposeAsync().ConfigureAwait(false); stopping.Dispose(); }
    }
}
