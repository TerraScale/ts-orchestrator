using System.Text.Json;
using System.Threading.Channels;
using NATS.Client.Core;
using TerraScale.Orchestrator.Protocol.Messaging;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

internal sealed record RegionalHostCycleSnapshot(long Active, long Backoff, long Busy, long Settled, long Rejected, long Failed, bool RetryPending, bool InFlight);

/// <summary>A separate bounded queue keeps a stalled cycle store away from session renewal.</summary>
internal sealed class RegionalHostCycleService : IAsyncDisposable
{
    private readonly INatsConnection connection;
    private readonly RegionalHostCycleAuthority authority;
    private readonly INatsSub<string> subscription;
    private readonly CancellationTokenSource stopping = new();
    private readonly Task loop;
    private readonly HashSet<(string Node, int Role)> failedScopes = [];
    private bool overflowedFailures;
    private long active;
    private long backoff;
    private long busy;
    private long settled;
    private long rejected;
    private long failed;
    private int retryPending;
    private Task<RegionalHostCycleResponse>? pending;

    private RegionalHostCycleService(INatsConnection connection, RegionalHostCycleAuthority authority, INatsSub<string> subscription)
    {
        this.connection = connection;
        this.authority = authority;
        this.subscription = subscription;
        loop = RunAsync();
    }

    internal Task Completion => loop;
    internal RegionalHostCycleSnapshot Snapshot => new(Interlocked.Read(ref active), Interlocked.Read(ref backoff),
        Interlocked.Read(ref busy), Interlocked.Read(ref settled), Interlocked.Read(ref rejected), Interlocked.Read(ref failed),
        Volatile.Read(ref retryPending) != 0, Volatile.Read(ref pending) is { IsCompleted: false });

    internal static async Task<RegionalHostCycleService> StartAsync(INatsConnection connection,
        RegionalHostCycleAuthority authority, CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(5));
        INatsSub<string>? subscription = null;
        try
        {
            var pattern = NatsSubjectTaxonomy.RegionalRoot(authority.Cell) + "." + NatsSubjectTaxonomy.RegionalAgentPrefixSegment +
                ".*." + NatsSubjectTaxonomy.ObservationFamilySegment + ".cycle";
            subscription = await connection.SubscribeCoreAsync<string>(pattern, queueGroup: "host-cycle",
                opts: new NatsSubOpts { ChannelOpts = new NatsSubChannelOpts { Capacity = 16, FullMode = BoundedChannelFullMode.DropWrite } },
                cancellationToken: deadline.Token).ConfigureAwait(false);
            await connection.PingAsync(deadline.Token).AsTask().WaitAsync(deadline.Token).ConfigureAwait(false);
            return new(connection, authority, subscription);
        }
        catch (Exception exception)
        {
            if (subscription is not null) await subscription.DisposeAsync().ConfigureAwait(false);
            if (exception is OperationCanceledException && !cancellationToken.IsCancellationRequested)
                throw new TimeoutException("The regional cycle service startup timed out.", exception);
            throw;
        }
    }

    private async Task RunAsync()
    {
        try
        {
            await foreach (var message in subscription.Msgs.ReadAllAsync(stopping.Token).ConfigureAwait(false))
            {
                if (!RegionalHostCycleRequest.TryRead(message.Data, message.Subject, message.ReplyTo,
                        authority.Cell, authority.Now, out var parsed))
                {
                    Interlocked.Increment(ref rejected);
                    continue;
                }
                var request = parsed!;
                var response = RegionalHostCycleResponse.Deny(request, RegionalHostSessionDecision.StoreUnavailable);
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(stopping.Token);
                deadline.CancelAfter(TimeSpan.FromSeconds(3));
                if (pending is null || pending.IsCompleted)
                {
                    // Even a synchronous store implementation cannot block the service loop. Keep at most
                    // one unfinished operation when a dependency ignores cancellation; never accumulate retries.
                    var token = deadline.Token;
                    pending = Task.Run(() => authority.ProcessAsync(request, token), CancellationToken.None);
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
                        RecordFailure(request);
                    else
                    {
                        failedScopes.Remove((request.Enrollment.NodeId, (int)request.Role));
                        Volatile.Write(ref retryPending, overflowedFailures || failedScopes.Count > 0 ? 1 : 0);
                        if (!response.Accepted) Interlocked.Increment(ref rejected);
                        else
                        {
                            switch (response.Disposition)
                            {
                                case RegionalHostCycleDisposition.Active: Interlocked.Increment(ref active); break;
                                case RegionalHostCycleDisposition.Backoff: Interlocked.Increment(ref backoff); break;
                                case RegionalHostCycleDisposition.Busy: Interlocked.Increment(ref busy); break;
                                case RegionalHostCycleDisposition.Settled: Interlocked.Increment(ref settled); break;
                            }
                        }
                    }
                }
                catch (Exception exception) when (exception is NatsException or OperationCanceledException or TimeoutException)
                { RecordFailure(request); }
            }
        }
        catch (OperationCanceledException) when (stopping.IsCancellationRequested) { }
    }

    private void RecordFailure(RegionalHostCycleRequest request)
    {
        Interlocked.Increment(ref failed);
        var scope = (request.Enrollment.NodeId, (int)request.Role);
        if (failedScopes.Count < 1024) failedScopes.Add(scope);
        else if (!failedScopes.Contains(scope)) overflowedFailures = true;
        Volatile.Write(ref retryPending, 1);
    }

    public async ValueTask DisposeAsync()
    {
        stopping.Cancel();
        try { await loop.ConfigureAwait(false); }
        finally { await subscription.DisposeAsync().ConfigureAwait(false); stopping.Dispose(); }
    }
}
