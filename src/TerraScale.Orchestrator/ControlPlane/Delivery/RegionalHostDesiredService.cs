using System.Text;
using System.Text.Json;
using NATS.Client.Core;
using TerraScale.Orchestrator.Protocol.Messaging;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

internal interface IHostDesiredArtifactSource
{
    Task<string?> ReadAsync(AdmittedRole role, string environment, string cell, CancellationToken cancellationToken);
}

/// <summary>Host desired selection uses only exact host subjects and its latest accepted session.</summary>
internal sealed class NatsHostDesiredArtifactSource(INatsConnection connection, string cell, string nodeId,
    Func<RegionalHostSessionSigner> currentSigner, TimeProvider? clock = null) : IHostDesiredArtifactSource
{
    private readonly TimeProvider time = clock ?? TimeProvider.System;

    public async Task<string?> ReadAsync(AdmittedRole role, string environment, string requestedCell, CancellationToken cancellationToken)
    {
        var request = currentSigner().SignDesired(role);
        if (requestedCell != cell || request.Enrollment.Region != cell.ToUpperInvariant() ||
            request.Enrollment.NodeId != nodeId || request.Enrollment.Scope.Environment != environment)
            throw new InvalidOperationException("Desired selection must match this host's enrolled scope.");
        var response = await SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.Accepted) throw new InvalidOperationException($"Desired selection was denied: {response.Decision}.");
        return response.ArtifactDigest;
    }

    internal async Task<RegionalHostDesiredResponse> SendAsync(RegionalHostDesiredRequest request, CancellationToken cancellationToken)
    {
        if (request.Enrollment.Region != cell.ToUpperInvariant() || request.Enrollment.NodeId != nodeId)
            throw new InvalidOperationException("The desired request does not match this host identity.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(5));
        var reply = RegionalHostDesiredRequest.ReplySubject(cell, nodeId, request.RequestId);
        await using var subscription = await connection.SubscribeCoreAsync<string>(reply,
            opts: new NatsSubOpts { MaxMsgs = 1 }, cancellationToken: deadline.Token).ConfigureAwait(false);
        await connection.PingAsync(deadline.Token).AsTask().WaitAsync(deadline.Token).ConfigureAwait(false);
        await connection.PublishAsync(RegionalHostDesiredRequest.Subject(cell, nodeId), request.Serialize(), replyTo: reply,
            cancellationToken: deadline.Token).ConfigureAwait(false);
        var message = await subscription.Msgs.ReadAsync(deadline.Token).ConfigureAwait(false);
        if (message.Data is not { Length: > 0 and <= 4096 } json || Encoding.UTF8.GetByteCount(json) > 4096)
            throw new InvalidDataException("The desired response exceeds its wire bounds.");
        var response = JsonSerializer.Deserialize<RegionalHostDesiredResponse>(json, RegionalHostSessionAuthority.JsonOptions)
            ?? throw new InvalidDataException("The desired response is missing.");
        response.RequireBinding(request, time.GetUtcNow());
        // Late responses cannot revive an execution lease whose cancellation has already fired.
        deadline.Token.ThrowIfCancellationRequested();
        return response;
    }
}

internal sealed record RegionalHostDesiredSnapshot(long Present, long Absent, long Rejected, long Failed, bool RetryPending, bool InFlight);

/// <summary>A separate bounded queue keeps a stalled desired store away from session renewal.</summary>
internal sealed class RegionalHostDesiredService : IAsyncDisposable
{
    private readonly INatsConnection connection;
    private readonly RegionalHostDesiredAuthority authority;
    private readonly INatsSub<string> subscription;
    private readonly CancellationTokenSource stopping = new();
    private readonly Task loop;
    private readonly HashSet<string> failedNodes = new(StringComparer.Ordinal);
    private bool overflowedFailures;
    private long present;
    private long absent;
    private long rejected;
    private long failed;
    private int retryPending;
    private Task<RegionalHostDesiredResponse>? pending;

    private RegionalHostDesiredService(INatsConnection connection, RegionalHostDesiredAuthority authority, INatsSub<string> subscription)
    {
        this.connection = connection;
        this.authority = authority;
        this.subscription = subscription;
        loop = RunAsync();
    }

    internal Task Completion => loop;
    internal RegionalHostDesiredSnapshot Snapshot => new(Interlocked.Read(ref present), Interlocked.Read(ref absent),
        Interlocked.Read(ref rejected), Interlocked.Read(ref failed), Volatile.Read(ref retryPending) != 0,
        Volatile.Read(ref pending) is { IsCompleted: false });

    internal static async Task<RegionalHostDesiredService> StartAsync(INatsConnection connection,
        RegionalHostDesiredAuthority authority, CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(5));
        INatsSub<string>? subscription = null;
        try
        {
            var pattern = NatsSubjectTaxonomy.RegionalRoot(authority.Cell) + "." + NatsSubjectTaxonomy.RegionalAgentPrefixSegment +
                ".*." + NatsSubjectTaxonomy.ObservationFamilySegment + ".desired";
            subscription = await connection.SubscribeCoreAsync<string>(pattern, queueGroup: "host-desired",
                cancellationToken: deadline.Token).ConfigureAwait(false);
            await connection.PingAsync(deadline.Token).AsTask().WaitAsync(deadline.Token).ConfigureAwait(false);
            return new(connection, authority, subscription);
        }
        catch (Exception exception)
        {
            if (subscription is not null) await subscription.DisposeAsync().ConfigureAwait(false);
            if (exception is OperationCanceledException && !cancellationToken.IsCancellationRequested)
                throw new TimeoutException("The regional desired service startup timed out.", exception);
            throw;
        }
    }

    private async Task RunAsync()
    {
        try
        {
            await foreach (var message in subscription.Msgs.ReadAllAsync(stopping.Token).ConfigureAwait(false))
            {
                if (!RegionalHostDesiredRequest.TryRead(message.Data, message.Subject, message.ReplyTo,
                        authority.Cell, authority.Now, out var parsed))
                {
                    Interlocked.Increment(ref rejected);
                    continue;
                }
                var request = parsed!;
                var response = RegionalHostDesiredResponse.Deny(request, RegionalHostSessionDecision.StoreUnavailable);
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
                        else if (response.ArtifactDigest is null) Interlocked.Increment(ref absent);
                        else Interlocked.Increment(ref present);
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
