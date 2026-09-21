using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using NATS.Client.Core;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

/// <summary>Downloads through the exact host subjects; no private object-store or inbox permissions.</summary>
internal sealed class NatsHostArtifactSource(INatsConnection connection, string cell, string nodeId,
    Func<RegionalHostSessionSigner> currentSigner, TimeProvider? clock = null) : IHostArtifactSource
{
    private readonly TimeProvider time = clock ?? TimeProvider.System;

    public async Task CopyIntoAsync(AdmittedRole role, string environment, string requestedCell, string digest,
        Stream destination, CancellationToken cancellationToken)
    {
        using var transfer = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        transfer.CancelAfter(TimeSpan.FromMinutes(5));
        RegionalHostArtifactRequest? first = null;
        long offset = 0;
        long? total = null;
        while (true)
        {
            transfer.Token.ThrowIfCancellationRequested();
            var request = currentSigner().SignArtifact(role, digest, offset, RegionalArtifactCache.MaximumChunkBytes);
            if (requestedCell != cell || request.Enrollment.Region != cell.ToUpperInvariant() ||
                request.Enrollment.NodeId != nodeId || request.Enrollment.Scope.Environment != environment ||
                first is not null && (request.Enrollment.Digest != first.Enrollment.Digest || request.SessionId != first.SessionId || request.Epoch != first.Epoch))
                throw new InvalidOperationException("Artifact delivery must stay within this host's enrolled scope and session.");
            first ??= request;
            var response = await SendAsync(request, transfer.Token).ConfigureAwait(false);
            if (!response.Accepted)
            {
                if (response.Decision is RegionalHostSessionDecision.StoreUnavailable or RegionalHostSessionDecision.Contention)
                {
                    await Task.Delay(TimeSpan.FromMilliseconds(250), transfer.Token).ConfigureAwait(false);
                    continue;
                }
                throw new InvalidOperationException($"Artifact delivery was denied: {response.Decision}.");
            }
            if (total is not null && total != response.TotalBytes)
                throw new InvalidDataException("The artifact length changed during transfer.");
            total = response.TotalBytes;
            transfer.Token.ThrowIfCancellationRequested();
            await destination.WriteAsync(response.Bytes, transfer.Token).ConfigureAwait(false);
            offset += response.Bytes!.Length;
            if (response.End)
            {
                transfer.Token.ThrowIfCancellationRequested();
                return;
            }
        }
    }

    internal async Task<RegionalHostArtifactResponse> SendAsync(RegionalHostArtifactRequest request, CancellationToken cancellationToken)
    {
        if (request.Enrollment.Region != cell.ToUpperInvariant() || request.Enrollment.NodeId != nodeId)
            throw new InvalidOperationException("The artifact request does not match this host identity.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(5));
        var reply = RegionalHostArtifactRequest.ReplySubject(cell, nodeId, request.RequestId);
        await using var subscription = await connection.SubscribeCoreAsync<string>(reply,
            opts: new NatsSubOpts { MaxMsgs = 1, ChannelOpts = new NatsSubChannelOpts { Capacity = 1, FullMode = BoundedChannelFullMode.DropWrite } }, cancellationToken: deadline.Token).ConfigureAwait(false);
        await connection.PingAsync(deadline.Token).AsTask().WaitAsync(deadline.Token).ConfigureAwait(false);
        await connection.PublishAsync(RegionalHostArtifactRequest.Subject(cell, nodeId), request.Serialize(), replyTo: reply,
            cancellationToken: deadline.Token).ConfigureAwait(false);
        var message = await subscription.Msgs.ReadAsync(deadline.Token).ConfigureAwait(false);
        if (message.Data is not { Length: > 0 and <= RegionalHostArtifactResponse.MaximumWireBytes } json ||
            Encoding.UTF8.GetByteCount(json) > RegionalHostArtifactResponse.MaximumWireBytes)
            throw new InvalidDataException("The artifact response exceeds its wire bounds.");
        var response = JsonSerializer.Deserialize<RegionalHostArtifactResponse>(json, RegionalHostSessionAuthority.JsonOptions)
            ?? throw new InvalidDataException("The artifact response is missing.");
        response.RequireBinding(request, time.GetUtcNow());
        if (response.Bytes is not null)
        {
            using var document = JsonDocument.Parse(json);
            if (document.RootElement.GetProperty(nameof(response.Bytes)).GetString() != Convert.ToBase64String(response.Bytes))
                throw new InvalidDataException("Artifact bytes must use canonical base64 encoding.");
        }
        deadline.Token.ThrowIfCancellationRequested();
        return response;
    }
}
