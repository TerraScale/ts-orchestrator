using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Net;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Delivery;

internal enum NativeGitOpsCellPublishDisposition
{
    Unspecified,
    Published,
    Duplicate,
    AuthorityLostBeforePublish,
    AuthorityLostAfterPublish,
}

internal sealed record NativeGitOpsCellPublishReceipt(
    NativeGitOpsCellPublishDisposition Disposition,
    string Cell,
    string HandoffDigest,
    string PayloadSha256,
    long WriterEpoch,
    ulong StreamSequence)
{
    internal bool IsDurable =>
        (Disposition is NativeGitOpsCellPublishDisposition.Published or
            NativeGitOpsCellPublishDisposition.Duplicate or
            NativeGitOpsCellPublishDisposition.AuthorityLostAfterPublish) &&
        StreamSequence > 0;
}

internal sealed record NativeGitOpsCellTransportAck(
    string Stream,
    ulong Sequence,
    bool Duplicate);

internal interface INativeGitOpsCellTransport
{
    Task<NativeGitOpsCellTransportAck> PublishAsync(
        string subject,
        string messageId,
        NativeGitOpsCellWireMessage message,
        CancellationToken cancellationToken);
}

internal sealed class NatsNativeGitOpsCellTransport(NatsClient client) : INativeGitOpsCellTransport
{
    public async Task<NativeGitOpsCellTransportAck> PublishAsync(
        string subject,
        string messageId,
        NativeGitOpsCellWireMessage message,
        CancellationToken cancellationToken)
    {
        var headers = new NatsHeaders();
        foreach (var header in message.Headers) headers[header.Key] = header.Value;
        var acknowledgement = await client.CreateJetStreamContext().PublishAsync(
            subject,
            message.Payload.ToArray(),
            opts: new NatsJSPubOpts
            {
                MsgId = messageId,
                ExpectedStream = NativeGitOpsCellPublisher.Stream,
                RetryAttempts = 3,
                RetryWaitBetweenAttempts = TimeSpan.FromMilliseconds(250),
            },
            headers: headers,
            cancellationToken: cancellationToken);
        acknowledgement.EnsureSuccess();
        return new(acknowledgement.Stream ?? string.Empty, acknowledgement.Seq, acknowledgement.Duplicate);
    }
}

/// <summary>
/// Publishes one already-signed regional CellSpec and requires a JetStream storage acknowledgement.
/// A writer-epoch-aware message identity deduplicates retries without suppressing a fenced takeover.
/// </summary>
internal sealed class NativeGitOpsCellPublisher(INativeGitOpsCellTransport transport)
{
    internal const string Stream = "CELL_SPEC";

    internal async Task<NativeGitOpsCellPublishReceipt> PublishAsync(
        NativeGitOpsCellHandoff handoff,
        CommandEnvelope envelope,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(handoff);
        ArgumentNullException.ThrowIfNull(envelope);
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        var message = NativeGitOpsCellWireCodec.Encode(handoff, envelope);
        var cell = envelope.Cell.Value;
        var spec = handoff.Cells.Single(item => item.Cell == cell);
        if (!authorityStillValid())
            return Receipt(
                NativeGitOpsCellPublishDisposition.AuthorityLostBeforePublish,
                handoff,
                spec,
                envelope.WriterEpoch.Value,
                0);

        var acknowledgement = await transport.PublishAsync(
            $"ts.orch.v1.{cell}.desired.gitops",
            $"gitops:{handoff.HandoffDigest}:{cell}:{envelope.WriterEpoch.Value}",
            message,
            cancellationToken);
        if (acknowledgement.Stream != Stream || acknowledgement.Sequence == 0)
            throw new InvalidDataException("The native GitOps CellSpec publish acknowledgement is invalid.");
        if (!authorityStillValid())
            return Receipt(
                NativeGitOpsCellPublishDisposition.AuthorityLostAfterPublish,
                handoff,
                spec,
                envelope.WriterEpoch.Value,
                acknowledgement.Sequence);
        return Receipt(
            acknowledgement.Duplicate
                ? NativeGitOpsCellPublishDisposition.Duplicate
                : NativeGitOpsCellPublishDisposition.Published,
            handoff,
            spec,
            envelope.WriterEpoch.Value,
            acknowledgement.Sequence);
    }

    private static NativeGitOpsCellPublishReceipt Receipt(
        NativeGitOpsCellPublishDisposition disposition,
        NativeGitOpsCellHandoff handoff,
        NativeGitOpsCellSpec spec,
        long writerEpoch,
        ulong sequence) => new(
        disposition,
        spec.Cell,
        handoff.HandoffDigest,
        spec.PayloadSha256,
        writerEpoch,
        sequence);
}
