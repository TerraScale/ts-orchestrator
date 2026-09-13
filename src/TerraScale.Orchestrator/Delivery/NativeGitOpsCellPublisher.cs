using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Net;
using TerraScale.Orchestrator.Messaging;
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
            // A duplicate message id is the converged receipt of the identical message,
            // never an error: the id is derived from the exact content being stored.
            _ = acknowledgement.EnsureStored();
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
        var descriptor = NativeGitOpsCellEnvelope.Describe(handoff)
            ?? throw new InvalidDataException("The native GitOps handoff cannot be published.");
        var message = NativeGitOpsCellWireCodec.Encode(handoff, envelope);
        return await PublishCoreAsync(
            descriptor,
            envelope,
            message,
            authorityStillValid,
            cancellationToken);
    }

    internal async Task<NativeGitOpsCellPublishReceipt> PublishPreparedAsync(
        NativeGitOpsCellHandoffDescriptor handoff,
        NativeGitOpsPreparedCellSpec prepared,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(handoff);
        ArgumentNullException.ThrowIfNull(prepared);
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        var decoded = NativeGitOpsCellWireCodec.Decode(prepared.Message.Payload, prepared.Message.Headers);
        if (!Same(handoff, decoded.Handoff) || decoded.Envelope.Cell.Value != prepared.Cell ||
            Convert.ToHexStringLower(decoded.Envelope.PayloadDigest.Bytes) != prepared.PayloadSha256)
            throw new InvalidDataException("The prepared native GitOps CellSpec changed handoff identity.");
        return await PublishCoreAsync(
            handoff,
            decoded.Envelope,
            prepared.Message,
            authorityStillValid,
            cancellationToken);
    }

    private async Task<NativeGitOpsCellPublishReceipt> PublishCoreAsync(
        NativeGitOpsCellHandoffDescriptor handoff,
        CommandEnvelope envelope,
        NativeGitOpsCellWireMessage message,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken)
    {
        var cell = envelope.Cell.Value;
        var spec = handoff.Cells.SingleOrDefault(item => item.Cell == cell)
            ?? throw new InvalidDataException("The native GitOps CellSpec is not part of the handoff.");
        if (!authorityStillValid())
            return Receipt(
                NativeGitOpsCellPublishDisposition.AuthorityLostBeforePublish,
                handoff,
                spec,
                envelope.WriterEpoch.Value,
                0);

        var acknowledgement = await transport.PublishAsync(
            TerraScale.Orchestrator.Protocol.Messaging.NatsSubjectTaxonomy.CellSpecSubject(cell),
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
        NativeGitOpsCellHandoffDescriptor handoff,
        NativeGitOpsCellDigest spec,
        long writerEpoch,
        ulong sequence) => new(
        disposition,
        spec.Cell,
        handoff.HandoffDigest,
        spec.PayloadSha256,
        writerEpoch,
        sequence);

    private static bool Same(
        NativeGitOpsCellHandoffDescriptor left,
        NativeGitOpsCellHandoffDescriptor right) =>
        left.Generation == right.Generation &&
        left.GlobalPlanDigest == right.GlobalPlanDigest &&
        left.HandoffDigest == right.HandoffDigest &&
        left.Cells.SequenceEqual(right.Cells);
}

