using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Net;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Delivery;

internal enum NativeGitOpsGlobalHandoffPublishDisposition
{
    Unspecified,
    Complete,
    AuthorityLostBeforePublish,
    AuthorityLostAfterPublish,
}

internal enum NativeGitOpsGlobalCellPublishDisposition
{
    Unspecified,
    Published,
    Duplicate,
    AuthorityLostAfterPublish,
}

internal sealed record NativeGitOpsGlobalCellPublishReceipt(
    NativeGitOpsGlobalCellPublishDisposition Disposition,
    string Cell,
    string WireSha256,
    ulong StreamSequence)
{
    internal bool IsDurable => StreamSequence > 0 && Disposition is
        NativeGitOpsGlobalCellPublishDisposition.Published or
        NativeGitOpsGlobalCellPublishDisposition.Duplicate or
        NativeGitOpsGlobalCellPublishDisposition.AuthorityLostAfterPublish;
}

internal sealed record NativeGitOpsGlobalHandoffPublishReceipt(
    NativeGitOpsGlobalHandoffPublishDisposition Disposition,
    IReadOnlyList<NativeGitOpsGlobalCellPublishReceipt> Cells)
{
    internal bool IsComplete => Disposition == NativeGitOpsGlobalHandoffPublishDisposition.Complete &&
        Cells.Count > 0 && Cells.All(static cell => cell.IsDurable);
}

internal sealed record NativeGitOpsGlobalCellPublishAttempt(
    NativeGitOpsGlobalHandoffPublishDisposition Disposition,
    NativeGitOpsGlobalCellPublishReceipt? Cell);

internal sealed record NativeGitOpsGlobalHandoffTransportAck(
    string Stream,
    ulong Sequence,
    bool Duplicate);

internal interface INativeGitOpsGlobalHandoffTransport
{
    Task<NativeGitOpsGlobalHandoffTransportAck> PublishAsync(
        string subject,
        string messageId,
        NativeGitOpsCellWireMessage message,
        CancellationToken cancellationToken);
}

internal sealed class NatsNativeGitOpsGlobalHandoffTransport(NatsClient client)
    : INativeGitOpsGlobalHandoffTransport
{
    public async Task<NativeGitOpsGlobalHandoffTransportAck> PublishAsync(
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
                ExpectedStream = NativeGitOpsGlobalHandoffPublisher.Stream,
                RetryAttempts = 3,
                RetryWaitBetweenAttempts = TimeSpan.FromMilliseconds(250),
            },
            headers: headers,
            cancellationToken: cancellationToken);
            // A duplicate message id is the converged receipt of the identical message,
            // never an error: the id is derived from the exact content being stored.
            _ = acknowledgement.EnsureStored();
        return new(
            acknowledgement.Stream ?? string.Empty,
            acknowledgement.Seq,
            acknowledgement.Duplicate);
    }
}

/// <summary>
/// Sequentially appends one already-persisted exact CellSpec per cell to GLOBAL_SPEC. It never
/// signs, regenerates, or publishes cells concurrently, and a partial authority loss cannot report
/// a complete global handoff.
/// </summary>
internal sealed class NativeGitOpsGlobalHandoffPublisher(INativeGitOpsGlobalHandoffTransport transport)
{
    internal const string Stream = "GLOBAL_SPEC";
    private const string SubjectPrefix = TerraScale.Orchestrator.Protocol.Messaging.NatsSubjectTaxonomy.GlobalCellSpecPrefix;

    internal async Task<NativeGitOpsGlobalHandoffPublishReceipt> PublishAsync(
        NativeGitOpsPreparedHandoff handoff,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(handoff);
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        Validate(handoff);
        var receipts = new List<NativeGitOpsGlobalCellPublishReceipt>(handoff.Cells.Count);
        foreach (var cell in handoff.Cells)
        {
            var attempt = await PublishCellCoreAsync(handoff, cell, authorityStillValid, cancellationToken);
            if (attempt.Cell is not null) receipts.Add(attempt.Cell);
            if (attempt.Disposition != NativeGitOpsGlobalHandoffPublishDisposition.Complete)
                return Result(attempt.Disposition, receipts);
        }
        return Result(NativeGitOpsGlobalHandoffPublishDisposition.Complete, receipts);
    }

    internal async Task<NativeGitOpsGlobalCellPublishAttempt> PublishCellAsync(
        NativeGitOpsPreparedHandoff handoff,
        NativeGitOpsPreparedCellSpec cell,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(handoff);
        ArgumentNullException.ThrowIfNull(cell);
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        Validate(handoff);
        if (!handoff.Cells.Any(prepared => prepared == cell))
            throw new InvalidDataException("The native GitOps global publication cell is not prepared.");
        return await PublishCellCoreAsync(handoff, cell, authorityStillValid, cancellationToken);
    }

    private async Task<NativeGitOpsGlobalCellPublishAttempt> PublishCellCoreAsync(
        NativeGitOpsPreparedHandoff handoff,
        NativeGitOpsPreparedCellSpec cell,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken)
    {
        if (!authorityStillValid())
            return new(NativeGitOpsGlobalHandoffPublishDisposition.AuthorityLostBeforePublish, null);
        var acknowledgement = await transport.PublishAsync(
            $"{SubjectPrefix}.{cell.Cell}",
            $"gitops-global:{handoff.Descriptor.HandoffDigest}:{cell.Cell}:{handoff.AuthorityEpoch}",
            cell.Message,
            cancellationToken);
        if (acknowledgement.Stream != Stream || acknowledgement.Sequence == 0)
            throw new InvalidDataException("The native GitOps global handoff acknowledgement is invalid.");
        if (!authorityStillValid())
            return new(
                NativeGitOpsGlobalHandoffPublishDisposition.AuthorityLostAfterPublish,
                new(
                    NativeGitOpsGlobalCellPublishDisposition.AuthorityLostAfterPublish,
                    cell.Cell,
                    cell.WireSha256,
                    acknowledgement.Sequence));
        return new(
            NativeGitOpsGlobalHandoffPublishDisposition.Complete,
            new(
                acknowledgement.Duplicate
                    ? NativeGitOpsGlobalCellPublishDisposition.Duplicate
                    : NativeGitOpsGlobalCellPublishDisposition.Published,
                cell.Cell,
                cell.WireSha256,
                acknowledgement.Sequence));
    }

    internal static void Validate(NativeGitOpsPreparedHandoff handoff)
    {
        if (handoff.SourceJournalRevision == 0 || handoff.AuthorityEpoch <= 0 ||
            !NativeGitOpsCellEnvelope.IsValidDescriptor(handoff.Descriptor) ||
            handoff.Cells is not { Count: > 0 } ||
            !handoff.Descriptor.Cells.Select(static cell => cell.Cell)
                .SequenceEqual(handoff.Cells.Select(static cell => cell.Cell), StringComparer.Ordinal))
            throw new InvalidDataException("The prepared native GitOps global handoff is invalid.");
        foreach (var cell in handoff.Cells)
        {
            if (NativeGitOpsSignedHandoffJournal.ComputeWireSha256(cell) != cell.WireSha256)
                throw new InvalidDataException("A prepared native GitOps CellSpec changed exact wire bytes.");
            var decoded = NativeGitOpsCellWireCodec.Decode(cell.Message.Payload, cell.Message.Headers);
            var expected = handoff.Descriptor.Cells.Single(item => item.Cell == cell.Cell);
            if (!Same(decoded.Handoff, handoff.Descriptor) ||
                decoded.Envelope.Cell.Value != cell.Cell ||
                decoded.Envelope.WriterEpoch.Value != handoff.AuthorityEpoch ||
                cell.PayloadSha256 != expected.PayloadSha256 ||
                Convert.ToHexStringLower(decoded.Envelope.PayloadDigest.Bytes) != expected.PayloadSha256)
                throw new InvalidDataException("A prepared native GitOps CellSpec changed handoff identity.");
        }
    }

    private static NativeGitOpsGlobalHandoffPublishReceipt Result(
        NativeGitOpsGlobalHandoffPublishDisposition disposition,
        List<NativeGitOpsGlobalCellPublishReceipt> receipts) => new(
        disposition,
        Array.AsReadOnly(receipts.ToArray()));

    private static bool Same(
        NativeGitOpsCellHandoffDescriptor left,
        NativeGitOpsCellHandoffDescriptor right) =>
        left.Generation == right.Generation &&
        left.GlobalPlanDigest == right.GlobalPlanDigest &&
        left.HandoffDigest == right.HandoffDigest &&
        left.Cells.SequenceEqual(right.Cells);
}
