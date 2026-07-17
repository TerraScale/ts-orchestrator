using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Delivery;

internal enum NativeGitOpsCellDeliveryDisposition
{
    Unspecified,
    Malformed,
    Rejected,
    AuthorityLostAfterAcceptance,
    Acknowledged,
}

internal sealed record NativeGitOpsCellDeliveryReceipt(
    NativeGitOpsCellDeliveryDisposition Disposition,
    NativeGitOpsCellAcceptanceDisposition AcceptanceDisposition,
    CommandValidationError ProtocolError,
    NativeGitOpsAcceptedCellSpec? Acceptance)
{
    internal bool IsAcknowledged => Disposition == NativeGitOpsCellDeliveryDisposition.Acknowledged;
}

/// <summary>
/// Drives one regional CellSpec delivery through decode, signature validation, durable acceptance,
/// a final authority check, and acknowledgement. It contains no receive loop or KMS policy.
/// </summary>
internal sealed class NativeGitOpsCellInbox(NativeGitOpsCellAcceptanceJournal journal)
{
    internal async Task<NativeGitOpsCellDeliveryReceipt> ProcessAsync(
        ReadOnlyMemory<byte> payload,
        IEnumerable<KeyValuePair<string, string>> headers,
        ulong streamSequence,
        string expectedCell,
        long expectedWriterEpoch,
        DateTimeOffset now,
        TimeSpan allowedClockSkew,
        ICommandSignatureVerifier signatureVerifier,
        Func<bool> authorityStillValid,
        Func<CancellationToken, Task> acknowledge,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(headers);
        ArgumentNullException.ThrowIfNull(signatureVerifier);
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        ArgumentNullException.ThrowIfNull(acknowledge);
        NativeGitOpsDecodedCellCommand command;
        try
        {
            command = NativeGitOpsCellWireCodec.Decode(payload, headers);
        }
        catch (InvalidDataException)
        {
            return new(
                NativeGitOpsCellDeliveryDisposition.Malformed,
                NativeGitOpsCellAcceptanceDisposition.Unspecified,
                CommandValidationError.MalformedEnvelope,
                null);
        }

        NativeGitOpsCellAcceptanceReceipt acceptance;
        try
        {
            acceptance = await journal.AcceptAsync(
                command.Envelope,
                command.Handoff,
                expectedCell,
                expectedWriterEpoch,
                streamSequence,
                now,
                allowedClockSkew,
                signatureVerifier,
                authorityStillValid,
                cancellationToken);
        }
        catch (ArgumentException)
        {
            return new(
                NativeGitOpsCellDeliveryDisposition.Malformed,
                NativeGitOpsCellAcceptanceDisposition.Unspecified,
                CommandValidationError.InvalidValidationContext,
                null);
        }
        if (!acceptance.CanAcknowledge)
            return new(
                NativeGitOpsCellDeliveryDisposition.Rejected,
                acceptance.Disposition,
                acceptance.ProtocolError,
                null);
        if (!authorityStillValid())
            return new(
                NativeGitOpsCellDeliveryDisposition.AuthorityLostAfterAcceptance,
                acceptance.Disposition,
                acceptance.ProtocolError,
                acceptance.Acceptance);

        await acknowledge(cancellationToken);
        return new(
            NativeGitOpsCellDeliveryDisposition.Acknowledged,
            acceptance.Disposition,
            acceptance.ProtocolError,
            acceptance.Acceptance);
    }
}
