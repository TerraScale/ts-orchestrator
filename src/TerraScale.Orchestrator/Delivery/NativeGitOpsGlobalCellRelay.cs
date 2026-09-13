using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Delivery;

internal enum NativeGitOpsGlobalCellRelayDisposition
{
    Unspecified,
    Malformed,
    Rejected,
    AuthorityLostBeforeRegionalPublish,
    AuthorityLostAfterRegionalPublish,
    AuthorityLostBeforeGlobalAcknowledge,
    Acknowledged,
}

internal sealed record NativeGitOpsGlobalCellRelayReceipt(
    NativeGitOpsGlobalCellRelayDisposition Disposition,
    NativeGitOpsCellEnvelopeError ValidationError,
    CommandValidationError ProtocolError,
    NativeGitOpsCellPublishReceipt? RegionalPublication)
{
    internal bool IsAcknowledged => Disposition == NativeGitOpsGlobalCellRelayDisposition.Acknowledged;
}

/// <summary>
/// Verifies one exact globally stored CellSpec, publishes the unchanged wire command to regional
/// CELL_SPEC, and acknowledges the global delivery only after regional JetStream storage succeeds.
/// </summary>
internal sealed class NativeGitOpsGlobalCellRelay(NativeGitOpsCellPublisher regionalPublisher)
{
    internal async Task<NativeGitOpsGlobalCellRelayReceipt> RelayAsync(
        ReadOnlyMemory<byte> payload,
        IEnumerable<KeyValuePair<string, string>> headers,
        string expectedCell,
        long expectedWriterEpoch,
        DateTimeOffset now,
        TimeSpan allowedClockSkew,
        ICommandSignatureVerifier signatureVerifier,
        Func<bool> regionalAuthorityStillValid,
        Func<CancellationToken, Task> acknowledgeGlobal,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(headers);
        ArgumentNullException.ThrowIfNull(signatureVerifier);
        ArgumentNullException.ThrowIfNull(regionalAuthorityStillValid);
        ArgumentNullException.ThrowIfNull(acknowledgeGlobal);
        NativeGitOpsDecodedCellCommand decoded;
        NativeGitOpsCellWireMessage message;
        try
        {
            var captured = headers.Take(17).ToArray();
            decoded = NativeGitOpsCellWireCodec.Decode(payload, captured);
            message = new(
                payload,
                captured.ToDictionary(
                    static item => item.Key,
                    static item => item.Value,
                    StringComparer.Ordinal));
        }
        catch (Exception exception) when (exception is InvalidDataException or ArgumentException)
        {
            return Result(
                NativeGitOpsGlobalCellRelayDisposition.Malformed,
                NativeGitOpsCellEnvelopeError.InvalidInput,
                CommandValidationError.MalformedEnvelope,
                null);
        }

        var validation = NativeGitOpsCellEnvelope.Validate(
            decoded.Envelope,
            decoded.Handoff,
            expectedCell,
            expectedWriterEpoch,
            now,
            allowedClockSkew,
            signatureVerifier);
        if (!validation.IsAccepted)
            return Result(
                NativeGitOpsGlobalCellRelayDisposition.Rejected,
                validation.Error,
                validation.ProtocolError,
                null);

        var cell = new NativeGitOpsPreparedCellSpec(
            decoded.Envelope.Cell.Value,
            Convert.ToHexStringLower(decoded.Envelope.PayloadDigest.Bytes),
            string.Empty,
            message);
        cell = cell with { WireSha256 = NativeGitOpsSignedHandoffJournal.ComputeWireSha256(cell) };
        var publication = await regionalPublisher.PublishPreparedAsync(
            decoded.Handoff,
            cell,
            regionalAuthorityStillValid,
            cancellationToken);
        if (publication.Disposition == NativeGitOpsCellPublishDisposition.AuthorityLostBeforePublish)
            return Result(
                NativeGitOpsGlobalCellRelayDisposition.AuthorityLostBeforeRegionalPublish,
                validation.Error,
                validation.ProtocolError,
                publication);
        if (publication.Disposition == NativeGitOpsCellPublishDisposition.AuthorityLostAfterPublish)
            return Result(
                NativeGitOpsGlobalCellRelayDisposition.AuthorityLostAfterRegionalPublish,
                validation.Error,
                validation.ProtocolError,
                publication);
        if (!publication.IsDurable)
            throw new InvalidDataException("A relayed native GitOps CellSpec was not durably published.");
        if (!regionalAuthorityStillValid())
            return Result(
                NativeGitOpsGlobalCellRelayDisposition.AuthorityLostBeforeGlobalAcknowledge,
                validation.Error,
                validation.ProtocolError,
                publication);

        await acknowledgeGlobal(cancellationToken);
        return Result(
            NativeGitOpsGlobalCellRelayDisposition.Acknowledged,
            validation.Error,
            validation.ProtocolError,
            publication);
    }

    private static NativeGitOpsGlobalCellRelayReceipt Result(
        NativeGitOpsGlobalCellRelayDisposition disposition,
        NativeGitOpsCellEnvelopeError validationError,
        CommandValidationError protocolError,
        NativeGitOpsCellPublishReceipt? publication) => new(
        disposition,
        validationError,
        protocolError,
        publication);
}

