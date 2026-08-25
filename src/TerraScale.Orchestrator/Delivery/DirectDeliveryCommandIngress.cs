using System.Text;
using System.Text.Json;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery.DeployHandoff;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Delivery;

/// <summary>The payload kind admitted through the signed direct-delivery mutation endpoint.</summary>
internal enum DirectDeliveryCommandPayloadKind
{
    None = 0,
    /// <summary>The canonical version-1 <see cref="DeliveryRequest"/> document.</summary>
    DeliveryRequest = 1,
    /// <summary>The Deploy-to-Orchestrator handoff manifest (mapping v1).</summary>
    DeployHandoffManifest = 2,
}

/// <summary>
/// The admitted outcome of one signed mutation: exactly one executable payload kind, or a typed
/// refusal. A rejected handoff mapping carries its bounded error so the refusal receipt can name
/// the exact remediation instead of a generic denial.
/// </summary>
internal sealed record DirectDeliveryCommandAdmission(
    DirectDeliveryCommandPayloadKind Kind,
    DeliveryRequest? Request,
    DeployHandoffMappingResult? Handoff,
    DirectDeliveryCommandWireError Error,
    CommandValidationError ValidationError,
    int Attempt = 0)
{
    internal bool IsExecutable =>
        Kind == DirectDeliveryCommandPayloadKind.DeliveryRequest && Request is not null ||
        Kind == DirectDeliveryCommandPayloadKind.DeployHandoffManifest &&
            Handoff is { IsAdmittedForTargetMutation: true };
}

/// <summary>
/// The payload-kind discriminator behind the signed direct-delivery mutation endpoint. Exactly
/// two payload shapes are admitted — the canonical DeliveryRequest and the Deploy handoff
/// manifest — and both sign through the same envelope material. Everything else, including a
/// manifest whose operation identity differs from its envelope, fails closed before dispatch.
/// </summary>
internal static class DirectDeliveryCommandIngress
{
    /// <summary>
    /// Validates the signed envelope and canonicalizes its payload. Direct requests are fenced
    /// against the expected authority lease exactly like the historical single-kind endpoint;
    /// handoff manifests cannot carry lease claims their signer does not know, so their envelope
    /// is validated without the lease-equality check and the runtime binds execution to the live
    /// lease when it stamps the canonical request.
    /// </summary>
    internal static DirectDeliveryCommandAdmission Decode(
        ReadOnlyMemory<byte> payload,
        IEnumerable<KeyValuePair<string, string>>? headers,
        string expectedCell,
        DateTimeOffset now,
        TimeSpan allowedClockSkew,
        ICommandSignatureVerifier signatureVerifier,
        long? expectedGeneration,
        long? expectedEpoch)
    {
        // Canonicalize first: the payload kind decides which lease expectations apply, and both
        // kinds sign the same envelope material over the exact payload bytes either way.
        var request = DirectDeliveryCommandWire.TryCanonicalizeDeliveryRequest(payload);
        if (request is not null)
        {
            var envelope = DirectDeliveryCommandWire.ValidateSignedEnvelope(
                payload, headers, expectedCell, now, allowedClockSkew, signatureVerifier,
                expectedGeneration, expectedEpoch, request.OperationId);
            if (envelope.Error != DirectDeliveryCommandWireError.None)
                return Refused(envelope.Error, envelope.ValidationError);
            if (request.AuthorityGeneration != envelope.Generation ||
                request.WriterEpoch != envelope.Epoch ||
                request.Attempt != envelope.Attempt)
                return Refused(
                    DirectDeliveryCommandWireError.MalformedEnvelope, CommandValidationError.MalformedEnvelope);
            return new(DirectDeliveryCommandPayloadKind.DeliveryRequest, request, null,
                DirectDeliveryCommandWireError.None, CommandValidationError.None, envelope.Attempt);
        }

        if (TryCanonicalizeHandoffManifest(payload) is { } manifest)
        {
            // A handoff signer cannot claim a regional authority lease it cannot observe; the
            // lease-equality expectations are therefore not applied to this payload kind. The
            // envelope signature, cell, operation identity, and validity window still bind the
            // exact manifest bytes.
            var envelope = DirectDeliveryCommandWire.ValidateSignedEnvelope(
                payload, headers, expectedCell, now, allowedClockSkew, signatureVerifier, null, null,
                manifest.OperationId);
            if (envelope.Error != DirectDeliveryCommandWireError.None)
                return Refused(envelope.Error, envelope.ValidationError);
            var mapping = DeployHandoffMapper.Map(manifest);
            return new(
                DirectDeliveryCommandPayloadKind.DeployHandoffManifest,
                null,
                mapping,
                DirectDeliveryCommandWireError.None,
                CommandValidationError.None,
                envelope.Attempt);
        }

        return Refused(
            DirectDeliveryCommandWireError.MalformedEnvelope, CommandValidationError.MalformedEnvelope);
    }

    /// <summary>
    /// The redacted receipt for a mutation refused before dispatch: malformed wire input is an
    /// input error; any envelope rejection (signature, cell, validity window) is a denial; a
    /// mapper-rejected handoff carries its bounded remediation.
    /// </summary>
    internal static DeliveryReceipt RefusalReceipt(DirectDeliveryCommandAdmission admission)
    {
        ArgumentNullException.ThrowIfNull(admission);
        if (admission.Kind == DirectDeliveryCommandPayloadKind.DeployHandoffManifest &&
            admission.Handoff is { IsAdmittedForTargetMutation: false, Error: { } error })
            return new(
                DeliveryRequest.CurrentSchemaVersion,
                "invalid",
                DeliveryReceiptStatus.Failed,
                null,
                null,
                null,
                new DeliveryProvenance(false, null, null),
                new DeliveryHealth([], false),
                new DeliveryRollback(false, null, DeliveryRollbackStatus.NotRequired),
                "refused",
                new DeliveryErrorInfo(
                    DirectDeliveryErrorCode.InvalidInput,
                    $"The signed direct-delivery handoff manifest was rejected ({error.Code}): {error.Message}",
                    error.Remediation));
        return new(
            DeliveryRequest.CurrentSchemaVersion,
            "invalid",
            DeliveryReceiptStatus.Failed,
            null,
            null,
            null,
            new DeliveryProvenance(false, null, null),
            new DeliveryHealth([], false),
            new DeliveryRollback(false, null, DeliveryRollbackStatus.NotRequired),
            "refused",
            new DeliveryErrorInfo(
                admission.Error == DirectDeliveryCommandWireError.MalformedEnvelope
                    ? DirectDeliveryErrorCode.InvalidInput
                    : DirectDeliveryErrorCode.UnauthorizedActor,
                "The signed direct-delivery command envelope was rejected before dispatch.",
                "Check the command signature, cell, validity window, and canonical payload bytes."));
    }

    private static DirectDeliveryCommandAdmission Refused(
        DirectDeliveryCommandWireError error, CommandValidationError validation) =>
        new(DirectDeliveryCommandPayloadKind.None, null, null, error, validation);

    /// <summary>
    /// A canonical handoff manifest payload: it must round-trip byte-exactly through the contract
    /// codec, so the signed payload digest always identifies one deterministic manifest document.
    /// </summary>
    private static DeployHandoffManifest? TryCanonicalizeHandoffManifest(ReadOnlyMemory<byte> payload)
    {
        string json;
        try
        {
            json = Encoding.UTF8.GetString(payload.Span);
        }
        catch (Exception exception) when (exception is DecoderFallbackException)
        {
            return null;
        }
        try
        {
            var manifest = JsonSerializer.Deserialize<DeployHandoffManifest>(json, DeployHandoffMapper.ManifestJsonOptions);
            return manifest is not null &&
                    Encoding.UTF8.GetBytes(
                        DeployHandoffMapper.SerializeManifest(manifest)).AsSpan().SequenceEqual(payload.Span)
                ? manifest
                : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
