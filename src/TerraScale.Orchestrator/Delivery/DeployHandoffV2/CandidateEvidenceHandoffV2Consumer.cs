using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Delivery.DeployHandoffV2;

/// <summary>
/// Exact Orchestrator consumer for the v2 handoff. It reads the existing durable artifact/source
/// authority and verifies its established signature before the pure verifier can create a
/// DeliveryRequest. It owns no promotion state and performs no rollout or target mutation.
/// </summary>
internal sealed class CandidateEvidenceHandoffV2Consumer(
    DirectDeliveryArtifactEvidenceJournal artifactEvidence,
    IRepositoryCiArtifactSignatureVerifier artifactEvidenceVerifier,
    ICandidateEvidenceHandoffV2SignatureVerifier handoffSignatureVerifier)
{
    private readonly DirectDeliveryArtifactEvidenceJournal artifactEvidence = artifactEvidence ??
        throw new ArgumentNullException(nameof(artifactEvidence));
    private readonly IRepositoryCiArtifactSignatureVerifier artifactEvidenceVerifier = artifactEvidenceVerifier ??
        throw new ArgumentNullException(nameof(artifactEvidenceVerifier));
    private readonly ICandidateEvidenceHandoffV2SignatureVerifier handoffSignatureVerifier = handoffSignatureVerifier ??
        throw new ArgumentNullException(nameof(handoffSignatureVerifier));

    internal async ValueTask<CandidateEvidenceHandoffV2Result> VerifyAsync(
        ReadOnlyMemory<byte> document,
        CandidateEvidenceHandoffV2AdmissionPolicy policy,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (!CandidateEvidenceHandoffV2Verifier.TryReadArtifactDigest(document, out var artifactDigest))
            return CandidateEvidenceHandoffV2Result.Reject(
                "handoff_v2_document_invalid",
                "The candidate handoff does not contain one bounded exact artifact digest.",
                "Regenerate the signed version-2 handoff.");
        DirectDeliverySignedArtifactEvidence? signed;
        try
        {
            signed = await artifactEvidence.ReadAsync(artifactDigest, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (exception is InvalidDataException or ArgumentException)
        {
            return CandidateEvidenceHandoffV2Result.Reject(
                "handoff_v2_durable_evidence_invalid",
                "Orchestrator's durable artifact/source evidence is corrupt or mismatched.",
                "Repair the existing artifact evidence authority before candidate admission.");
        }
        catch (Exception exception) when (exception is not (OutOfMemoryException or StackOverflowException or
            AccessViolationException))
        {
            return CandidateEvidenceHandoffV2Result.Reject(
                "handoff_v2_durable_evidence_unavailable",
                "Orchestrator's durable artifact/source evidence authority is unavailable.",
                "Retry without changing the candidate after the existing evidence authority recovers.");
        }
        if (signed is null)
            return CandidateEvidenceHandoffV2Result.Reject(
                "handoff_v2_durable_evidence_missing",
                "No durable artifact/source evidence exists for the candidate digest.",
                "Record the signed CI artifact evidence before candidate admission.");
        bool verified;
        try
        {
            verified = DirectDeliveryArtifactEvidenceJournal.Verifies(signed, artifactEvidenceVerifier);
        }
        catch (Exception exception) when (exception is not (OutOfMemoryException or StackOverflowException or
            AccessViolationException))
        {
            verified = false;
        }
        return CandidateEvidenceHandoffV2Verifier.Verify(
            document,
            policy,
            signed.Evidence,
            verified,
            handoffSignatureVerifier);
    }
}

/// <summary>Reuses the established command-signature contract and rotating CI trust roots.</summary>
internal sealed class RepositoryCandidateEvidenceHandoffV2SignatureVerifier(
    IRepositoryCiArtifactSignatureVerifier verifier) : ICandidateEvidenceHandoffV2SignatureVerifier
{
    private readonly IRepositoryCiArtifactSignatureVerifier verifier = verifier ??
        throw new ArgumentNullException(nameof(verifier));

    public bool Verify(
        string signingIdentity,
        ReadOnlyMemory<byte> canonicalMaterial,
        ReadOnlyMemory<byte> signature)
    {
        if (!OpaqueSignature.TryCopyFrom(signature.Span, out var opaque) || opaque is null)
            return false;
        return verifier.Verify(signingIdentity, canonicalMaterial, opaque) == VerificationOutcome.Valid;
    }
}

