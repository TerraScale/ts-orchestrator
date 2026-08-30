using System.Text.Json.Serialization;
using TerraScale.Orchestrator.ControlPlane.Delivery;

namespace TerraScale.Orchestrator.Delivery.DeployHandoffV2;

internal static class CandidateEvidenceHandoffV2Contract
{
    internal const int SchemaVersion = 2;
    internal const string MediaType = "application/vnd.terrascale.candidate-evidence-handoff.v2+json";
    internal const string SigningDomain = "terrascale.deploy/candidate-evidence-handoff/v2";
    internal const string SigningAlgorithm = "ecdsa-p256-sha256";
    internal const int MaximumDocumentBytes = 256 * 1024;
    internal const int MaximumDepth = 16;
    internal const int MaximumTextLength = 256;
    internal const int MaximumReasonLength = 1_024;
    internal const int MaximumLocks = 64;
    internal const int MaximumTests = 128;
    internal const int MaximumApprovals = 16;
    internal const int MaximumRegions = 20;
    internal const int MaximumGaps = 32;
    internal const int MaximumSignatureBytes = 16 * 1024;
}

internal sealed record CandidateEvidenceHandoffV2Envelope(
    [property: JsonPropertyName("schemaVersion")] int SchemaVersion,
    [property: JsonPropertyName("mediaType")] string MediaType,
    [property: JsonPropertyName("payload")] CandidateEvidenceHandoffV2Payload Payload,
    [property: JsonPropertyName("signature")] CandidateHandoffV2Signature Signature);

internal sealed record CandidateEvidenceHandoffV2Payload(
    [property: JsonPropertyName("operationId")] string OperationId,
    [property: JsonPropertyName("source")] CandidateHandoffV2Source Source,
    [property: JsonPropertyName("deployCli")] CandidateHandoffV2DeployCli DeployCli,
    [property: JsonPropertyName("dependencyLocks")] IReadOnlyList<CandidateHandoffV2DependencyLock> DependencyLocks,
    [property: JsonPropertyName("artifact")] CandidateHandoffV2Artifact Artifact,
    [property: JsonPropertyName("configurationDigest")] string ConfigurationDigest,
    [property: JsonPropertyName("migrationDigest")] string? MigrationDigest,
    [property: JsonPropertyName("supplyChain")] CandidateHandoffV2SupplyChainEvidence SupplyChain,
    [property: JsonPropertyName("security")] CandidateHandoffV2SecurityEvidence Security,
    [property: JsonPropertyName("tests")] IReadOnlyList<CandidateHandoffV2TestEvidence> Tests,
    [property: JsonPropertyName("approvals")] IReadOnlyList<CandidateHandoffV2ApprovalEvidence> Approvals,
    [property: JsonPropertyName("target")] CandidateHandoffV2Target Target,
    [property: JsonPropertyName("lease")] CandidateHandoffV2LeaseEvidence Lease,
    [property: JsonPropertyName("rollback")] CandidateHandoffV2Rollback Rollback,
    [property: JsonPropertyName("knownGaps")] IReadOnlyList<CandidateHandoffV2KnownGap> KnownGaps,
    [property: JsonPropertyName("requestedBy")] string RequestedBy,
    [property: JsonPropertyName("reason")] string Reason,
    [property: JsonPropertyName("audience")] string Audience,
    [property: JsonPropertyName("issuedAt")] DateTimeOffset IssuedAt,
    [property: JsonPropertyName("expiresAt")] DateTimeOffset ExpiresAt);

internal sealed record CandidateHandoffV2Source(
    [property: JsonPropertyName("repository")] string Repository,
    [property: JsonPropertyName("commit")] string Commit,
    [property: JsonPropertyName("treeDigest")] string TreeDigest,
    [property: JsonPropertyName("cleanWorktree")] CandidateHandoffV2CleanWorktreeEvidence CleanWorktree);

internal sealed record CandidateHandoffV2CleanWorktreeEvidence(
    [property: JsonPropertyName("schemaVersion")] int SchemaVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("statusDigest")] string StatusDigest,
    [property: JsonPropertyName("proofDigest")] string ProofDigest,
    [property: JsonPropertyName("checkedAt")] DateTimeOffset CheckedAt);

internal sealed record CandidateHandoffV2DeployCli(
    [property: JsonPropertyName("package")] string Package,
    [property: JsonPropertyName("version")] string Version,
    [property: JsonPropertyName("packageDigest")] string PackageDigest,
    [property: JsonPropertyName("executableDigest")] string ExecutableDigest);

internal sealed record CandidateHandoffV2DependencyLock(
    [property: JsonPropertyName("path")] string Path,
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("digest")] string Digest);

internal sealed record CandidateHandoffV2Artifact(
    [property: JsonPropertyName("digest")] string Digest,
    [property: JsonPropertyName("manifestDigest")] string ManifestDigest,
    [property: JsonPropertyName("ociConfigDigest")] string OciConfigDigest,
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("architecture")] string Architecture,
    [property: JsonPropertyName("repository")] string Repository,
    [property: JsonPropertyName("reference")] string Reference);

internal sealed record CandidateHandoffV2SupplyChainEvidence(
    [property: JsonPropertyName("receiptDigest")] string ReceiptDigest,
    [property: JsonPropertyName("receiptSchemaVersion")] int ReceiptSchemaVersion,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("artifactDigest")] string ArtifactDigest,
    [property: JsonPropertyName("sbomDigest")] string SbomDigest,
    [property: JsonPropertyName("provenanceDigest")] string ProvenanceDigest,
    [property: JsonPropertyName("policyDigest")] string PolicyDigest,
    [property: JsonPropertyName("scanDigest")] string ScanDigest,
    [property: JsonPropertyName("trustPolicyDigest")] string TrustPolicyDigest,
    [property: JsonPropertyName("signatureDigest")] string SignatureDigest,
    [property: JsonPropertyName("workload")] string Workload,
    [property: JsonPropertyName("audience")] string Audience,
    [property: JsonPropertyName("environment")] string Environment,
    [property: JsonPropertyName("signatureAlgorithm")] string SignatureAlgorithm,
    [property: JsonPropertyName("signaturePolicyVersion")] int SignaturePolicyVersion,
    [property: JsonPropertyName("signatureThreshold")] int SignatureThreshold,
    [property: JsonPropertyName("verifiedSignatures")] int VerifiedSignatures);

internal sealed record CandidateHandoffV2SecurityEvidence(
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("policyDigest")] string PolicyDigest,
    [property: JsonPropertyName("scanDigest")] string ScanDigest,
    [property: JsonPropertyName("scanGeneratedAt")] DateTimeOffset ScanGeneratedAt,
    [property: JsonPropertyName("vulnerabilityCount")] int VulnerabilityCount,
    [property: JsonPropertyName("licenseCount")] int LicenseCount);

internal sealed record CandidateHandoffV2TestEvidence(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("required")] bool Required,
    [property: JsonPropertyName("artifactDigest")] string ArtifactDigest,
    [property: JsonPropertyName("evidenceDigest")] string EvidenceDigest,
    [property: JsonPropertyName("startedAt")] DateTimeOffset StartedAt,
    [property: JsonPropertyName("completedAt")] DateTimeOffset CompletedAt);

/// <summary>Reviewed evidence only. This record never grants rollout authority.</summary>
internal sealed record CandidateHandoffV2ApprovalEvidence(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("scope")] string Scope,
    [property: JsonPropertyName("decision")] string Decision,
    [property: JsonPropertyName("evidenceDigest")] string EvidenceDigest,
    [property: JsonPropertyName("approverIdentityDigest")] string ApproverIdentityDigest,
    [property: JsonPropertyName("decidedAt")] DateTimeOffset DecidedAt,
    [property: JsonPropertyName("expiresAt")] DateTimeOffset ExpiresAt);

internal sealed record CandidateHandoffV2Target(
    [property: JsonPropertyName("service")] string Service,
    [property: JsonPropertyName("environment")] string Environment,
    [property: JsonPropertyName("regions")] IReadOnlyList<string> Regions);

/// <summary>Delivery-workflow lease evidence only. Regional authority still comes from Orchestrator.</summary>
internal sealed record CandidateHandoffV2LeaseEvidence(
    [property: JsonPropertyName("leaseId")] string LeaseId,
    [property: JsonPropertyName("action")] string Action,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("scopeDigest")] string ScopeDigest,
    [property: JsonPropertyName("evidenceDigest")] string EvidenceDigest,
    [property: JsonPropertyName("holderIdentityDigest")] string HolderIdentityDigest,
    [property: JsonPropertyName("acquiredAt")] DateTimeOffset AcquiredAt,
    [property: JsonPropertyName("expiresAt")] DateTimeOffset ExpiresAt);

internal sealed record CandidateHandoffV2Rollback(
    [property: JsonPropertyName("artifactDigest")] string ArtifactDigest,
    [property: JsonPropertyName("manifestDigest")] string ManifestDigest,
    [property: JsonPropertyName("ociConfigDigest")] string OciConfigDigest,
    [property: JsonPropertyName("configurationDigest")] string ConfigurationDigest,
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("architecture")] string Architecture,
    [property: JsonPropertyName("repository")] string Repository,
    [property: JsonPropertyName("reference")] string Reference);

internal sealed record CandidateHandoffV2KnownGap(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("severity")] string Severity,
    [property: JsonPropertyName("blocking")] bool Blocking,
    [property: JsonPropertyName("evidenceDigest")] string EvidenceDigest);

internal sealed record CandidateHandoffV2Signature(
    [property: JsonPropertyName("algorithm")] string Algorithm,
    [property: JsonPropertyName("identity")] string Identity,
    [property: JsonPropertyName("value")] string Value);

internal sealed record CandidateHandoffV2LeaseExpectation(string LeaseId, string EvidenceDigest);

/// <summary>All current observations required by the pure verifier. Callers cannot omit an authority binding.</summary>
internal sealed record CandidateEvidenceHandoffV2AdmissionPolicy(
    DateTimeOffset Now,
    string ExpectedOperationId,
    string ExpectedAudience,
    CandidateHandoffV2DeployCli ExpectedDeployCli,
    CandidateHandoffV2Artifact ExpectedArtifact,
    string ExpectedConfigurationDigest,
    string? ExpectedMigrationDigest,
    CandidateHandoffV2Target ExpectedTarget,
    CandidateHandoffV2LeaseExpectation ExpectedLease,
    CandidateHandoffV2Rollback ExpectedRollback,
    string ExpectedSupplyChainReceiptDigest,
    IReadOnlyDictionary<string, string> ExpectedApprovalDigests,
    IReadOnlySet<string> RequiredTests,
    TimeSpan MaximumEnvelopeAge,
    TimeSpan MaximumCleanWorktreeProofAge,
    TimeSpan MaximumTestAge,
    TimeSpan MaximumSecurityAge);

internal enum CandidateEvidenceHandoffV2Decision
{
    Rejected = 0,
    Verified = 1,
}

internal sealed record CandidateEvidenceHandoffV2Error(string Code, string Message, string Remediation);

/// <summary>
/// Verified evidence mapped to the existing direct-delivery request. Approval and lease fields
/// remain evidence. They do not populate authorityGeneration, writerEpoch, or any rollout permit.
/// </summary>
internal sealed record CandidateEvidenceHandoffV2Admission(
    DeliveryRequest Delivery,
    CandidateHandoffV2Artifact Artifact,
    CandidateHandoffV2Rollback Rollback,
    CandidateHandoffV2SupplyChainEvidence SupplyChain,
    CandidateHandoffV2SecurityEvidence Security,
    IReadOnlyList<CandidateHandoffV2ApprovalEvidence> ApprovalEvidence,
    CandidateHandoffV2LeaseEvidence LeaseEvidence);

internal sealed record CandidateEvidenceHandoffV2Result(
    CandidateEvidenceHandoffV2Decision Decision,
    CandidateEvidenceHandoffV2Admission? Admission,
    CandidateEvidenceHandoffV2Error? Error)
{
    internal static CandidateEvidenceHandoffV2Result Reject(string code, string message, string remediation) =>
        new(CandidateEvidenceHandoffV2Decision.Rejected, null, new(code, message, remediation));
}
