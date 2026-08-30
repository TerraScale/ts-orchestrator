using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using TerraScale.Orchestrator.ControlPlane.Delivery;

namespace TerraScale.Orchestrator.Delivery.DeployHandoffV2;

internal interface ICandidateEvidenceHandoffV2SignatureVerifier
{
    bool Verify(string signingIdentity, ReadOnlyMemory<byte> canonicalMaterial, ReadOnlyMemory<byte> signature);
}

/// <summary>Pure version-2 candidate evidence verification. It performs no I/O and grants no rollout authority.</summary>
internal static partial class CandidateEvidenceHandoffV2Verifier
{
    private static readonly JsonSerializerOptions JsonOptions = CreateOptions();

    internal static CandidateEvidenceHandoffV2Result Verify(
        ReadOnlyMemory<byte> document,
        CandidateEvidenceHandoffV2AdmissionPolicy policy,
        DirectDeliveryArtifactEvidence durableEvidence,
        bool durableEvidenceSignatureVerified,
        ICandidateEvidenceHandoffV2SignatureVerifier signatureVerifier)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(durableEvidence);
        ArgumentNullException.ThrowIfNull(signatureVerifier);
        try
        {
            ValidatePolicy(policy);
            var envelope = Parse(document);
            ValidateEnvelope(envelope, policy, durableEvidence, durableEvidenceSignatureVerified, signatureVerifier);
            var payload = envelope.Payload;
            var request = new DeliveryRequest(
                DeliveryRequest.CurrentSchemaVersion,
                payload.OperationId,
                new DeliverySource(payload.Source.Repository, payload.Source.Commit, payload.Source.TreeDigest),
                new DeliveryArtifact(payload.Artifact.Digest, payload.Artifact.ManifestDigest, payload.Artifact.Kind),
                new DeliveryTarget(payload.Target.Service, payload.Target.Environment, payload.Target.Regions.ToArray()),
                payload.ConfigurationDigest,
                payload.MigrationDigest,
                payload.RequestedBy,
                payload.Reason,
                AuthorityGeneration: 0,
                WriterEpoch: 0,
                Attempt: 0);
            return new(
                CandidateEvidenceHandoffV2Decision.Verified,
                new(
                    request,
                    payload.Artifact,
                    payload.Rollback,
                    payload.SupplyChain,
                    payload.Security,
                    payload.FirstPartyLicense,
                    payload.Approvals.ToArray(),
                    payload.Lease),
                null);
        }
        catch (CandidateHandoffV2Rejection rejection)
        {
            return CandidateEvidenceHandoffV2Result.Reject(rejection.Code, rejection.Message, rejection.Remediation);
        }
        catch (Exception exception) when (exception is not (OutOfMemoryException or StackOverflowException or AccessViolationException))
        {
            return CandidateEvidenceHandoffV2Result.Reject(
                "handoff_v2_document_invalid",
                "The candidate handoff document is malformed or cannot be evaluated.",
                "Regenerate the bounded version-2 handoff from TerraScale.Deploy.");
        }
    }

    internal static ReadOnlyMemory<byte> CanonicalSigningMaterial(
        CandidateEvidenceHandoffV2Payload payload,
        string algorithm,
        string identity)
    {
        var material = new CandidateHandoffV2SigningMaterial(
            CandidateEvidenceHandoffV2Contract.SigningDomain,
            CandidateEvidenceHandoffV2Contract.SchemaVersion,
            CandidateEvidenceHandoffV2Contract.MediaType,
            algorithm,
            identity,
            payload);
        return JsonSerializer.SerializeToUtf8Bytes(material, JsonOptions);
    }

    internal static byte[] SerializeEnvelope(CandidateEvidenceHandoffV2Envelope envelope) =>
        JsonSerializer.SerializeToUtf8Bytes(envelope, JsonOptions);

    internal static bool TryReadArtifactDigest(ReadOnlyMemory<byte> document, [NotNullWhen(true)] out string? digest)
    {
        if (TryReadRoutingIdentity(document, out var identity))
        {
            digest = identity.ArtifactDigest;
            return true;
        }
        digest = null;
        return false;
    }

    internal static bool TryReadRoutingIdentity(
        ReadOnlyMemory<byte> document,
        [NotNullWhen(true)] out CandidateEvidenceHandoffV2RoutingIdentity? identity)
    {
        try
        {
            var payload = Parse(document).Payload;
            var operationId = payload?.OperationId;
            var artifactDigest = payload?.Artifact?.Digest;
            if (!IsIdentity(operationId, 128) || !IsDigest(artifactDigest))
            {
                identity = null;
                return false;
            }
            identity = new(operationId!, artifactDigest!);
            return true;
        }
        catch (Exception exception) when (exception is CandidateHandoffV2Rejection or JsonException or ArgumentException)
        {
            identity = null;
            return false;
        }
    }

    internal static bool IsAdmissionPolicyValid(CandidateEvidenceHandoffV2AdmissionPolicy policy)
    {
        try
        {
            ValidatePolicy(policy);
            return true;
        }
        catch (CandidateHandoffV2Rejection)
        {
            return false;
        }
    }

    internal static string CleanWorktreeProofDigest(
        CandidateHandoffV2Source source,
        string statusDigest,
        DateTimeOffset checkedAt)
    {
        var proof = new CandidateHandoffV2CleanProofMaterial(
            "terrascale.deploy/clean-worktree-proof/v1",
            source.Repository,
            source.Commit,
            source.TreeDigest,
            "clean",
            statusDigest,
            checkedAt);
        return Sha256(JsonSerializer.SerializeToUtf8Bytes(proof, JsonOptions));
    }

    internal static string LeaseScopeDigest(CandidateHandoffV2Target target, string action)
    {
        var scope = new CandidateHandoffV2LeaseScopeMaterial(
            "terrascale.deploy/lease-scope/v1",
            action,
            target.Service,
            target.Environment,
            target.Regions);
        return Sha256(JsonSerializer.SerializeToUtf8Bytes(scope, JsonOptions));
    }

    private static CandidateEvidenceHandoffV2Envelope Parse(ReadOnlyMemory<byte> json)
    {
        if (json.IsEmpty || json.Length > CandidateEvidenceHandoffV2Contract.MaximumDocumentBytes)
            Reject("handoff_v2_document_invalid", "The candidate handoff is empty or exceeds 256 KiB.", "Send the exact bounded signed handoff.");
        using var parsed = JsonDocument.Parse(json, new JsonDocumentOptions
        {
            MaxDepth = CandidateEvidenceHandoffV2Contract.MaximumDepth,
            CommentHandling = JsonCommentHandling.Disallow,
            AllowTrailingCommas = false,
        });
        RejectDuplicateProperties(parsed.RootElement, "$");
        return JsonSerializer.Deserialize<CandidateEvidenceHandoffV2Envelope>(json.Span, JsonOptions)
            ?? throw new JsonException("The handoff was null.");
    }

    private static void ValidateEnvelope(
        CandidateEvidenceHandoffV2Envelope envelope,
        CandidateEvidenceHandoffV2AdmissionPolicy policy,
        DirectDeliveryArtifactEvidence durable,
        bool durableSignatureVerified,
        ICandidateEvidenceHandoffV2SignatureVerifier signatureVerifier)
    {
        if (envelope.SchemaVersion != CandidateEvidenceHandoffV2Contract.SchemaVersion ||
            envelope.MediaType != CandidateEvidenceHandoffV2Contract.MediaType)
            Reject("handoff_v2_schema_unsupported", "The handoff schema or media type is not the isolated version-2 contract.", "Use schemaVersion 2 and the version-2 media type; v1 is frozen.");
        if (envelope.Payload is null || envelope.Signature is null)
            Reject("handoff_v2_evidence_missing", "The signed payload or signature is missing.", "Produce the complete signed handoff.");
        var signature = envelope.Signature;
        if (signature.Algorithm != CandidateEvidenceHandoffV2Contract.SigningAlgorithm || !IsIdentity(signature.Identity, 512) ||
            string.IsNullOrEmpty(signature.Value) || signature.Value.Length > CandidateEvidenceHandoffV2Contract.MaximumSignatureBytes * 2)
            Reject("handoff_v2_signature_invalid", "The handoff signature identity, algorithm, or value is invalid.", "Use the admitted P-256 workload-bound signing identity.");
        if (signature.Identity != policy.ExpectedSigningIdentity)
            Reject("handoff_v2_signer_mismatch", "The handoff signing identity is not admitted for this workload policy.", "Use the exact workload-bound signing identity recorded by Orchestrator admission policy.");
        byte[] signatureBytes;
        try
        {
            signatureBytes = Convert.FromBase64String(signature.Value);
        }
        catch (FormatException)
        {
            Reject("handoff_v2_signature_invalid", "The handoff signature is not canonical base64.", "Regenerate the signed handoff.");
            throw;
        }
        if (signatureBytes.Length is < 1 or > CandidateEvidenceHandoffV2Contract.MaximumSignatureBytes ||
            Convert.ToBase64String(signatureBytes) != signature.Value)
            Reject("handoff_v2_signature_invalid", "The handoff signature is empty, oversized, or non-canonical.", "Regenerate the signed handoff.");
        var payload = envelope.Payload;
        ValidatePayload(payload);
        var material = CanonicalSigningMaterial(payload, signature.Algorithm, signature.Identity);
        if (!signatureVerifier.Verify(signature.Identity, material, signatureBytes))
            Reject("handoff_v2_signature_mismatch", "The handoff signature or signing identity is not trusted for these canonical bytes.", "Use the admitted workload identity and exact audience-bound payload.");
        ValidateFreshness(payload, policy);
        ValidateAdmissionBindings(payload, policy, durable, durableSignatureVerified);
    }

    private static void ValidatePayload(CandidateEvidenceHandoffV2Payload payload)
    {
        RequireIdentity(payload.OperationId, 128, "operationId");
        SecretFree(payload.OperationId, "operationId");
        var source = payload.Source;
        if (source is null || !IsText(source.Repository, CandidateEvidenceHandoffV2Contract.MaximumTextLength) ||
            !source.Repository.Contains('/', StringComparison.Ordinal) || !IsCommit(source.Commit) || !IsDigest(source.TreeDigest) ||
            source.CleanWorktree is null)
            Reject("handoff_v2_source_invalid", "The source or clean-worktree evidence is incomplete.", "Bind the exact repository, commit, tree, and clean-worktree proof.");
        SecretFree(source.Repository, "source.repository");
        ValidateCleanWorktree(source, payload.IssuedAt);

        var cli = payload.DeployCli;
        if (cli is null || cli.Package != "TerraScale.Deploy.Cli" || !VersionPattern().IsMatch(cli.Version ?? string.Empty) ||
            !IsDigest(cli.PackageDigest) || !IsDigest(cli.ExecutableDigest))
            Reject("handoff_v2_cli_invalid", "The exact Deploy CLI identity is incomplete.", "Bind the pinned CLI version, package digest, and executable digest.");
        ValidateLocks(payload.DependencyLocks);
        ValidateArtifact(payload.Artifact, "artifact");
        if (!IsDigest(payload.ConfigurationDigest) || payload.MigrationDigest is not null && !IsDigest(payload.MigrationDigest))
            Reject("handoff_v2_configuration_invalid", "The configuration or migration digest is malformed.", "Use exact lowercase sha256 identities.");
        ValidateTarget(payload.Target);
        ValidateSupplyChain(payload);
        ValidateTests(payload.Tests, payload.Artifact.Digest, payload.IssuedAt);
        ValidateApprovals(payload.Approvals, payload.IssuedAt);
        ValidateLease(payload.Lease, payload.Target, payload.IssuedAt);
        ValidateRollback(payload.Rollback, payload.Artifact);
        ValidateGaps(payload.KnownGaps);
        RequireIdentity(payload.RequestedBy, CandidateEvidenceHandoffV2Contract.MaximumTextLength, "requestedBy");
        if (!IsText(payload.Reason, CandidateEvidenceHandoffV2Contract.MaximumReasonLength))
            Reject("handoff_v2_field_invalid", "The handoff reason is empty, oversized, or contains control characters.", "Use a bounded redacted reason.");
        RequireIdentity(payload.Audience, CandidateEvidenceHandoffV2Contract.MaximumTextLength, "audience");
        SecretFree(payload.RequestedBy, "requestedBy");
        SecretFree(payload.Reason, "reason");
        SecretFree(payload.Audience, "audience");
        if (!Utc(payload.IssuedAt) || !Utc(payload.ExpiresAt) || payload.ExpiresAt <= payload.IssuedAt ||
            payload.ExpiresAt - payload.IssuedAt > TimeSpan.FromMinutes(30))
            Reject("handoff_v2_time_invalid", "The handoff timestamps are invalid or exceed 30 minutes.", "Use UTC timestamps with a short positive lifetime.");
    }

    private static void ValidateCleanWorktree(
        CandidateHandoffV2Source source,
        DateTimeOffset issuedAt)
    {
        var proof = source.CleanWorktree;
        if (proof.SchemaVersion != 1 || proof.Status != "clean" || proof.StatusDigest != Sha256(ReadOnlySpan<byte>.Empty) ||
            !IsDigest(proof.ProofDigest) || !Utc(proof.CheckedAt) || proof.CheckedAt > issuedAt ||
            proof.ProofDigest != CleanWorktreeProofDigest(source, proof.StatusDigest, proof.CheckedAt))
            Reject("handoff_v2_clean_worktree_invalid", "The clean-worktree proof is malformed or does not bind the source.", "Regenerate it from the exact clean checkout.");
    }

    private static void ValidateLocks(IReadOnlyList<CandidateHandoffV2DependencyLock>? locks)
    {
        if (locks is null || locks.Count is < 1 or > CandidateEvidenceHandoffV2Contract.MaximumLocks)
            Reject("handoff_v2_locks_missing", "Dependency-lock evidence is missing or oversized.", "Bind every dependency lock file.");
        var paths = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in locks)
        {
            if (item is null || !IsRelativePath(item.Path) || item.Kind is not ("nuget" or "cargo" or "npm" or "pnpm" or "yarn" or "bun") ||
                !IsDigest(item.Digest) || !paths.Add(item.Path))
                Reject("handoff_v2_locks_invalid", "A dependency-lock entry is malformed, duplicated, or unknown.", "Use distinct relative paths, known lock kinds, and exact digests.");
            SecretFree(item.Path, "dependencyLocks.path");
        }
    }

    private static void ValidateArtifact(CandidateHandoffV2Artifact? artifact, string field)
    {
        if (artifact is null || !IsDigest(artifact.Digest) || !IsDigest(artifact.ManifestDigest) ||
            !IsDigest(artifact.OciConfigDigest) || artifact.Kind is not ("service" or "package" or "site") ||
            artifact.Architecture is not ("linux/amd64" or "linux/arm64" or "multi") ||
            !IsOciRepository(artifact.Repository) || artifact.Reference != artifact.Repository + "@" + artifact.Digest)
            Reject("handoff_v2_artifact_invalid", $"The {field} identity is incomplete, mutable, or unsupported.", "Use an OCI repository and exact artifact, manifest, and config digests; tags are forbidden.");
        SecretFree(artifact.Repository, field + ".repository");
    }

    private static void ValidateTarget(CandidateHandoffV2Target? target)
    {
        if (target is null || !IsIdentity(target.Service, CandidateEvidenceHandoffV2Contract.MaximumTextLength) ||
            target.Environment is not ("local" or "development" or "production") || target.Regions is null ||
            target.Regions.Count is < 1 or > CandidateEvidenceHandoffV2Contract.MaximumRegions ||
            target.Regions.Any(region => !RegionPattern().IsMatch(region ?? string.Empty)) ||
            target.Regions.Distinct(StringComparer.Ordinal).Count() != target.Regions.Count)
            Reject("handoff_v2_target_invalid", "The target scope is missing, duplicated, or unsupported.", "Use the exact service, environment, and ordered canonical RegionCode list.");
        SecretFree(target.Service, "target.service");
    }

    private static void ValidateSupplyChain(CandidateEvidenceHandoffV2Payload payload)
    {
        var supply = payload.SupplyChain;
        var security = payload.Security;
        if (supply is null || supply.ReceiptSchemaVersion != 2 || supply.Status != "passed" || !IsDigest(supply.ReceiptDigest) ||
            !IsDigest(supply.ArtifactDigest) || !IsDigest(supply.SbomDigest) || !IsDigest(supply.ProvenanceDigest) ||
            !IsDigest(supply.PolicyDigest) || !IsDigest(supply.ScanDigest) || !IsDigest(supply.TrustPolicyDigest) ||
            !IsDigest(supply.SignatureDigest) || supply.ArtifactDigest != payload.Artifact.Digest ||
            supply.Workload != payload.Target.Service || supply.Audience != payload.Audience ||
            supply.Environment != payload.Target.Environment || supply.SignatureAlgorithm != CandidateEvidenceHandoffV2Contract.SigningAlgorithm ||
            supply.SignaturePolicyVersion <= 0 || supply.SignatureThreshold <= 0 || supply.VerifiedSignatures < supply.SignatureThreshold)
            Reject("handoff_v2_supply_chain_invalid", "The SupplyChainReceipt evidence is incomplete, failed, or bound to another candidate scope.", "Use the exact passed receipt for this artifact and audience.");
        if (security is null || security.Status != "passed" || security.PolicyDigest != supply.PolicyDigest ||
            security.ScanDigest != supply.ScanDigest || !Utc(security.ScanGeneratedAt) ||
            security.ScanGeneratedAt > payload.IssuedAt || security.VulnerabilityCount < 0 || security.LicenseCount < 0)
            Reject("handoff_v2_security_invalid", "Security results are failed, malformed, or mismatched with the SupplyChainReceipt.", "Use the passed policy and scan results from the exact receipt.");
        ValidateFirstPartyLicense(payload.FirstPartyLicense, payload.Source, payload.IssuedAt);
        ValidateFirstPartyLicenseIsDistinct(payload.FirstPartyLicense, supply);
    }

    private static void ValidateFirstPartyLicense(
        CandidateHandoffV2FirstPartyLicenseEvidence? evidence,
        CandidateHandoffV2Source source,
        DateTimeOffset issuedAt)
    {
        if (evidence is null || evidence.SchemaVersion != 1 || evidence.Status != "resolved" ||
            evidence.Scope != "all-first-party-components" || evidence.Repository != source.Repository ||
            evidence.SourceTreeDigest != source.TreeDigest || !IsDigest(evidence.ComponentInventoryDigest) ||
            evidence.PrivateComponentCoverage != "complete" || !IsDigest(evidence.DispositionDigest) ||
            !IsDigest(evidence.EvidenceDigest) || !Utc(evidence.DecidedAt) ||
            evidence.DecidedAt == default || evidence.DecidedAt > issuedAt)
            Reject(
                "handoff_v2_first_party_license_invalid",
                "First-party license evidence is missing, unresolved, incomplete, stale, or bound to another source tree.",
                "Use the exact resolved owner evidence covering every first-party component, including private components.");
    }

    private static void ValidateFirstPartyLicenseIsDistinct(
        CandidateHandoffV2FirstPartyLicenseEvidence evidence,
        CandidateHandoffV2SupplyChainEvidence supply)
    {
        if (evidence.EvidenceDigest == supply.SbomDigest ||
            evidence.EvidenceDigest == supply.ProvenanceDigest ||
            evidence.EvidenceDigest == supply.PolicyDigest ||
            evidence.EvidenceDigest == supply.ScanDigest ||
            evidence.EvidenceDigest == supply.TrustPolicyDigest ||
            evidence.EvidenceDigest == supply.SignatureDigest)
            Reject(
                "handoff_v2_first_party_license_not_distinct",
                "Generic SBOM, scanner, policy, provenance, or signature evidence was substituted for the first-party disposition proof.",
                "Bind a separate owner-recorded first-party disposition proof and its exact digest.");
    }

    private static void ValidateTests(
        IReadOnlyList<CandidateHandoffV2TestEvidence>? tests,
        string artifactDigest,
        DateTimeOffset issuedAt)
    {
        if (tests is null || tests.Count is < 1 or > CandidateEvidenceHandoffV2Contract.MaximumTests)
            Reject("handoff_v2_tests_missing", "Candidate-bound test evidence is missing or oversized.", "Include every required test result.");
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var test in tests)
        {
            if (test is null || !IsIdentity(test.Name, CandidateEvidenceHandoffV2Contract.MaximumTextLength) ||
                test.Status is not ("passed" or "failed" or "skipped") || !names.Add(test.Name) ||
                test.ArtifactDigest != artifactDigest || !IsDigest(test.EvidenceDigest) || !Utc(test.StartedAt) ||
                !Utc(test.CompletedAt) || test.CompletedAt < test.StartedAt || test.CompletedAt > issuedAt)
                Reject("handoff_v2_test_invalid", "Test evidence is malformed, duplicated, or bound to another artifact.", "Use exact bounded candidate results.");
            if (test.Required && test.Status != "passed")
                Reject("handoff_v2_required_test_not_passed", "A required candidate test failed or was skipped.", "Pass every required test on the exact candidate.");
            SecretFree(test.Name, "tests.name");
        }
    }

    private static void ValidateApprovals(
        IReadOnlyList<CandidateHandoffV2ApprovalEvidence>? approvals,
        DateTimeOffset issuedAt)
    {
        if (approvals is null || approvals.Count is < 1 or > CandidateEvidenceHandoffV2Contract.MaximumApprovals)
            Reject("handoff_v2_approvals_missing", "Approval evidence digests are missing or oversized.", "Include reviewed redacted approval evidence only.");
        var ids = new HashSet<string>(StringComparer.Ordinal);
        var digests = new HashSet<string>(StringComparer.Ordinal);
        foreach (var approval in approvals)
        {
            if (approval is null || !IsIdentity(approval.Id, 128) || !IsIdentity(approval.Scope, 128) || approval.Decision != "approved" ||
                !IsDigest(approval.EvidenceDigest) || !IsDigest(approval.ApproverIdentityDigest) ||
                !ids.Add(approval.Id) || !digests.Add(approval.EvidenceDigest) || !Utc(approval.DecidedAt) ||
                !Utc(approval.ExpiresAt) || approval.DecidedAt > issuedAt || approval.ExpiresAt < issuedAt)
                Reject("handoff_v2_approval_invalid", "Approval evidence is malformed, duplicated, or not approved.", "Use distinct current evidence digests for the exact candidate.");
            SecretFree(approval.Id, "approvals.id");
            SecretFree(approval.Scope, "approvals.scope");
        }
    }

    private static void ValidateLease(
        CandidateHandoffV2LeaseEvidence? lease,
        CandidateHandoffV2Target target,
        DateTimeOffset issuedAt)
    {
        if (lease is null || !IsIdentity(lease.LeaseId, 128) || lease.Action != "candidate-handoff" || lease.Status != "active" ||
            !IsDigest(lease.ScopeDigest) || !IsDigest(lease.EvidenceDigest) || !IsDigest(lease.HolderIdentityDigest) ||
            !Utc(lease.AcquiredAt) || !Utc(lease.ExpiresAt) || lease.AcquiredAt > issuedAt ||
            lease.ExpiresAt < issuedAt || lease.ScopeDigest != LeaseScopeDigest(target, lease.Action))
            Reject("handoff_v2_lease_invalid", "The target-scoped handoff lease is malformed or mismatched.", "Bind the exact active candidate-handoff lease evidence.");
        SecretFree(lease.LeaseId, "lease.leaseId");
    }

    private static void ValidateRollback(CandidateHandoffV2Rollback? rollback, CandidateHandoffV2Artifact artifact)
    {
        if (rollback is null)
            Reject("handoff_v2_rollback_missing", "The exact retained rollback identity is missing.", "Bind the qualified prior artifact and configuration.");
        ValidateArtifact(new(
            rollback.ArtifactDigest,
            rollback.ManifestDigest,
            rollback.OciConfigDigest,
            rollback.Kind,
            rollback.Architecture,
            rollback.Repository,
            rollback.Reference), "rollback");
        if (!IsDigest(rollback.ConfigurationDigest) || rollback.ArtifactDigest == artifact.Digest ||
            rollback.Kind != artifact.Kind || rollback.Architecture != artifact.Architecture || rollback.Repository != artifact.Repository)
            Reject("handoff_v2_rollback_invalid", "The rollback identity is not a distinct compatible retained artifact.", "Use the exact qualified prior bytes and configuration.");
    }

    private static void ValidateGaps(IReadOnlyList<CandidateHandoffV2KnownGap>? gaps)
    {
        if (gaps is null || gaps.Count > CandidateEvidenceHandoffV2Contract.MaximumGaps)
            Reject("handoff_v2_gaps_invalid", "The known-gaps register is missing or oversized.", "Provide an explicit bounded array.");
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var gap in gaps)
        {
            if (gap is null || !IsIdentity(gap.Id, 128) || gap.Severity is not ("low" or "medium" or "high" or "critical") ||
                !IsDigest(gap.EvidenceDigest) || !ids.Add(gap.Id))
                Reject("handoff_v2_gaps_invalid", "A known gap is malformed, duplicated, or has an unknown severity.", "Use stable gap IDs, known severities, and exact evidence digests.");
            if (gap.Blocking)
                Reject("handoff_v2_blocking_gap", "The candidate declares a blocking known gap.", "Resolve it and produce new candidate evidence.");
            SecretFree(gap.Id, "knownGaps.id");
        }
    }

    private static void ValidateFreshness(
        CandidateEvidenceHandoffV2Payload payload,
        CandidateEvidenceHandoffV2AdmissionPolicy policy)
    {
        var now = policy.Now;
        if (payload.IssuedAt > now || payload.ExpiresAt < now || now - payload.IssuedAt > policy.MaximumEnvelopeAge)
            Reject("handoff_v2_stale", "The handoff is not yet valid, expired, or older than admission policy allows.", "Produce current evidence for the same candidate.");
        if (payload.Source.CleanWorktree.CheckedAt > now || now - payload.Source.CleanWorktree.CheckedAt > policy.MaximumCleanWorktreeProofAge)
            Reject("handoff_v2_clean_worktree_stale", "The clean-worktree proof is stale.", "Reinspect the unchanged exact checkout and resign.");
        if (payload.Security.ScanGeneratedAt > now || now - payload.Security.ScanGeneratedAt > policy.MaximumSecurityAge)
            Reject("handoff_v2_security_stale", "The security result is stale.", "Rerun security verification on the exact candidate.");
        if (payload.FirstPartyLicense.DecidedAt > now ||
            now - payload.FirstPartyLicense.DecidedAt > policy.MaximumFirstPartyLicenseAge)
            Reject("handoff_v2_first_party_license_stale", "The first-party license disposition is stale or from the future.", "Obtain a current resolved disposition for the unchanged source tree.");
        foreach (var test in payload.Tests)
            if (test.CompletedAt > now || now - test.CompletedAt > policy.MaximumTestAge)
                Reject("handoff_v2_test_stale", "A candidate test result is stale.", "Rerun the required test on the exact candidate.");
        foreach (var approval in payload.Approvals)
            if (approval.DecidedAt > now || approval.ExpiresAt < now)
                Reject("handoff_v2_approval_stale", "Approval evidence is not current.", "Obtain current reviewed evidence for this exact candidate.");
        if (payload.Lease.AcquiredAt > now || payload.Lease.ExpiresAt < now)
            Reject("handoff_v2_lease_stale", "The handoff lease is not currently active.", "Acquire a current target-scoped candidate-handoff lease.");
    }

    private static void ValidateAdmissionBindings(
        CandidateEvidenceHandoffV2Payload payload,
        CandidateEvidenceHandoffV2AdmissionPolicy policy,
        DirectDeliveryArtifactEvidence durable,
        bool durableSignatureVerified)
    {
        if (!durableSignatureVerified || durable.Repository != payload.Source.Repository || durable.Commit != payload.Source.Commit ||
            durable.TreeDigest != payload.Source.TreeDigest || durable.ArtifactDigest != payload.Artifact.Digest ||
            durable.ManifestDigest != payload.Artifact.ManifestDigest || durable.Kind != payload.Artifact.Kind)
            Reject("handoff_v2_durable_evidence_mismatch", "Orchestrator's durable signed artifact/source evidence does not match the handoff.", "Record and verify the exact CI artifact evidence before candidate admission.");
        if (payload.OperationId != policy.ExpectedOperationId)
            Reject("handoff_v2_operation_mismatch", "The handoff operation identity does not match admitted intent.", "Use the exact durable operation identity assigned to this candidate.");
        if (payload.Audience != policy.ExpectedAudience)
            Reject("handoff_v2_audience_mismatch", "The handoff audience does not match Orchestrator admission.", "Sign the exact candidate for the admitted Orchestrator audience.");
        if (payload.DeployCli != policy.ExpectedDeployCli)
            Reject("handoff_v2_cli_mismatch", "The Deploy CLI identity does not match the pinned admission identity.", "Use the exact pinned CLI package and executable.");
        if (!SameDependencyLocks(payload.DependencyLocks, policy.ExpectedDependencyLocks))
            Reject("handoff_v2_dependency_locks_mismatch", "Dependency-lock evidence does not match the exact admitted lock set.", "Use every expected lock path, kind, and digest with no additions or substitutions.");
        if (payload.Artifact != policy.ExpectedArtifact)
            Reject("handoff_v2_artifact_mismatch", "The artifact or OCI/config identity does not match admission observations.", "Use the exact immutable registry observation.");
        if (payload.ConfigurationDigest != policy.ExpectedConfigurationDigest || payload.MigrationDigest != policy.ExpectedMigrationDigest)
            Reject("handoff_v2_configuration_mismatch", "Configuration or migration evidence does not match admitted intent.", "Regenerate evidence for the exact configuration and migration.");
        if (!SameTarget(payload.Target, policy.ExpectedTarget))
            Reject("handoff_v2_target_mismatch", "The target scope does not match admitted intent.", "Use the exact service, environment, and ordered Region set.");
        if (payload.Lease.LeaseId != policy.ExpectedLease.LeaseId || payload.Lease.EvidenceDigest != policy.ExpectedLease.EvidenceDigest)
            Reject("handoff_v2_lease_mismatch", "The handoff lease identity or evidence digest does not match admission.", "Use the current exact lease record.");
        if (payload.Rollback != policy.ExpectedRollback)
            Reject("handoff_v2_rollback_mismatch", "The rollback identity does not match the retained qualified observation.", "Bind the exact current rollback bytes and configuration.");
        if (payload.SupplyChain.ReceiptDigest != policy.ExpectedSupplyChainReceiptDigest)
            Reject("handoff_v2_supply_chain_mismatch", "The SupplyChainReceipt digest does not match admission evidence.", "Use the exact passed receipt bytes recorded for this candidate.");
        if (!SameFirstPartyLicense(payload.FirstPartyLicense, policy.ExpectedFirstPartyLicense))
            Reject("handoff_v2_first_party_license_mismatch", "First-party license evidence does not match the admitted disposition digests and coverage.", "Use the exact separately authorized first-party license evidence.");
        if (payload.Approvals.Count != policy.ExpectedApprovalDigests.Count ||
            payload.Approvals.Any(approval => !policy.ExpectedApprovalDigests.TryGetValue(approval.Id, out var digest) || digest != approval.EvidenceDigest))
            Reject("handoff_v2_approval_mismatch", "Approval evidence digests do not match the reviewed admission set.", "Use every exact reviewed approval digest and no substitute.");
        var required = payload.Tests.Where(static test => test.Required).Select(static test => test.Name).ToHashSet(StringComparer.Ordinal);
        if (!required.SetEquals(policy.RequiredTests))
            Reject("handoff_v2_required_tests_mismatch", "Required test identities do not match admission policy.", "Run and bind the exact required test set.");
    }

    private static void ValidatePolicy(CandidateEvidenceHandoffV2AdmissionPolicy policy)
    {
        if (!Utc(policy.Now) || !IsIdentity(policy.ExpectedOperationId, 128) ||
            !IsIdentity(policy.ExpectedAudience, CandidateEvidenceHandoffV2Contract.MaximumTextLength) ||
            !IsIdentity(policy.ExpectedSigningIdentity, 512) || !ValidExpectedDeployCli(policy.ExpectedDeployCli) ||
            !ValidExpectedDependencyLocks(policy.ExpectedDependencyLocks) ||
            !ValidExpectedArtifact(policy.ExpectedArtifact) || !ValidExpectedTarget(policy.ExpectedTarget) ||
            !ValidExpectedLease(policy.ExpectedLease) ||
            !ValidExpectedRollback(policy.ExpectedRollback, policy.ExpectedArtifact) ||
            !IsDigest(policy.ExpectedConfigurationDigest) ||
            policy.ExpectedMigrationDigest is not null && !IsDigest(policy.ExpectedMigrationDigest) ||
            !IsDigest(policy.ExpectedSupplyChainReceiptDigest) ||
            !ValidExpectedFirstPartyLicense(policy.ExpectedFirstPartyLicense) ||
            !ValidExpectedApprovalDigests(policy.ExpectedApprovalDigests) ||
            !ValidRequiredTests(policy.RequiredTests) ||
            !Positive(policy.MaximumEnvelopeAge) || !Positive(policy.MaximumCleanWorktreeProofAge) ||
            !Positive(policy.MaximumTestAge) || !Positive(policy.MaximumSecurityAge) ||
            !Positive(policy.MaximumFirstPartyLicenseAge))
            Reject("handoff_v2_policy_invalid", "The Orchestrator admission policy is incomplete or invalid.", "Supply every exact current admission observation and positive freshness limit.");
    }

    private static void RejectDuplicateProperties(JsonElement value, string path)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in value.EnumerateObject())
            {
                if (!names.Add(property.Name))
                    Reject("handoff_v2_document_invalid", $"The handoff repeats property '{Bounded(path + "." + property.Name)}'.", "Remove duplicate properties; last-value-wins parsing is forbidden.");
                RejectDuplicateProperties(property.Value, path + "." + property.Name);
            }
        }
        else if (value.ValueKind == JsonValueKind.Array)
        {
            var index = 0;
            foreach (var item in value.EnumerateArray())
                RejectDuplicateProperties(item, $"{path}[{index++}]");
        }
    }

    private static bool SameTarget(CandidateHandoffV2Target actual, CandidateHandoffV2Target expected) =>
        actual.Service == expected.Service && actual.Environment == expected.Environment &&
        actual.Regions.SequenceEqual(expected.Regions, StringComparer.Ordinal);

    private static bool SameFirstPartyLicense(
        CandidateHandoffV2FirstPartyLicenseEvidence actual,
        CandidateHandoffV2FirstPartyLicenseExpectation expected) =>
        actual.SchemaVersion == expected.SchemaVersion && actual.Status == expected.Status &&
        actual.Scope == expected.Scope && actual.ComponentInventoryDigest == expected.ComponentInventoryDigest &&
        actual.PrivateComponentCoverage == expected.PrivateComponentCoverage &&
        actual.DispositionDigest == expected.DispositionDigest && actual.EvidenceDigest == expected.EvidenceDigest;

    private static bool SameDependencyLocks(
        IReadOnlyList<CandidateHandoffV2DependencyLock> actual,
        IReadOnlyList<CandidateHandoffV2DependencyLock> expected)
    {
        if (actual.Count != expected.Count)
            return false;
        var admitted = expected.ToDictionary(static value => value.Path, StringComparer.Ordinal);
        return actual.All(value => admitted.TryGetValue(value.Path, out var item) && item == value);
    }

    private static bool ValidExpectedDependencyLocks(IReadOnlyList<CandidateHandoffV2DependencyLock>? locks)
    {
        if (locks is null || locks.Count is < 1 or > CandidateEvidenceHandoffV2Contract.MaximumLocks)
            return false;
        var paths = new HashSet<string>(StringComparer.Ordinal);
        return locks.All(item => item is not null && IsRelativePath(item.Path) &&
            item.Kind is "nuget" or "cargo" or "npm" or "pnpm" or "yarn" or "bun" &&
            IsDigest(item.Digest) && paths.Add(item.Path));
    }

    private static bool ValidExpectedDeployCli(CandidateHandoffV2DeployCli? cli) =>
        cli is not null && cli.Package == "TerraScale.Deploy.Cli" &&
        VersionPattern().IsMatch(cli.Version ?? string.Empty) &&
        IsDigest(cli.PackageDigest) && IsDigest(cli.ExecutableDigest);

    private static bool ValidExpectedArtifact(CandidateHandoffV2Artifact? artifact) =>
        artifact is not null && IsDigest(artifact.Digest) && IsDigest(artifact.ManifestDigest) &&
        IsDigest(artifact.OciConfigDigest) && artifact.Kind is "service" or "package" or "site" &&
        artifact.Architecture is "linux/amd64" or "linux/arm64" or "multi" &&
        IsOciRepository(artifact.Repository) && artifact.Reference == artifact.Repository + "@" + artifact.Digest;

    private static bool ValidExpectedTarget(CandidateHandoffV2Target? target) =>
        target is not null && IsIdentity(target.Service, CandidateEvidenceHandoffV2Contract.MaximumTextLength) &&
        target.Environment is "local" or "development" or "production" && target.Regions is not null &&
        target.Regions.Count is >= 1 and <= CandidateEvidenceHandoffV2Contract.MaximumRegions &&
        target.Regions.All(region => RegionPattern().IsMatch(region ?? string.Empty)) &&
        target.Regions.Distinct(StringComparer.Ordinal).Count() == target.Regions.Count;

    private static bool ValidExpectedLease(CandidateHandoffV2LeaseExpectation? lease) =>
        lease is not null && IsIdentity(lease.LeaseId, 128) && IsDigest(lease.EvidenceDigest);

    private static bool ValidExpectedFirstPartyLicense(CandidateHandoffV2FirstPartyLicenseExpectation? evidence) =>
        evidence is not null && evidence.SchemaVersion == 1 && evidence.Status == "resolved" &&
        evidence.Scope == "all-first-party-components" && IsDigest(evidence.ComponentInventoryDigest) &&
        evidence.PrivateComponentCoverage == "complete" && IsDigest(evidence.DispositionDigest) &&
        IsDigest(evidence.EvidenceDigest);

    private static bool ValidExpectedRollback(
        CandidateHandoffV2Rollback? rollback,
        CandidateHandoffV2Artifact? artifact) =>
        rollback is not null && artifact is not null &&
        ValidExpectedArtifact(new(
            rollback.ArtifactDigest,
            rollback.ManifestDigest,
            rollback.OciConfigDigest,
            rollback.Kind,
            rollback.Architecture,
            rollback.Repository,
            rollback.Reference)) &&
        IsDigest(rollback.ConfigurationDigest) && rollback.ArtifactDigest != artifact.Digest &&
        rollback.Kind == artifact.Kind && rollback.Architecture == artifact.Architecture &&
        rollback.Repository == artifact.Repository;

    private static bool ValidExpectedApprovalDigests(IReadOnlyDictionary<string, string>? approvals) =>
        approvals is not null &&
        approvals.Count is >= 1 and <= CandidateEvidenceHandoffV2Contract.MaximumApprovals &&
        approvals.All(static item => IsIdentity(item.Key, 128) && IsDigest(item.Value));

    private static bool ValidRequiredTests(IReadOnlySet<string>? tests) =>
        tests is not null && tests.Count is >= 1 and <= CandidateEvidenceHandoffV2Contract.MaximumTests &&
        tests.All(test => IsIdentity(test, CandidateEvidenceHandoffV2Contract.MaximumTextLength));

    private static string Sha256(ReadOnlySpan<byte> value) => "sha256:" + Convert.ToHexStringLower(SHA256.HashData(value));

    private static bool IsDigest(string? value) => DigestPattern().IsMatch(value ?? string.Empty);
    private static bool IsCommit(string? value) => CommitPattern().IsMatch(value ?? string.Empty);
    private static bool Utc(DateTimeOffset value) => value.Offset == TimeSpan.Zero;
    private static bool Positive(TimeSpan value) => value > TimeSpan.Zero && value <= TimeSpan.FromDays(30);
    private static string Bounded(string value) => value.Length <= 160 ? value : value[..160];

    private static bool IsText(string? value, int maximum) =>
        value is { Length: > 0 } && value.Length <= maximum && !value.Any(char.IsControl);

    private static bool IsIdentity(string? value, int maximum) =>
        IsText(value, maximum) && value!.All(character => !char.IsWhiteSpace(character));

    private static bool IsRelativePath(string? value)
    {
        if (!IsText(value, CandidateEvidenceHandoffV2Contract.MaximumTextLength) || value is not { } path)
            return false;
        return !Path.IsPathRooted(path) && path != "." &&
            !path.Contains('\\') && !path.Contains(':') &&
            !path.Split('/', StringSplitOptions.None).Any(part => part is "" or "." or "..");
    }

    private static bool IsOciRepository(string? value)
    {
        if (!IsIdentity(value, CandidateEvidenceHandoffV2Contract.MaximumTextLength) || value!.Contains('@') ||
            value.Contains('?') || value.Contains('#') || !value.Contains('/'))
            return false;
        return value.LastIndexOf(':') <= value.LastIndexOf('/');
    }

    private static void RequireIdentity(string? value, int maximum, string field)
    {
        if (!IsIdentity(value, maximum))
            Reject("handoff_v2_field_invalid", $"Field '{field}' is empty, oversized, or contains whitespace/control characters.", "Use the bounded contract identity.");
    }

    private static void SecretFree(string? value, string field)
    {
        if (value is not null && SecretPattern().IsMatch(value))
            Reject("handoff_v2_unredacted", $"Field '{field}' appears to contain secret or credential material.", "Redact the evidence before handoff.");
    }

    [DoesNotReturn]
    private static void Reject(string code, string message, string remediation) =>
        throw new CandidateHandoffV2Rejection(code, message, remediation);

    private static JsonSerializerOptions CreateOptions() => new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false,
        PropertyNameCaseInsensitive = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        MaxDepth = CandidateEvidenceHandoffV2Contract.MaximumDepth,
    };

    private sealed record CandidateHandoffV2SigningMaterial(
        [property: JsonPropertyName("domain")] string Domain,
        [property: JsonPropertyName("schemaVersion")] int SchemaVersion,
        [property: JsonPropertyName("mediaType")] string MediaType,
        [property: JsonPropertyName("algorithm")] string Algorithm,
        [property: JsonPropertyName("identity")] string Identity,
        [property: JsonPropertyName("payload")] CandidateEvidenceHandoffV2Payload Payload);

    private sealed record CandidateHandoffV2CleanProofMaterial(
        [property: JsonPropertyName("domain")] string Domain,
        [property: JsonPropertyName("repository")] string Repository,
        [property: JsonPropertyName("commit")] string Commit,
        [property: JsonPropertyName("treeDigest")] string TreeDigest,
        [property: JsonPropertyName("status")] string Status,
        [property: JsonPropertyName("statusDigest")] string StatusDigest,
        [property: JsonPropertyName("checkedAt")] DateTimeOffset CheckedAt);

    private sealed record CandidateHandoffV2LeaseScopeMaterial(
        [property: JsonPropertyName("domain")] string Domain,
        [property: JsonPropertyName("action")] string Action,
        [property: JsonPropertyName("service")] string Service,
        [property: JsonPropertyName("environment")] string Environment,
        [property: JsonPropertyName("regions")] IReadOnlyList<string> Regions);

    [GeneratedRegex("^sha256:[0-9a-f]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex DigestPattern();

    [GeneratedRegex("^[0-9a-f]{40}$", RegexOptions.CultureInvariant)]
    private static partial Regex CommitPattern();

    [GeneratedRegex("^[A-Z]{3}$", RegexOptions.CultureInvariant)]
    private static partial Regex RegionPattern();

    [GeneratedRegex("^[0-9]+\\.[0-9]+\\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$", RegexOptions.CultureInvariant)]
    private static partial Regex VersionPattern();

    [GeneratedRegex("(?i)(bearer\\s+|(?:token|password|secret|private[_ -]?key|authorization|cookie)\\s*[:=]|-----BEGIN|://[^/\\s:@]+:[^@\\s/]+@|\\?[^#\\s]*(?:token|secret|key)=)", RegexOptions.CultureInvariant)]
    private static partial Regex SecretPattern();

    private sealed class CandidateHandoffV2Rejection(string code, string message, string remediation) : Exception(message)
    {
        internal string Code { get; } = code;
        internal string Remediation { get; } = remediation;
    }
}
