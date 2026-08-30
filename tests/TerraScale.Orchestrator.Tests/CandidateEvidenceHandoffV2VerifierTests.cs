using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Delivery.DeployHandoffV2;

namespace TerraScale.Orchestrator.Tests;

public sealed class CandidateEvidenceHandoffV2VerifierTests
{
    [Test]
    public async Task ValidExactEvidenceMapsOnlyAfterPureVerificationAndCarriesNoRolloutAuthority()
    {
        var envelope = Envelope();
        var result = Verify(envelope);

        await Assert.That(result.Decision).IsEqualTo(CandidateEvidenceHandoffV2Decision.Verified);
        await Assert.That(result.Error).IsNull();
        await Assert.That(result.Admission).IsNotNull();
        await Assert.That(result.Admission!.Delivery.OperationId).IsEqualTo("candidate-op-1");
        await Assert.That(result.Admission.Delivery.AuthorityGeneration).IsEqualTo(0L);
        await Assert.That(result.Admission.Delivery.WriterEpoch).IsEqualTo(0L);
        await Assert.That(result.Admission.Delivery.Attempt).IsEqualTo(0);
        await Assert.That(result.Admission.ApprovalEvidence[0].EvidenceDigest)
            .IsEqualTo(envelope.Payload.Approvals[0].EvidenceDigest);
        await Assert.That(result.Admission.LeaseEvidence.EvidenceDigest)
            .IsEqualTo(envelope.Payload.Lease.EvidenceDigest);
        await Assert.That(result.Admission.FirstPartyLicense)
            .IsEqualTo(envelope.Payload.FirstPartyLicense);
    }

    [Test]
    public async Task CanonicalSigningMaterialMatchesTheDeployProducerCorpus()
    {
        var envelope = Envelope();
        var material = CandidateEvidenceHandoffV2Verifier.CanonicalSigningMaterial(
            envelope.Payload,
            envelope.Signature.Algorithm,
            envelope.Signature.Identity).ToArray();

        await Assert.That(Convert.ToHexStringLower(SHA256.HashData(material)))
            .IsEqualTo("9c2dce7f498dfa9647f1e2f6aa2ab9acebfef3807952d1ed5b54147103090a45");
        await Assert.That(Encoding.UTF8.GetString(material)).StartsWith(
            "{\"domain\":\"terrascale.deploy/candidate-evidence-handoff/v2\",\"schemaVersion\":2");
    }

    [Test]
    public async Task SignatureAudienceAndDurableAuthorityMismatchesFailClosed()
    {
        var envelope = Envelope();
        var signature = CandidateEvidenceHandoffV2Verifier.Verify(
            Bytes(envelope),
            Policy(envelope),
            Durable(envelope),
            true,
            new FixedSignatureVerifier(false));
        var audience = Verify(
            envelope with { Payload = envelope.Payload with { Audience = "different-orchestrator", SupplyChain = envelope.Payload.SupplyChain with { Audience = "different-orchestrator" } } });
        var crossWorkloadSigner = CandidateEvidenceHandoffV2Verifier.Verify(
            Bytes(envelope),
            Policy(envelope) with { ExpectedSigningIdentity = "ecdsa-p256-sha256-" + new string('0', 64) },
            Durable(envelope),
            true,
            new FixedSignatureVerifier(true));
        var unsignedAuthority = CandidateEvidenceHandoffV2Verifier.Verify(
            Bytes(envelope),
            Policy(envelope),
            Durable(envelope),
            false,
            new FixedSignatureVerifier(true));
        var wrongSource = CandidateEvidenceHandoffV2Verifier.Verify(
            Bytes(envelope),
            Policy(envelope),
            Durable(envelope) with { Commit = new string('0', 40) },
            true,
            new FixedSignatureVerifier(true));

        await Assert.That(signature.Error!.Code).IsEqualTo("handoff_v2_signature_mismatch");
        await Assert.That(audience.Error!.Code).IsEqualTo("handoff_v2_audience_mismatch");
        await Assert.That(crossWorkloadSigner.Error!.Code).IsEqualTo("handoff_v2_signer_mismatch");
        await Assert.That(unsignedAuthority.Error!.Code).IsEqualTo("handoff_v2_durable_evidence_mismatch");
        await Assert.That(wrongSource.Error!.Code).IsEqualTo("handoff_v2_durable_evidence_mismatch");
        await Assert.That(signature.Admission).IsNull();
        await Assert.That(unsignedAuthority.Admission).IsNull();
    }

    [Test]
    public async Task MissingStaleMutableAndMismatchedEvidenceFailsClosed()
    {
        var baseline = Envelope();
        var cases = new (CandidateEvidenceHandoffV2Envelope Envelope, CandidateEvidenceHandoffV2AdmissionPolicy Policy, string Code)[]
        {
            (baseline with { Payload = baseline.Payload with { Artifact = baseline.Payload.Artifact with { Reference = baseline.Payload.Artifact.Repository + ":latest" } } }, Policy(baseline), "handoff_v2_artifact_invalid"),
            (baseline with { Payload = baseline.Payload with { Tests = [baseline.Payload.Tests[0] with { Status = "skipped" }] } }, Policy(baseline), "handoff_v2_required_test_not_passed"),
            (baseline with { Payload = baseline.Payload with { KnownGaps = [new("DEP-P0-BLOCKED", "high", true, Digest('1'))] } }, Policy(baseline), "handoff_v2_blocking_gap"),
            (baseline with { Payload = baseline.Payload with { Reason = "password=unredacted" } }, Policy(baseline), "handoff_v2_unredacted"),
            (baseline with { Payload = baseline.Payload with { DependencyLocks = [baseline.Payload.DependencyLocks[0], baseline.Payload.DependencyLocks[0]] } }, Policy(baseline), "handoff_v2_locks_invalid"),
            (baseline with { Payload = baseline.Payload with { DependencyLocks = [baseline.Payload.DependencyLocks[0] with { Path = "nested\\..\\packages.lock.json" }] } }, Policy(baseline), "handoff_v2_locks_invalid"),
            (baseline, Policy(baseline) with { Now = DateTimeOffset.Parse("2026-08-30T12:16:00+00:00") }, "handoff_v2_stale"),
            (baseline, Policy(baseline) with { ExpectedOperationId = "another-operation" }, "handoff_v2_operation_mismatch"),
            (baseline, Policy(baseline) with { ExpectedDependencyLocks = [baseline.Payload.DependencyLocks[0] with { Digest = Digest('0') }] }, "handoff_v2_dependency_locks_mismatch"),
            (baseline, Policy(baseline) with { ExpectedSupplyChainReceiptDigest = Digest('0') }, "handoff_v2_supply_chain_mismatch"),
            (baseline, Policy(baseline) with { ExpectedFirstPartyLicense = Policy(baseline).ExpectedFirstPartyLicense with { EvidenceDigest = Digest('1') } }, "handoff_v2_first_party_license_mismatch"),
            (baseline, Policy(baseline) with { ExpectedApprovalDigests = new Dictionary<string, string> { ["code-review"] = Digest('0') } }, "handoff_v2_approval_mismatch"),
            (baseline, Policy(baseline) with { ExpectedLease = new("another-lease", baseline.Payload.Lease.EvidenceDigest) }, "handoff_v2_lease_mismatch"),
            (baseline, Policy(baseline) with { RequiredTests = new HashSet<string>(["another-suite"], StringComparer.Ordinal) }, "handoff_v2_required_tests_mismatch"),
        };

        foreach (var item in cases)
        {
            var result = CandidateEvidenceHandoffV2Verifier.Verify(
                Bytes(item.Envelope),
                item.Policy,
                Durable(baseline),
                true,
                new FixedSignatureVerifier(true));
            await Assert.That(result.Decision).IsEqualTo(CandidateEvidenceHandoffV2Decision.Rejected);
            await Assert.That(result.Admission).IsNull();
            await Assert.That(result.Error!.Code).IsEqualTo(item.Code);
        }
    }

    [Test]
    public async Task UnknownDuplicateAndOversizedDocumentsFailBeforeAdmission()
    {
        var envelope = Envelope();
        var raw = Encoding.UTF8.GetString(CorpusBytes());
        var unknown = Encoding.UTF8.GetBytes(raw.Replace(
            "\"operationId\": \"candidate-op-1\"",
            "\"operationId\": \"candidate-op-1\", \"benchmarkAuthorization\": true",
            StringComparison.Ordinal));
        var duplicate = Encoding.UTF8.GetBytes(raw.Replace(
            "\"operationId\": \"candidate-op-1\"",
            "\"operationId\": \"candidate-op-1\", \"operationId\": \"candidate-op-2\"",
            StringComparison.Ordinal));
        var mixedCaseDuplicate = Encoding.UTF8.GetBytes(raw.Replace(
            "\"operationId\": \"candidate-op-1\"",
            "\"operationId\": \"candidate-op-1\", \"OperationId\": \"candidate-op-2\"",
            StringComparison.Ordinal));
        var nonCanonicalCase = Encoding.UTF8.GetBytes(raw.Replace(
            "\"operationId\": \"candidate-op-1\"",
            "\"OperationId\": \"candidate-op-1\"",
            StringComparison.Ordinal));
        var oversized = new byte[CandidateEvidenceHandoffV2Contract.MaximumDocumentBytes + 1];

        foreach (var document in new[] { unknown, duplicate, mixedCaseDuplicate, nonCanonicalCase, oversized })
        {
            var result = CandidateEvidenceHandoffV2Verifier.Verify(
                document,
                Policy(envelope),
                Durable(envelope),
                true,
                new FixedSignatureVerifier(true));
            await Assert.That(result.Decision).IsEqualTo(CandidateEvidenceHandoffV2Decision.Rejected);
            await Assert.That(result.Admission).IsNull();
            await Assert.That(result.Error!.Code).IsEqualTo("handoff_v2_document_invalid");
        }
    }

    [Test]
    public async Task EvidenceCreatedAfterIssuedAtFailsBeforeFreshnessEvaluation()
    {
        var baseline = Envelope();
        var issuedAt = baseline.Payload.IssuedAt;
        var cleanCheckedAt = issuedAt.AddSeconds(1);
        var cleanWorktree = baseline.Payload.Source.CleanWorktree with
        {
            CheckedAt = cleanCheckedAt,
            ProofDigest = CandidateEvidenceHandoffV2Verifier.CleanWorktreeProofDigest(
                baseline.Payload.Source,
                baseline.Payload.Source.CleanWorktree.StatusDigest,
                cleanCheckedAt),
        };
        var cases = new (CandidateEvidenceHandoffV2Envelope Envelope, string Code)[]
        {
            (baseline with
            {
                Payload = baseline.Payload with
                {
                    Source = baseline.Payload.Source with { CleanWorktree = cleanWorktree },
                },
            }, "handoff_v2_clean_worktree_invalid"),
            (baseline with { Payload = baseline.Payload with { Security = baseline.Payload.Security with { ScanGeneratedAt = issuedAt.AddSeconds(1) } } }, "handoff_v2_security_invalid"),
            (baseline with { Payload = baseline.Payload with { Tests = [baseline.Payload.Tests[0] with { CompletedAt = issuedAt.AddSeconds(1) }] } }, "handoff_v2_test_invalid"),
            (baseline with { Payload = baseline.Payload with { Approvals = [baseline.Payload.Approvals[0] with { DecidedAt = issuedAt.AddSeconds(1) }] } }, "handoff_v2_approval_invalid"),
            (baseline with { Payload = baseline.Payload with { Lease = baseline.Payload.Lease with { AcquiredAt = issuedAt.AddSeconds(1) } } }, "handoff_v2_lease_invalid"),
        };

        foreach (var item in cases)
        {
            var result = CandidateEvidenceHandoffV2Verifier.Verify(
                Bytes(item.Envelope),
                Policy(baseline),
                Durable(baseline),
                true,
                new FixedSignatureVerifier(true));
            await Assert.That(result.Error!.Code).IsEqualTo(item.Code);
        }
    }

    [Test]
    public async Task StaleTestsSecurityApprovalsAndLeaseFailIndependently()
    {
        var baseline = Envelope();
        var now = DateTimeOffset.Parse("2026-08-30T12:05:00+00:00");
        var cases = new (CandidateEvidenceHandoffV2Envelope Envelope, CandidateEvidenceHandoffV2AdmissionPolicy Policy, string Code)[]
        {
            (baseline, Policy(baseline) with { MaximumTestAge = TimeSpan.FromMinutes(10) }, "handoff_v2_test_stale"),
            (baseline, Policy(baseline) with { MaximumSecurityAge = TimeSpan.FromMinutes(10) }, "handoff_v2_security_stale"),
            (baseline with { Payload = baseline.Payload with { Approvals = [baseline.Payload.Approvals[0] with { ExpiresAt = now.AddSeconds(-1) }] } }, Policy(baseline), "handoff_v2_approval_stale"),
            (baseline with { Payload = baseline.Payload with { Lease = baseline.Payload.Lease with { ExpiresAt = now.AddSeconds(-1) } } }, Policy(baseline), "handoff_v2_lease_stale"),
        };

        foreach (var item in cases)
        {
            var policy = item.Policy with
            {
                ExpectedLease = new(item.Envelope.Payload.Lease.LeaseId, item.Envelope.Payload.Lease.EvidenceDigest),
            };
            var result = CandidateEvidenceHandoffV2Verifier.Verify(
                Bytes(item.Envelope),
                policy,
                Durable(baseline),
                true,
                new FixedSignatureVerifier(true));
            await Assert.That(result.Error!.Code).IsEqualTo(item.Code);
        }
    }

    internal static CandidateEvidenceHandoffV2Envelope Envelope() =>
        JsonSerializer.Deserialize<CandidateEvidenceHandoffV2Envelope>(CorpusBytes(), new JsonSerializerOptions(JsonSerializerDefaults.Web))
        ?? throw new InvalidDataException("The v2 corpus fixture is empty.");

    internal static CandidateEvidenceHandoffV2AdmissionPolicy Policy(CandidateEvidenceHandoffV2Envelope envelope) => new(
        DateTimeOffset.Parse("2026-08-30T12:05:00+00:00"),
        envelope.Payload.OperationId,
        "terrascale-orchestrator",
        envelope.Signature.Identity,
        envelope.Payload.DeployCli,
        envelope.Payload.DependencyLocks,
        envelope.Payload.Artifact,
        envelope.Payload.ConfigurationDigest,
        envelope.Payload.MigrationDigest,
        envelope.Payload.Target,
        new(envelope.Payload.Lease.LeaseId, envelope.Payload.Lease.EvidenceDigest),
        envelope.Payload.Rollback,
        envelope.Payload.SupplyChain.ReceiptDigest,
        new(
            envelope.Payload.FirstPartyLicense.SchemaVersion,
            envelope.Payload.FirstPartyLicense.Status,
            envelope.Payload.FirstPartyLicense.Scope,
            envelope.Payload.FirstPartyLicense.ComponentInventoryDigest,
            envelope.Payload.FirstPartyLicense.PrivateComponentCoverage,
            envelope.Payload.FirstPartyLicense.DispositionDigest,
            envelope.Payload.FirstPartyLicense.EvidenceDigest),
        envelope.Payload.Approvals.ToDictionary(static value => value.Id, static value => value.EvidenceDigest, StringComparer.Ordinal),
        envelope.Payload.Tests.Where(static value => value.Required).Select(static value => value.Name).ToHashSet(StringComparer.Ordinal),
        TimeSpan.FromMinutes(10),
        TimeSpan.FromMinutes(10),
        TimeSpan.FromHours(1),
        TimeSpan.FromHours(1),
        TimeSpan.FromHours(1));

    internal static DirectDeliveryArtifactEvidence Durable(CandidateEvidenceHandoffV2Envelope envelope) => new(
        envelope.Payload.Source.Repository,
        envelope.Payload.Source.Commit,
        envelope.Payload.Source.TreeDigest,
        envelope.Payload.Artifact.Digest,
        envelope.Payload.Artifact.ManifestDigest,
        envelope.Payload.Artifact.Kind);

    internal static byte[] Bytes(CandidateEvidenceHandoffV2Envelope envelope) =>
        CandidateEvidenceHandoffV2Verifier.SerializeEnvelope(envelope);

    internal static byte[] CorpusBytes() => File.ReadAllBytes(Path.Combine(
        RepositoryRoot(),
        "tests",
        "TerraScale.Orchestrator.Tests",
        "DeployHandoffV2",
        "fixtures",
        "candidate-evidence-handoff-v2.json"));

    internal static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "TerraScale.Orchestrator.slnx")))
                return directory.FullName;
            directory = directory.Parent;
        }
        throw new InvalidOperationException("Could not locate the TerraScale.Orchestrator repository root.");
    }

    private static CandidateEvidenceHandoffV2Result Verify(CandidateEvidenceHandoffV2Envelope envelope) =>
        CandidateEvidenceHandoffV2Verifier.Verify(
            Bytes(envelope),
            Policy(Envelope()),
            Durable(Envelope()),
            true,
            new FixedSignatureVerifier(true));

    private static string Digest(char value) => "sha256:" + new string(value, 64);

    internal sealed class FixedSignatureVerifier(bool result) : ICandidateEvidenceHandoffV2SignatureVerifier
    {
        public bool Verify(string signingIdentity, ReadOnlyMemory<byte> canonicalMaterial, ReadOnlyMemory<byte> signature)
        {
            _ = signingIdentity;
            _ = canonicalMaterial;
            _ = signature;
            return result;
        }
    }
}
