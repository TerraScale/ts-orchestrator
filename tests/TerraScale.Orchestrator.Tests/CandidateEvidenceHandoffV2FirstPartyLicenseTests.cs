using System.Text;
using System.Text.Json.Nodes;
using TerraScale.Orchestrator.Delivery.DeployHandoffV2;

namespace TerraScale.Orchestrator.Tests;

public sealed class CandidateEvidenceHandoffV2FirstPartyLicenseTests
{
    [Test]
    public async Task FirstPartyLicenseEvidenceFailsClosedAtEveryContractBoundary()
    {
        var baseline = CandidateEvidenceHandoffV2VerifierTests.Envelope();
        var evidence = baseline.Payload.FirstPartyLicense;
        var cases = new (CandidateEvidenceHandoffV2Envelope Envelope, string Code)[]
        {
            (WithEvidence(baseline, null!), "handoff_v2_first_party_license_invalid"),
            (WithEvidence(baseline, evidence with { SchemaVersion = 2 }), "handoff_v2_first_party_license_invalid"),
            (WithEvidence(baseline, evidence with { Status = "pending-before-release" }), "handoff_v2_first_party_license_invalid"),
            (WithEvidence(baseline, evidence with { Scope = "dependencies-only" }), "handoff_v2_first_party_license_invalid"),
            (WithEvidence(baseline, evidence with { Repository = "TerraScale/Another" }), "handoff_v2_first_party_license_invalid"),
            (WithEvidence(baseline, evidence with { SourceTreeDigest = Digest('a') }), "handoff_v2_first_party_license_invalid"),
            (WithEvidence(baseline, evidence with { ComponentInventoryDigest = "SHA256:" + new string('3', 64) }), "handoff_v2_first_party_license_invalid"),
            (WithEvidence(baseline, evidence with { PrivateComponentCoverage = "dependencies-only" }), "handoff_v2_first_party_license_invalid"),
            (WithEvidence(baseline, evidence with { DispositionDigest = "LicenseRef-TerraScale-Pending" }), "handoff_v2_first_party_license_invalid"),
            (WithEvidence(baseline, evidence with { EvidenceDigest = "sha256:short" }), "handoff_v2_first_party_license_invalid"),
            (WithEvidence(baseline, evidence with { DecidedAt = default }), "handoff_v2_first_party_license_invalid"),
            (WithEvidence(baseline, evidence with { DecidedAt = baseline.Payload.IssuedAt.AddSeconds(1) }), "handoff_v2_first_party_license_invalid"),
            (WithEvidence(baseline, evidence with { EvidenceDigest = baseline.Payload.SupplyChain.SbomDigest }), "handoff_v2_first_party_license_not_distinct"),
            (baseline with { Payload = baseline.Payload with { SupplyChain = baseline.Payload.SupplyChain with { ReceiptSchemaVersion = 1 } } }, "handoff_v2_supply_chain_invalid"),
            (baseline with { Payload = baseline.Payload with { Approvals = [baseline.Payload.Approvals[0] with { ApproverIdentityDigest = string.Empty }] } }, "handoff_v2_approval_invalid"),
        };

        foreach (var item in cases)
        {
            var result = Verify(item.Envelope, CandidateEvidenceHandoffV2VerifierTests.Policy(baseline));
            await Assert.That(result.Decision).IsEqualTo(CandidateEvidenceHandoffV2Decision.Rejected);
            await Assert.That(result.Admission).IsNull();
            await Assert.That(result.Error!.Code).IsEqualTo(item.Code);
        }
    }

    [Test]
    public async Task MissingProjectionFailsClosedDuringStrictParsing()
    {
        var baseline = CandidateEvidenceHandoffV2VerifierTests.Envelope();
        var root = JsonNode.Parse(CandidateEvidenceHandoffV2VerifierTests.CorpusBytes())!.AsObject();
        root["payload"]!.AsObject().Remove("firstPartyLicense");

        var result = CandidateEvidenceHandoffV2Verifier.Verify(
            Encoding.UTF8.GetBytes(root.ToJsonString()),
            CandidateEvidenceHandoffV2VerifierTests.Policy(baseline),
            CandidateEvidenceHandoffV2VerifierTests.Durable(baseline),
            true,
            new CandidateEvidenceHandoffV2VerifierTests.FixedSignatureVerifier(true));

        await Assert.That(result.Decision).IsEqualTo(CandidateEvidenceHandoffV2Decision.Rejected);
        await Assert.That(result.Admission).IsNull();
        await Assert.That(result.Error!.Code).IsEqualTo("handoff_v2_first_party_license_invalid");
    }

    [Test]
    public async Task AdmissionPolicyPinsEveryFirstPartyDispositionIdentityAndFreshness()
    {
        var baseline = CandidateEvidenceHandoffV2VerifierTests.Envelope();
        var policy = CandidateEvidenceHandoffV2VerifierTests.Policy(baseline);
        var expectation = policy.ExpectedFirstPartyLicense;
        var mismatches = new[]
        {
            policy with { ExpectedFirstPartyLicense = expectation with { ComponentInventoryDigest = Digest('4') } },
            policy with { ExpectedFirstPartyLicense = expectation with { DispositionDigest = Digest('4') } },
            policy with { ExpectedFirstPartyLicense = expectation with { EvidenceDigest = Digest('4') } },
        };

        foreach (var mismatch in mismatches)
        {
            var result = Verify(baseline, mismatch);
            await Assert.That(result.Decision).IsEqualTo(CandidateEvidenceHandoffV2Decision.Rejected);
            await Assert.That(result.Error!.Code).IsEqualTo("handoff_v2_first_party_license_mismatch");
        }

        var stale = Verify(baseline, policy with { MaximumFirstPartyLicenseAge = TimeSpan.FromMinutes(10) });
        await Assert.That(stale.Decision).IsEqualTo(CandidateEvidenceHandoffV2Decision.Rejected);
        await Assert.That(stale.Error!.Code).IsEqualTo("handoff_v2_first_party_license_stale");

        foreach (var invalid in new[]
                 {
                     policy with { ExpectedFirstPartyLicense = expectation with { SchemaVersion = 2 } },
                     policy with { ExpectedFirstPartyLicense = expectation with { Status = "pending-before-release" } },
                     policy with { ExpectedFirstPartyLicense = expectation with { Scope = "dependencies-only" } },
                     policy with { ExpectedFirstPartyLicense = expectation with { PrivateComponentCoverage = "partial" } },
                     policy with { MaximumFirstPartyLicenseAge = TimeSpan.Zero },
                 })
            await Assert.That(CandidateEvidenceHandoffV2Verifier.IsAdmissionPolicyValid(invalid)).IsFalse();
    }

    [Test]
    public async Task SignedFirstPartyProjectionTamperingChangesCanonicalMaterialAndFailsSignature()
    {
        var baseline = CandidateEvidenceHandoffV2VerifierTests.Envelope();
        var canonical = CandidateEvidenceHandoffV2Verifier.CanonicalSigningMaterial(
            baseline.Payload,
            baseline.Signature.Algorithm,
            baseline.Signature.Identity);
        var tampered = WithEvidence(
            baseline,
            baseline.Payload.FirstPartyLicense with { ComponentInventoryDigest = Digest('4') });

        var result = CandidateEvidenceHandoffV2Verifier.Verify(
            CandidateEvidenceHandoffV2VerifierTests.Bytes(tampered),
            CandidateEvidenceHandoffV2VerifierTests.Policy(baseline),
            CandidateEvidenceHandoffV2VerifierTests.Durable(baseline),
            true,
            new ExactCanonicalMaterialVerifier(canonical));

        await Assert.That(result.Decision).IsEqualTo(CandidateEvidenceHandoffV2Decision.Rejected);
        await Assert.That(result.Admission).IsNull();
        await Assert.That(result.Error!.Code).IsEqualTo("handoff_v2_signature_mismatch");
    }

    private static CandidateEvidenceHandoffV2Envelope WithEvidence(
        CandidateEvidenceHandoffV2Envelope envelope,
        CandidateHandoffV2FirstPartyLicenseEvidence evidence) =>
        envelope with { Payload = envelope.Payload with { FirstPartyLicense = evidence } };

    private static CandidateEvidenceHandoffV2Result Verify(
        CandidateEvidenceHandoffV2Envelope envelope,
        CandidateEvidenceHandoffV2AdmissionPolicy policy)
    {
        var baseline = CandidateEvidenceHandoffV2VerifierTests.Envelope();
        return CandidateEvidenceHandoffV2Verifier.Verify(
            CandidateEvidenceHandoffV2VerifierTests.Bytes(envelope),
            policy,
            CandidateEvidenceHandoffV2VerifierTests.Durable(baseline),
            true,
            new CandidateEvidenceHandoffV2VerifierTests.FixedSignatureVerifier(true));
    }

    private static string Digest(char value) => "sha256:" + new string(value, 64);

    private sealed class ExactCanonicalMaterialVerifier(ReadOnlyMemory<byte> expected)
        : ICandidateEvidenceHandoffV2SignatureVerifier
    {
        public bool Verify(
            string signingIdentity,
            ReadOnlyMemory<byte> canonicalMaterial,
            ReadOnlyMemory<byte> signature)
        {
            _ = signingIdentity;
            _ = signature;
            return canonicalMaterial.Span.SequenceEqual(expected.Span);
        }
    }
}

