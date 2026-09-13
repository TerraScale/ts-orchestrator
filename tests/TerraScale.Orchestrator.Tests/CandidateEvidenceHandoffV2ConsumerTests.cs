using System.Security.Cryptography;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Delivery.DeployHandoffV2;

namespace TerraScale.Orchestrator.Tests;

public sealed class CandidateEvidenceHandoffV2ConsumerTests
{
    [Test]
    public async Task ConsumerRequiresDurableAuthorityThenVerifiesWithEstablishedP256Trust()
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("The production signing-key permission contract is Linux-only.");
        var original = CandidateEvidenceHandoffV2VerifierTests.Envelope();
        using var identity = EcdsaIdentity.Create();
        var envelope = Sign(original, identity.Signer);
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var adapter = new DirectDeliveryProductionAdapterTests.LedgerAdapter(ledger);
        var durableTrust = new DirectDeliveryProductionAdapterTests.HashSignature(42);
        var journal = new DirectDeliveryArtifactEvidenceJournal(adapter);
        await journal.RecordAsync(
            CandidateEvidenceHandoffV2VerifierTests.Durable(envelope),
            durableTrust,
            default);
        var consumer = new CandidateEvidenceHandoffV2Consumer(
            journal,
            durableTrust,
            new RepositoryCandidateEvidenceHandoffV2SignatureVerifier(identity.Verifier));

        var result = await consumer.VerifyAsync(
            CandidateEvidenceHandoffV2VerifierTests.Bytes(envelope),
            CandidateEvidenceHandoffV2VerifierTests.Policy(envelope));

        await Assert.That(result.Decision).IsEqualTo(CandidateEvidenceHandoffV2Decision.Verified);
        await Assert.That(result.Admission).IsNotNull();
        await Assert.That(result.Admission!.Delivery.Artifact!.Digest).IsEqualTo(envelope.Payload.Artifact.Digest);
        await Assert.That(result.Admission.Delivery.AuthorityGeneration).IsEqualTo(0L);
    }

    [Test]
    public async Task MissingOrMismatchedDurableEvidenceCannotProduceDeliveryRequest()
    {
        var envelope = CandidateEvidenceHandoffV2VerifierTests.Envelope();
        var document = CandidateEvidenceHandoffV2VerifierTests.Bytes(envelope);
        var policy = CandidateEvidenceHandoffV2VerifierTests.Policy(envelope);
        var trust = new DirectDeliveryProductionAdapterTests.HashSignature(7);

        var emptyLedger = new ForgejoWebhookJournalTests.TestLedger();
        var empty = new CandidateEvidenceHandoffV2Consumer(
            new(new DirectDeliveryProductionAdapterTests.LedgerAdapter(emptyLedger)),
            trust,
            new CandidateEvidenceHandoffV2VerifierTests.FixedSignatureVerifier(true));
        var missing = await empty.VerifyAsync(document, policy);

        var mismatchedLedger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new DirectDeliveryArtifactEvidenceJournal(
            new DirectDeliveryProductionAdapterTests.LedgerAdapter(mismatchedLedger));
        await journal.RecordAsync(
            CandidateEvidenceHandoffV2VerifierTests.Durable(envelope) with { Commit = new string('0', 40) },
            trust,
            default);
        var mismatched = await new CandidateEvidenceHandoffV2Consumer(
                journal,
                trust,
                new CandidateEvidenceHandoffV2VerifierTests.FixedSignatureVerifier(true))
            .VerifyAsync(document, policy);

        await Assert.That(missing.Error!.Code).IsEqualTo("handoff_v2_durable_evidence_missing");
        await Assert.That(missing.Admission).IsNull();
        await Assert.That(mismatched.Error!.Code).IsEqualTo("handoff_v2_durable_evidence_mismatch");
        await Assert.That(mismatched.Admission).IsNull();
    }

    [Test]
    public async Task WrongHandoffTrustRootIsRejectedAfterDurableEvidencePasses()
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("The production signing-key permission contract is Linux-only.");
        var original = CandidateEvidenceHandoffV2VerifierTests.Envelope();
        using var signer = EcdsaIdentity.Create();
        using var other = EcdsaIdentity.Create();
        var envelope = Sign(original, signer.Signer);
        var trust = new DirectDeliveryProductionAdapterTests.HashSignature(9);
        var journal = new DirectDeliveryArtifactEvidenceJournal(
            new DirectDeliveryProductionAdapterTests.LedgerAdapter(new ForgejoWebhookJournalTests.TestLedger()));
        await journal.RecordAsync(CandidateEvidenceHandoffV2VerifierTests.Durable(envelope), trust, default);
        var consumer = new CandidateEvidenceHandoffV2Consumer(
            journal,
            trust,
            new RepositoryCandidateEvidenceHandoffV2SignatureVerifier(other.Verifier));

        var result = await consumer.VerifyAsync(
            CandidateEvidenceHandoffV2VerifierTests.Bytes(envelope),
            CandidateEvidenceHandoffV2VerifierTests.Policy(envelope));

        await Assert.That(result.Error!.Code).IsEqualTo("handoff_v2_signature_mismatch");
        await Assert.That(result.Admission).IsNull();
    }

    [Test]
    public async Task RepeatedVerificationIsPureAndKeepsTheDurableOperationIdentity()
    {
        var envelope = CandidateEvidenceHandoffV2VerifierTests.Envelope();
        var trust = new DirectDeliveryProductionAdapterTests.HashSignature(11);
        var journal = new DirectDeliveryArtifactEvidenceJournal(
            new DirectDeliveryProductionAdapterTests.LedgerAdapter(new ForgejoWebhookJournalTests.TestLedger()));
        await journal.RecordAsync(CandidateEvidenceHandoffV2VerifierTests.Durable(envelope), trust, default);
        var consumer = new CandidateEvidenceHandoffV2Consumer(
            journal,
            trust,
            new CandidateEvidenceHandoffV2VerifierTests.FixedSignatureVerifier(true));
        var document = CandidateEvidenceHandoffV2VerifierTests.Bytes(envelope);
        var policy = CandidateEvidenceHandoffV2VerifierTests.Policy(envelope);

        var first = await consumer.VerifyAsync(document, policy);
        var second = await consumer.VerifyAsync(document, policy);

        await Assert.That(TerraScale.Orchestrator.ControlPlane.Delivery.DeliveryWireCodec.SerializeRequest(first.Admission!.Delivery))
            .IsEqualTo(TerraScale.Orchestrator.ControlPlane.Delivery.DeliveryWireCodec.SerializeRequest(second.Admission!.Delivery));
        await Assert.That(first.Admission!.Delivery.OperationId).IsEqualTo(policy.ExpectedOperationId);
        await Assert.That(first.Admission.Delivery.AuthorityGeneration).IsEqualTo(0L);
        await Assert.That(first.Admission.Delivery.Attempt).IsEqualTo(0);
    }

    private static CandidateEvidenceHandoffV2Envelope Sign(
        CandidateEvidenceHandoffV2Envelope envelope,
        EcdsaCommandSigner signer)
    {
        var material = CandidateEvidenceHandoffV2Verifier.CanonicalSigningMaterial(
            envelope.Payload,
            CandidateEvidenceHandoffV2Contract.SigningAlgorithm,
            signer.Identity);
        var signature = signer.Sign(material);
        return envelope with
        {
            Signature = new(
                CandidateEvidenceHandoffV2Contract.SigningAlgorithm,
                signer.Identity,
                Convert.ToBase64String(signature.Bytes)),
        };
    }

    private sealed class EcdsaIdentity : IDisposable
    {
        private readonly string publicPath;

        private EcdsaIdentity(EcdsaCommandSigner signer, EcdsaCommandSignatureVerifier verifier, string publicPath)
        {
            Signer = signer;
            Verifier = verifier;
            this.publicPath = publicPath;
        }

        internal EcdsaCommandSigner Signer { get; }
        internal EcdsaCommandSignatureVerifier Verifier { get; }

        internal static EcdsaIdentity Create()
        {
            if (!OperatingSystem.IsLinux())
                throw new PlatformNotSupportedException("The production signing-key permission contract is Linux-only.");
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var privatePath = Path.Combine(Path.GetTempPath(), $"ts-handoff-v2-private-{Guid.NewGuid():N}.pem");
            var publicPath = Path.Combine(Path.GetTempPath(), $"ts-handoff-v2-public-{Guid.NewGuid():N}.pem");
            File.WriteAllText(privatePath, key.ExportPkcs8PrivateKeyPem());
            File.WriteAllText(publicPath, key.ExportSubjectPublicKeyInfoPem());
            File.SetUnixFileMode(privatePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            try
            {
                return new(
                    EcdsaCommandSigner.LoadPrivatePem(privatePath),
                    EcdsaCommandSignatureVerifier.LoadPublicPem([publicPath]),
                    publicPath);
            }
            finally
            {
                File.Delete(privatePath);
            }
        }

        public void Dispose()
        {
            Verifier.Dispose();
            Signer.Dispose();
            File.Delete(publicPath);
        }
    }
}

