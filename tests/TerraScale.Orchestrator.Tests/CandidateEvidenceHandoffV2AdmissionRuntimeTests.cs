using System.Text;
using System.Text.Json;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Delivery.DeployHandoffV2;

namespace TerraScale.Orchestrator.Tests;

public sealed class CandidateEvidenceHandoffV2AdmissionRuntimeTests
{
    [Test]
    public async Task ExactStartupPolicyProducesAdmissionOnlyReceiptWithoutDeliveryMutation()
    {
        var envelope = CandidateEvidenceHandoffV2VerifierTests.Envelope();
        var fixture = await RuntimeAsync(envelope, CandidateEvidenceHandoffV2VerifierTests.Policy(envelope));

        var receipt = await fixture.Runtime.AdmitAsync(
            CandidateEvidenceHandoffV2VerifierTests.Bytes(envelope),
            CandidateEvidenceHandoffV2VerifierTests.Policy(envelope).Now);

        await Assert.That(receipt.Status).IsEqualTo("admitted");
        await Assert.That(receipt.Error).IsNull();
        await Assert.That(receipt.AuthorityGeneration).IsEqualTo(0L);
        await Assert.That(receipt.WriterEpoch).IsEqualTo(0L);
        await Assert.That(receipt.Attempt).IsEqualTo(0);
        await Assert.That(await CountKeysAsync(fixture.Ledger, "direct.operation.>")).IsEqualTo(0);
        await Assert.That(await CountKeysAsync(fixture.Ledger, "direct.target.>")).IsEqualTo(0);

        using var serialized = JsonDocument.Parse(
            CandidateEvidenceHandoffV2AdmissionRuntime.SerializeReceipt(receipt));
        await Assert.That(serialized.RootElement.GetProperty("mediaType").GetString())
            .IsEqualTo(CandidateEvidenceHandoffV2Contract.AdmissionReceiptMediaType);
        await Assert.That(serialized.RootElement.GetProperty("authorityGeneration").GetInt64()).IsEqualTo(0L);
    }

    [Test]
    public async Task MissingOrDifferentOperationArtifactPolicyFailsBeforeConsumerAdmission()
    {
        var envelope = CandidateEvidenceHandoffV2VerifierTests.Envelope();
        var fixture = await RuntimeAsync(envelope, null);

        var receipt = await fixture.Runtime.AdmitAsync(
            CandidateEvidenceHandoffV2VerifierTests.Bytes(envelope),
            CandidateEvidenceHandoffV2VerifierTests.Policy(envelope).Now);

        await Assert.That(receipt.Status).IsEqualTo("rejected");
        await Assert.That(receipt.Error!.Code).IsEqualTo("handoff_v2_policy_missing");
        await Assert.That(receipt.AuthorityGeneration).IsEqualTo(0L);
        await Assert.That(await CountKeysAsync(fixture.Ledger, "direct.operation.>")).IsEqualTo(0);
    }

    [Test]
    public async Task CatalogRejectsDuplicateKeysMixedCaseFieldsAndInjectsCurrentTime()
    {
        var envelope = CandidateEvidenceHandoffV2VerifierTests.Envelope();
        var policy = CandidateEvidenceHandoffV2VerifierTests.Policy(envelope);
        var bytes = CatalogBytes(policy);
        var catalog = CandidateEvidenceHandoffV2AdmissionPolicyCatalog.Parse(bytes);
        var routing = new CandidateEvidenceHandoffV2RoutingIdentity(
            policy.ExpectedOperationId,
            policy.ExpectedArtifact.Digest);
        var observedNow = policy.Now.AddMinutes(1);

        var resolved = catalog.Resolve(routing, observedNow);
        var duplicate = await Assert.That(() => CandidateEvidenceHandoffV2AdmissionPolicyCatalog.Create([policy, policy]))
            .Throws<InvalidDataException>();
        var mixedCase = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(bytes).Replace(
            "\"operationId\"",
            "\"OperationId\"",
            StringComparison.Ordinal));
        var mixedCaseError = await Assert.That(() => CandidateEvidenceHandoffV2AdmissionPolicyCatalog.Parse(mixedCase))
            .Throws<InvalidDataException>();
        var duplicateProperty = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(bytes).Replace(
            $"\"operationId\":\"{policy.ExpectedOperationId}\"",
            $"\"operationId\":\"{policy.ExpectedOperationId}\",\"operationId\":\"substitute-operation\"",
            StringComparison.Ordinal));
        var duplicatePropertyError = await Assert.That(() =>
                CandidateEvidenceHandoffV2AdmissionPolicyCatalog.Parse(duplicateProperty))
            .Throws<InvalidDataException>();
        var oversizedError = await Assert.That(() =>
                CandidateEvidenceHandoffV2AdmissionPolicyCatalog.Parse(new byte[(4 * 1024 * 1024) + 1]))
            .Throws<InvalidDataException>();

        await Assert.That(resolved).IsNotNull();
        await Assert.That(resolved!.Now).IsEqualTo(observedNow);
        await Assert.That(duplicate).IsNotNull();
        await Assert.That(mixedCaseError).IsNotNull();
        await Assert.That(duplicatePropertyError).IsNotNull();
        await Assert.That(oversizedError).IsNotNull();
    }

    [Test]
    public async Task CatalogFileReaderAcceptsOnlyOneBoundedSnapshot()
    {
        var envelope = CandidateEvidenceHandoffV2VerifierTests.Envelope();
        var bytes = CatalogBytes(CandidateEvidenceHandoffV2VerifierTests.Policy(envelope));
        var root = Path.Combine(Path.GetTempPath(), "terrascale-handoff-v2-catalog-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, "catalog.json");
        try
        {
            await File.WriteAllBytesAsync(path, bytes);
            var catalog = CandidateEvidenceHandoffV2AdmissionPolicyCatalog.Load(path);
            await Assert.That(catalog.IsEmpty).IsFalse();

            await File.WriteAllBytesAsync(path, new byte[(4 * 1024 * 1024) + 1]);
            var oversized = await Assert.That(() => CandidateEvidenceHandoffV2AdmissionPolicyCatalog.Load(path))
                .Throws<InvalidDataException>();
            await Assert.That(oversized).IsNotNull();
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static async Task<RuntimeFixture> RuntimeAsync(
        CandidateEvidenceHandoffV2Envelope envelope,
        CandidateEvidenceHandoffV2AdmissionPolicy? policy)
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var adapter = new DirectDeliveryProductionAdapterTests.LedgerAdapter(ledger);
        var trust = new DirectDeliveryProductionAdapterTests.HashSignature(91);
        var journal = new DirectDeliveryArtifactEvidenceJournal(adapter);
        await journal.RecordAsync(CandidateEvidenceHandoffV2VerifierTests.Durable(envelope), trust, default);
        var consumer = new CandidateEvidenceHandoffV2Consumer(
            journal,
            trust,
            new CandidateEvidenceHandoffV2VerifierTests.FixedSignatureVerifier(true));
        var catalog = policy is null
            ? CandidateEvidenceHandoffV2AdmissionPolicyCatalog.Empty
            : CandidateEvidenceHandoffV2AdmissionPolicyCatalog.Create([policy]);
        return new(new(consumer, catalog), ledger);
    }

    private static byte[] CatalogBytes(CandidateEvidenceHandoffV2AdmissionPolicy policy) =>
        JsonSerializer.SerializeToUtf8Bytes(new
        {
            schemaVersion = 1,
            policies = new[]
            {
                new
                {
                    operationId = policy.ExpectedOperationId,
                    audience = policy.ExpectedAudience,
                    signingIdentity = policy.ExpectedSigningIdentity,
                    deployCli = policy.ExpectedDeployCli,
                    dependencyLocks = policy.ExpectedDependencyLocks,
                    artifact = policy.ExpectedArtifact,
                    configurationDigest = policy.ExpectedConfigurationDigest,
                    migrationDigest = policy.ExpectedMigrationDigest,
                    target = policy.ExpectedTarget,
                    lease = policy.ExpectedLease,
                    rollback = policy.ExpectedRollback,
                    supplyChainReceiptDigest = policy.ExpectedSupplyChainReceiptDigest,
                    firstPartyLicense = policy.ExpectedFirstPartyLicense,
                    approvalDigests = policy.ExpectedApprovalDigests,
                    requiredTests = policy.RequiredTests.Order(StringComparer.Ordinal).ToArray(),
                    maximumEnvelopeAgeSeconds = checked((int)policy.MaximumEnvelopeAge.TotalSeconds),
                    maximumCleanWorktreeProofAgeSeconds = checked((int)policy.MaximumCleanWorktreeProofAge.TotalSeconds),
                    maximumTestAgeSeconds = checked((int)policy.MaximumTestAge.TotalSeconds),
                    maximumSecurityAgeSeconds = checked((int)policy.MaximumSecurityAge.TotalSeconds),
                    maximumFirstPartyLicenseAgeSeconds = checked((int)policy.MaximumFirstPartyLicenseAge.TotalSeconds),
                },
            },
        });

    private static async Task<int> CountKeysAsync(ForgejoWebhookJournalTests.TestLedger ledger, string filter)
    {
        var count = 0;
        await foreach (var _ in ledger.ListKeysAsync(filter, default))
            count++;
        return count;
    }

    private sealed record RuntimeFixture(
        CandidateEvidenceHandoffV2AdmissionRuntime Runtime,
        ForgejoWebhookJournalTests.TestLedger Ledger);
}

