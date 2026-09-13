using System.Text;
using System.Text.Json.Nodes;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Delivery.DeployHandoffV2;

namespace TerraScale.Orchestrator.Tests;

public sealed class CandidateEvidenceHandoffV2ProvisionalSchemaBoundaryTests
{
    [Test]
    public async Task ProvisionalMatrixNoRebuildAndRollbackRetentionClaimsFailBeforeAdmission()
    {
        var envelope = CandidateEvidenceHandoffV2VerifierTests.Envelope();
        var policy = CandidateEvidenceHandoffV2VerifierTests.Policy(envelope);
        var fixture = await RuntimeAsync(envelope, policy);
        var cases = new (string Name, Action<JsonObject> AddUnsupportedField)[]
        {
            ("payload.releaseProfiles", root => Payload(root)["releaseProfiles"] = JsonNode.Parse(
                """[{"name":"full","weight":"heavy","commands":[["dotnet","test"]]}]""")),
            ("payload.testMatrix", root => Payload(root)["testMatrix"] = JsonNode.Parse(
                """[{"profile":"full","weight":"heavy","required":true}]""")),
            ("payload.test_matrix", root => Payload(root)["test_matrix"] = JsonNode.Parse(
                """[{"profile":"full","weight":"heavy","required":true}]""")),
            ("payload.noRebuild", root => Payload(root)["noRebuild"] = true),
            ("payload.tests[].weight", root => First(Payload(root), "tests")["weight"] = "heavy"),
            ("payload.tests[].commands", root => First(Payload(root), "tests")["commands"] = JsonNode.Parse(
                """[["dotnet","test"]]""")),
            ("payload.rollback.retentionReceiptDigest", root =>
                Payload(root)["rollback"]!.AsObject()["retentionReceiptDigest"] = Digest('9')),
        };

        foreach (var item in cases)
        {
            var root = CorpusRoot();
            item.AddUnsupportedField(root);

            var receipt = await fixture.Runtime.AdmitAsync(
                Encoding.UTF8.GetBytes(root.ToJsonString()),
                policy.Now);

            await Assert.That(receipt.Status).IsEqualTo("rejected");
            await Assert.That(receipt.OperationId).IsEqualTo("invalid");
            await Assert.That(receipt.ArtifactDigest).IsEqualTo(Digest('0'));
            await Assert.That(receipt.Error!.Code).IsEqualTo("handoff_v2_document_invalid");
            await Assert.That(receipt.AuthorityGeneration).IsEqualTo(0L);
            await Assert.That(receipt.WriterEpoch).IsEqualTo(0L);
            await Assert.That(receipt.Attempt).IsEqualTo(0);
            await Assert.That(await CountKeysAsync(fixture.Ledger, "direct.operation.>"))
                .IsEqualTo(0);
            await Assert.That(await CountKeysAsync(fixture.Ledger, "direct.target.>"))
                .IsEqualTo(0);
        }
    }

    private static JsonObject CorpusRoot() =>
        JsonNode.Parse(CandidateEvidenceHandoffV2VerifierTests.CorpusBytes())!.AsObject();

    private static JsonObject Payload(JsonObject root) => root["payload"]!.AsObject();

    private static JsonObject First(JsonObject parent, string name) =>
        parent[name]!.AsArray()[0]!.AsObject();

    private static async Task<RuntimeFixture> RuntimeAsync(
        CandidateEvidenceHandoffV2Envelope envelope,
        CandidateEvidenceHandoffV2AdmissionPolicy policy)
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var adapter = new DirectDeliveryProductionAdapterTests.LedgerAdapter(ledger);
        var trust = new DirectDeliveryProductionAdapterTests.HashSignature(91);
        var journal = new DirectDeliveryArtifactEvidenceJournal(adapter);
        await journal.RecordAsync(
            CandidateEvidenceHandoffV2VerifierTests.Durable(envelope),
            trust,
            default);
        var consumer = new CandidateEvidenceHandoffV2Consumer(
            journal,
            trust,
            new CandidateEvidenceHandoffV2VerifierTests.FixedSignatureVerifier(true));
        var catalog = CandidateEvidenceHandoffV2AdmissionPolicyCatalog.Create([policy]);
        return new(new(consumer, catalog), ledger);
    }

    private static async Task<int> CountKeysAsync(
        ForgejoWebhookJournalTests.TestLedger ledger,
        string filter)
    {
        var count = 0;
        await foreach (var _ in ledger.ListKeysAsync(filter, default))
            count++;
        return count;
    }

    private static string Digest(char value) => "sha256:" + new string(value, 64);

    private sealed record RuntimeFixture(
        CandidateEvidenceHandoffV2AdmissionRuntime Runtime,
        ForgejoWebhookJournalTests.TestLedger Ledger);
}

