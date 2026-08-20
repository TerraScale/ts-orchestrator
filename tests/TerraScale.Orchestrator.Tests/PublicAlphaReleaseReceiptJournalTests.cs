using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

public sealed class PublicAlphaReleaseReceiptJournalTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 19, 18, 0, 0, TimeSpan.Zero);
    private static readonly string Candidate = Digest("candidate");
    private static readonly string PreviousCandidate = Digest("previous");

    [Test]
    public async Task ReceiptSurvivesRestartAndIsRetrievedByReleaseIdentity()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var receipt = Receipt("activate", Candidate);

        var recorded = await new PublicAlphaReleaseReceiptJournal(ledger).AppendAsync(receipt);
        var recovered = await new PublicAlphaReleaseReceiptJournal(ledger).ReadAsync("release-42");

        await Assert.That(recorded.Disposition).IsEqualTo(PublicAlphaReleaseReceiptJournalDisposition.Recorded);
        await Assert.That(recovered).IsNotNull();
        await Assert.That(recovered!.Digest).IsEqualTo(receipt.Digest);
        await Assert.That(recovered.Events.Single().Decision).IsEqualTo("activate");
    }

    [Test]
    public async Task ActivationAndRollbackEventsAppendWithoutReplacingEvidence()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new PublicAlphaReleaseReceiptJournal(ledger);
        await journal.AppendAsync(Receipt("activate", Candidate));

        var appended = await journal.AppendAsync(Receipt("rollback", PreviousCandidate));
        var recovered = await new PublicAlphaReleaseReceiptJournal(ledger).ReadAsync("release-42");

        await Assert.That(appended.Disposition).IsEqualTo(PublicAlphaReleaseReceiptJournalDisposition.Recorded);
        await Assert.That(recovered!.Events.Select(static item => item.Decision))
            .IsEquivalentTo(["activate", "rollback"]);
        await Assert.That(recovered.EvidenceLinks.Select(static item => item.Digest))
            .IsEquivalentTo([Digest("evidence-activate"), Digest("evidence-rollback")]);
    }

    [Test]
    public async Task ConflictingReleaseIdentityCannotOverwriteDurableReceipt()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new PublicAlphaReleaseReceiptJournal(ledger);
        await journal.AppendAsync(Receipt("activate", Candidate));

        await Assert.That(async () => await journal.AppendAsync(
            Receipt("rollback", PreviousCandidate, configurationRevision: "config-other")))
            .Throws<InvalidDataException>();
        var recovered = await journal.ReadAsync("release-42");
        await Assert.That(recovered!.Events).HasSingleItem();
    }

    [Test]
    public async Task DuplicateAppendDoesNotCreateDuplicateEvidenceOrEvents()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new PublicAlphaReleaseReceiptJournal(ledger);
        var receipt = Receipt("activate", Candidate);
        await journal.AppendAsync(receipt);

        var duplicate = await journal.AppendAsync(receipt);
        var recovered = await journal.ReadAsync("release-42");

        await Assert.That(duplicate.Disposition).IsEqualTo(PublicAlphaReleaseReceiptJournalDisposition.Duplicate);
        await Assert.That(recovered!.EvidenceLinks.Count).IsEqualTo(1);
        await Assert.That(recovered.Events.Count).IsEqualTo(1);
    }

    [Test]
    public async Task CorruptDurableReceiptFailsClosed()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new PublicAlphaReleaseReceiptJournal(ledger);
        await journal.AppendAsync(Receipt("activate", Candidate));
        ledger.CorruptFirst();

        await Assert.That(async () => await journal.ReadAsync("release-42"))
            .Throws<InvalidDataException>();
    }

    private static PublicAlphaReleaseReceipt Receipt(
        string decision,
        string globalDigest,
        string configurationRevision = "config-7") => new(
        new(
            "release-42",
            ObjectId("source-revision"),
            Candidate,
            PreviousCandidate,
            configurationRevision,
            Digest("migrations"),
            Now - TimeSpan.FromMinutes(20)),
        [new($"gate/{decision}", Digest($"evidence-{decision}"))],
        [new(decision, decision == "activate" ? "mariogk" : "terrascale-orchestrator", Now, globalDigest)]);

    private static string Digest(string value) => $"sha256:{Convert.ToHexStringLower(
        SHA256.HashData(Encoding.UTF8.GetBytes(value)))}";

    private static string ObjectId(string value) => Digest(value)[7..];
}
