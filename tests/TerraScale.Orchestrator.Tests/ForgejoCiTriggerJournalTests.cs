using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

public sealed class ForgejoCiTriggerJournalTests
{
    [Test]
    public async Task LeaderPersistsTheExactTriggerDecisionBeforeAcknowledgement()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var envelope = Push("refs/heads/develop");
        var handler = new ForgejoCiInboxHandler(
            new(ledger),
            () => Authority(isLeader: true));

        var receipt = await handler.HandleAsync(Payload(envelope));
        var recovered = await new ForgejoCiTriggerJournal(ledger).ReadAsync(envelope.DedupeKey);

        await Assert.That(receipt.Disposition).IsEqualTo(ForgejoCiTriggerJournalDisposition.Recorded);
        await Assert.That(receipt.Plan.Disposition).IsEqualTo(ForgejoCiTriggerDisposition.Dispatch);
        await Assert.That(recovered).IsNotNull();
        await Assert.That(recovered!.Reason).IsEqualTo(ForgejoCiTriggerReason.DevelopValidation);
        await Assert.That(recovered.Capabilities).IsEquivalentTo(receipt.Plan.Capabilities);
    }

    [Test]
    public async Task IgnoredAndHeldEventsAreAlsoDurableDecisions()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new ForgejoCiTriggerJournal(ledger);
        var ignored = ForgejoCiTriggerPlanner.Plan(Push("refs/heads/feature/example"));
        var held = ForgejoCiTriggerPlanner.Plan(Push("refs/heads/main", deletion: true));

        var ignoredReceipt = await journal.RecordAsync(ignored, 7, 9, static () => true);
        var heldReceipt = await journal.RecordAsync(held, 7, 9, static () => true);

        await Assert.That(ignoredReceipt.Plan.Disposition).IsEqualTo(ForgejoCiTriggerDisposition.Ignored);
        await Assert.That(heldReceipt.Plan.Disposition).IsEqualTo(ForgejoCiTriggerDisposition.Held);
        await Assert.That(ledger.Mutations).IsEqualTo(2);
    }

    [Test]
    public async Task FollowersAndLeadershipLossCannotCommit()
    {
        var envelope = Push("refs/heads/develop");
        var followerLedger = new ForgejoWebhookJournalTests.TestLedger();
        var follower = await new ForgejoCiInboxHandler(
                new(followerLedger),
                () => Authority(isLeader: false))
            .HandleAsync(Payload(envelope));

        var lossLedger = new ForgejoWebhookJournalTests.TestLedger();
        var calls = 0;
        var lost = await new ForgejoCiInboxHandler(
                new(lossLedger),
                () => ++calls == 1 ? Authority(isLeader: true) : Authority(isLeader: false))
            .HandleAsync(Payload(envelope));

        await Assert.That(follower.Disposition).IsEqualTo(ForgejoCiTriggerJournalDisposition.StaleAuthority);
        await Assert.That(lost.Disposition).IsEqualTo(ForgejoCiTriggerJournalDisposition.StaleAuthority);
        await Assert.That(followerLedger.Mutations).IsEqualTo(0);
        await Assert.That(lossLedger.Mutations).IsEqualTo(0);
    }

    [Test]
    public async Task ConcurrentDeliveryConvergesOnOneDecision()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var plan = ForgejoCiTriggerPlanner.Plan(Push("refs/heads/develop"));
        var journal = new ForgejoCiTriggerJournal(ledger);

        var receipts = await Task.WhenAll(Enumerable.Range(0, 16).Select(_ =>
            journal.RecordAsync(plan, 7, 9, static () => true)));

        await Assert.That(receipts.Count(receipt =>
            receipt.Disposition == ForgejoCiTriggerJournalDisposition.Recorded)).IsEqualTo(1);
        await Assert.That(receipts.Count(receipt =>
            receipt.Disposition == ForgejoCiTriggerJournalDisposition.Duplicate)).IsEqualTo(15);
        await Assert.That(ledger.Mutations).IsEqualTo(1);
    }

    [Test]
    public async Task CorruptEventOrDecisionFailsClosed()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var envelope = Push("refs/heads/develop");
        var journal = new ForgejoCiTriggerJournal(ledger);
        await journal.RecordAsync(
            ForgejoCiTriggerPlanner.Plan(envelope),
            7,
            9,
            static () => true);
        ledger.CorruptFirst();

        await Assert.That(async () => await journal.ReadAsync(envelope.DedupeKey))
            .Throws<InvalidDataException>();
        await Assert.That(async () => await new ForgejoCiInboxHandler(
                new(new ForgejoWebhookJournalTests.TestLedger()),
                () => Authority(isLeader: true))
            .HandleAsync("not-json"))
            .Throws<InvalidDataException>();
    }

    private static string Payload(ForgejoWebhookEnvelope envelope) => JsonSerializer.Serialize(
        ForgejoWebhookEventDocument.From(envelope),
        ForgejoWebhookEventJsonContext.Default.ForgejoWebhookEventDocument);

    private static ForgejoWebhookEnvelope Push(string reference, bool deletion = false) => new(
        Guid.Parse("f6266f16-1bf3-46a5-9ea4-602e06ead473"),
        ForgejoWebhookKind.Push,
        "push",
        "TerraScale/TerraScale.Orchestrator",
        "TerraScale/TerraScale.Orchestrator",
        "affe000000000000000000000000000000000001",
        deletion ? new string('0', 40) : "bffeb74224043ba2feb48d137756c8a9331c449a",
        reference,
        null,
        null,
        deletion,
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes($"{reference}:{deletion}"))));

    private static RegionalAuthoritySnapshot Authority(bool isLeader) => new(
        isLeader ? "leader" : "follower",
        isLeader,
        7,
        9,
        DateTimeOffset.UtcNow.AddSeconds(10),
        DateTimeOffset.UtcNow,
        null);
}
