using System.Text.Json;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

public sealed class ForgejoSourceJournalTests
{
    private const string Repository = "TerraScale/TerraScale.Orchestrator";
    private const string CommitA = "bffeb74224043ba2feb48d137756c8a9331c449a";
    private const string CommitB = "affe000000000000000000000000000000000001";
    private const string TreeA = "117eb74224043ba2feb48d137756c8a9331c44ff";
    private const string TreeB = "affe000000000000000000000000000000000002";

    [Test]
    public async Task ExactObservationIsRecordedOncePerAuthoritySequence()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new ForgejoSourceJournal(ledger);
        var observation = Observation("develop", CommitA, TreeA);

        var recorded = await journal.ObserveAsync(observation, 4, 7);
        var duplicate = await journal.ObserveAsync(observation, 4, 7);

        await Assert.That(recorded.Disposition).IsEqualTo(ForgejoSourceJournalDisposition.Recorded);
        await Assert.That(duplicate.Disposition).IsEqualTo(ForgejoSourceJournalDisposition.Duplicate);
        await Assert.That(ledger.Mutations).IsEqualTo(1);
        await Assert.That(Document(ledger).Commit).IsEqualTo(CommitA);
    }

    [Test]
    public async Task SequenceFencesLateAndConflictingObservations()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new ForgejoSourceJournal(ledger);
        await journal.ObserveAsync(Observation("develop", CommitA, TreeA), 4, 7);

        var advanced = await journal.ObserveAsync(Observation("develop", CommitB, TreeB), 4, 8);
        var late = await journal.ObserveAsync(Observation("develop", CommitA, TreeA), 4, 7);
        var conflict = await journal.ObserveAsync(Observation("develop", CommitA, TreeA), 4, 8);

        await Assert.That(advanced.Disposition).IsEqualTo(ForgejoSourceJournalDisposition.Recorded);
        await Assert.That(late.Disposition).IsEqualTo(ForgejoSourceJournalDisposition.StaleSequence);
        await Assert.That(conflict.Disposition).IsEqualTo(ForgejoSourceJournalDisposition.IdentityConflict);
        await Assert.That(Document(ledger).Commit).IsEqualTo(CommitB);
    }

    [Test]
    public async Task NewAuthorityFencesEveryWriteFromTheOldLeader()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new ForgejoSourceJournal(ledger);
        await journal.ObserveAsync(Observation("main", CommitA, TreeA), 4, 100);

        var newLeader = await journal.ObserveAsync(Observation("main", CommitB, TreeB), 5, 1);
        var oldLeader = await journal.ObserveAsync(Observation("main", CommitA, TreeA), 4, 101);

        await Assert.That(newLeader.Disposition).IsEqualTo(ForgejoSourceJournalDisposition.Recorded);
        await Assert.That(oldLeader.Disposition).IsEqualTo(ForgejoSourceJournalDisposition.StaleAuthority);
        await Assert.That(Document(ledger).AuthorityEpoch).IsEqualTo(5);
        await Assert.That(Document(ledger).Commit).IsEqualTo(CommitB);
    }

    [Test]
    public async Task ConcurrentIdentityConflictSelectsExactlyOneObservation()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new ForgejoSourceJournal(ledger);

        var receipts = await Task.WhenAll(
            journal.ObserveAsync(Observation("develop", CommitA, TreeA), 1, 1),
            journal.ObserveAsync(Observation("develop", CommitB, TreeB), 1, 1));

        await Assert.That(receipts.Count(receipt =>
            receipt.Disposition == ForgejoSourceJournalDisposition.Recorded)).IsEqualTo(1);
        await Assert.That(receipts.Count(receipt =>
            receipt.Disposition == ForgejoSourceJournalDisposition.IdentityConflict)).IsEqualTo(1);
        await Assert.That(ledger.Mutations).IsEqualTo(1);
    }

    [Test]
    public async Task UnprotectedBranchesNeverReachTheDurableJournal()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new ForgejoSourceJournal(ledger);
        var revision = new ForgejoResolvedRevision(Repository, CommitA, TreeA, true);
        var observation = new ForgejoBranchObservation("develop", false, revision);

        var receipt = await journal.ObserveAsync(observation, 1, 1);

        await Assert.That(receipt.Disposition).IsEqualTo(ForgejoSourceJournalDisposition.UnprotectedBranch);
        await Assert.That(ledger.Mutations).IsEqualTo(0);
    }

    [Test]
    public async Task InterruptedCreateAndUpdateResumeWithTheSameFencingOrder()
    {
        var createLedger = new ForgejoWebhookJournalTests.TestLedger(1);
        var createJournal = new ForgejoSourceJournal(createLedger);
        await Assert.That(async () =>
                await createJournal.ObserveAsync(Observation("develop", CommitA, TreeA), 1, 1))
            .Throws<IOException>();
        var recoveredCreate = await new ForgejoSourceJournal(createLedger)
            .ObserveAsync(Observation("develop", CommitA, TreeA), 1, 1);

        var updateLedger = new ForgejoWebhookJournalTests.TestLedger(2);
        var updateJournal = new ForgejoSourceJournal(updateLedger);
        await updateJournal.ObserveAsync(Observation("develop", CommitA, TreeA), 1, 1);
        await Assert.That(async () =>
                await updateJournal.ObserveAsync(Observation("develop", CommitB, TreeB), 1, 2))
            .Throws<IOException>();
        var recoveredUpdate = await new ForgejoSourceJournal(updateLedger)
            .ObserveAsync(Observation("develop", CommitB, TreeB), 1, 2);

        await Assert.That(recoveredCreate.Disposition).IsEqualTo(ForgejoSourceJournalDisposition.Recorded);
        await Assert.That(recoveredUpdate.Disposition).IsEqualTo(ForgejoSourceJournalDisposition.Recorded);
        await Assert.That(Document(updateLedger).Commit).IsEqualTo(CommitB);
    }

    private static ForgejoBranchObservation Observation(string branch, string commit, string tree) =>
        new(branch, true, new ForgejoResolvedRevision(Repository, commit, tree, true));

    private static ForgejoSourceJournalDocument Document(ForgejoWebhookJournalTests.TestLedger ledger) =>
        JsonSerializer.Deserialize(
            ledger.Values.Single(),
            ForgejoSourceJournalJsonContext.Default.ForgejoSourceJournalDocument)!;
}
