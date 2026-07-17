using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

public sealed class ForgejoSourcePollerTests
{
    private const string Repository = "TerraScale/TerraScale.Orchestrator";
    private const string Commit = "bffeb74224043ba2feb48d137756c8a9331c449a";
    private const string Tree = "117eb74224043ba2feb48d137756c8a9331c44ff";

    [Test]
    public async Task CurrentLeaderPollsBothProtectedBranchesIntoTheFencedJournal()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var branches = new List<string>();
        await using var poller = new ForgejoSourcePoller(
            (branch, _) =>
            {
                branches.Add(branch);
                return Task.FromResult(Observation(branch));
            },
            new ForgejoSourceJournal(ledger),
            () => Authority(7));

        await poller.PollOnceAsync();

        await Assert.That(branches).IsEquivalentTo(["develop", "main"]);
        await Assert.That(ledger.Mutations).IsEqualTo(2);
        await Assert.That(ledger.Values.Count).IsEqualTo(2);
    }

    [Test]
    public async Task FollowerNeverCallsForgejoOrMutatesTheJournal()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var calls = 0;
        await using var poller = new ForgejoSourcePoller(
            (branch, _) =>
            {
                calls++;
                return Task.FromResult(Observation(branch));
            },
            new ForgejoSourceJournal(ledger),
            () => Authority(7, leader: false));

        await poller.PollOnceAsync();

        await Assert.That(calls).IsEqualTo(0);
        await Assert.That(ledger.Mutations).IsEqualTo(0);
    }

    [Test]
    public async Task LeaseChangeDuringApiReadDiscardsTheUnfencedObservation()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var authority = Authority(7);
        var calls = 0;
        await using var poller = new ForgejoSourcePoller(
            (branch, _) =>
            {
                calls++;
                authority = Authority(8, leader: false);
                return Task.FromResult(Observation(branch));
            },
            new ForgejoSourceJournal(ledger),
            () => authority);

        await poller.PollOnceAsync();

        await Assert.That(calls).IsEqualTo(1);
        await Assert.That(ledger.Mutations).IsEqualTo(0);
    }

    [Test]
    public async Task UnprotectedProductionBranchTerminatesThePollCycle()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        await using var poller = new ForgejoSourcePoller(
            (branch, _) => Task.FromResult(Observation(branch, isProtected: false)),
            new ForgejoSourceJournal(ledger),
            () => Authority(7));

        await Assert.That(async () => await poller.PollOnceAsync()).Throws<InvalidOperationException>();
        await Assert.That(ledger.Mutations).IsEqualTo(0);
    }

    [Test]
    public async Task DurableNewerAuthorityStopsAStalePollCycle()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new ForgejoSourceJournal(ledger);
        await journal.ObserveAsync(Observation("develop"), 8, 1);
        var calls = 0;
        await using var poller = new ForgejoSourcePoller(
            (branch, _) =>
            {
                calls++;
                return Task.FromResult(Observation(branch));
            },
            journal,
            () => Authority(7));

        await poller.PollOnceAsync();

        await Assert.That(calls).IsEqualTo(1);
        await Assert.That(ledger.Mutations).IsEqualTo(1);
    }

    private static ForgejoBranchObservation Observation(string branch, bool isProtected = true) =>
        new(branch, isProtected, new ForgejoResolvedRevision(Repository, Commit, Tree, true));

    private static RegionalAuthoritySnapshot Authority(long epoch, bool leader = true)
    {
        var now = DateTimeOffset.UtcNow;
        return new(
            leader ? "leader" : "follower",
            leader,
            epoch,
            epoch,
            now.AddSeconds(10),
            now,
            null);
    }
}
