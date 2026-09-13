using System.Security.Cryptography;
using System.Text;
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

    [Test]
    public async Task CurrentLeaderReconcilesEachDurablyObservedBranchWithTheSameFence()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var reconciled = new List<string>();
        await using var poller = new ForgejoSourcePoller(
            (branch, _) => Task.FromResult(Observation(branch)),
            new ForgejoSourceJournal(ledger),
            () => Authority(7),
            (observation, epoch, sequence, _) =>
            {
                reconciled.Add($"{observation.Branch}:{epoch}:{sequence}");
                return Task.FromResult(new NativeGitOpsSourceReconcileResult(
                    NativeGitOpsSourceJournalDisposition.Recorded,
                    null));
            });

        await poller.PollOnceAsync();

        await Assert.That(string.Join(',', reconciled)).IsEqualTo("develop:7:1,main:7:2");
    }

    [Test]
    public async Task DurableProtectedMainPublishesTheCompleteGlobalHandoff()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var steps = new List<string>();
        await using var poller = new ForgejoSourcePoller(
            (branch, _) => Task.FromResult(Observation(branch)),
            new ForgejoSourceJournal(ledger),
            () => Authority(7),
            (observation, _, _, _) =>
            {
                steps.Add($"reconcile:{observation.Branch}");
                return Task.FromResult(new NativeGitOpsSourceReconcileResult(
                    NativeGitOpsSourceJournalDisposition.Recorded,
                    null));
            },
            (observation, epoch, _) =>
            {
                steps.Add($"publish:{observation.Branch}:{epoch}");
                return Task.FromResult(CompletedHandoff());
            });

        await poller.PollOnceAsync();

        await Assert.That(string.Join(',', steps))
            .IsEqualTo("reconcile:develop,reconcile:main,publish:main:7");
    }

    [Test]
    public async Task AuthorityLossAtHandoffBoundaryStopsThePollCycle()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var publishes = 0;
        await using var poller = new ForgejoSourcePoller(
            (branch, _) => Task.FromResult(Observation(branch)),
            new ForgejoSourceJournal(ledger),
            () => Authority(7),
            static (_, _, _, _) => Task.FromResult(new NativeGitOpsSourceReconcileResult(
                NativeGitOpsSourceJournalDisposition.Recorded,
                null)),
            (_, _, _) =>
            {
                publishes++;
                return Task.FromResult(new NativeGitOpsGlobalHandoffCoordinationReceipt(
                    NativeGitOpsGlobalHandoffCoordinationDisposition.AuthorityLost,
                    NativeGitOpsSignedHandoffJournalDisposition.StaleAuthority,
                    null,
                    1));
            });

        await poller.PollOnceAsync();

        await Assert.That(publishes).IsEqualTo(1);
    }

    [Test]
    public async Task InitialEmptyDesiredStateHasNoUnaddressedGlobalHandoff()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var publishes = 0;
        await using var poller = new ForgejoSourcePoller(
            (branch, _) => Task.FromResult(Observation(branch)),
            new ForgejoSourceJournal(ledger),
            () => Authority(7),
            (observation, _, _, _) => Task.FromResult(new NativeGitOpsSourceReconcileResult(
                NativeGitOpsSourceJournalDisposition.Recorded,
                EmptySource(observation.Revision))),
            (_, _, _) =>
            {
                publishes++;
                return Task.FromResult(CompletedHandoff());
            });

        await poller.PollOnceAsync();

        await Assert.That(publishes).IsEqualTo(0);
    }

    private static NativeGitOpsSourcePlan EmptySource(ForgejoResolvedRevision revision)
    {
        var content = Encoding.UTF8.GetBytes(
            "{\"apiVersion\":\"terrascale.io/v1\",\"kind\":\"TerraScaleDesiredState\",\"generation\":1,\"workloads\":[]}");
        var plan = NativeGitOpsManifest.Parse(content);
        return new(
            revision,
            new(
                revision.Repository,
                revision.Commit,
                NativeGitOpsSourceLoader.ManifestPath,
                new string('c', 40),
                Convert.ToHexStringLower(SHA256.HashData(content)),
                content),
            plan,
            NativeGitOpsDiff.Compare(null, plan));
    }

    private static NativeGitOpsGlobalHandoffCoordinationReceipt CompletedHandoff()
    {
        var digest = new string('a', 64);
        var snapshot = new NativeGitOpsGlobalHandoffPublishSnapshot(
            Repository,
            "main",
            1,
            7,
            1,
            digest,
            digest,
            1,
            1,
            [new("gru", digest, 1)],
            1);
        return new(
            NativeGitOpsGlobalHandoffCoordinationDisposition.Completed,
            NativeGitOpsSignedHandoffJournalDisposition.Recorded,
            new(
                NativeGitOpsGlobalHandoffDispatchDisposition.Completed,
                NativeGitOpsGlobalHandoffPublishJournalDisposition.Recorded,
                snapshot,
                1),
            1);
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

