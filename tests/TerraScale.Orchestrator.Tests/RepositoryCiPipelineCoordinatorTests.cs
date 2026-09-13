using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

public sealed class RepositoryCiPipelineCoordinatorTests
{
    private const string Repository = "TerraScale/TerraScale.Orchestrator";
    private const string BaseCommit = "affe000000000000000000000000000000000001";
    private const string Commit = "bffeb74224043ba2feb48d137756c8a9331c449a";
    private const string Tree = "117eb74224043ba2feb48d137756c8a9331c44ff";

    [Test]
    public async Task DurableTriggerPlansOnceAndRestartPerformsNoSourceReads()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var objects = new TestObjectStore();
        var triggers = new ForgejoCiTriggerJournal(ledger);
        var trigger = Trigger();
        await RecordTrigger(triggers, trigger);
        var pathReads = 0;
        var graphReads = 0;
        IReadOnlyList<string>? graphPaths = null;
        var coordinator = new RepositoryCiPipelineCoordinator(
            triggers,
            new RepositoryCiPipelineJournal(ledger, objects),
            (envelope, _) =>
            {
                pathReads++;
                return Task.FromResult<IReadOnlyList<string>>(["src/file.cs"]);
            },
            (plan, paths, _) =>
            {
                graphReads++;
                graphPaths = paths;
                return Task.FromResult(Graph());
            });

        var recorded = await Coordinate(coordinator, trigger.Envelope.DedupeKey);
        var restarted = new RepositoryCiPipelineCoordinator(
            new ForgejoCiTriggerJournal(ledger),
            new RepositoryCiPipelineJournal(ledger, objects),
            static (_, _) => throw new InvalidOperationException("unexpected path read"),
            static (_, _, _) => throw new InvalidOperationException("unexpected graph read"));
        var replay = await Coordinate(restarted, trigger.Envelope.DedupeKey);
        var changedWindow = await Coordinate(restarted, trigger.Envelope.DedupeKey, generation: 8);

        await Assert.That(recorded.Disposition)
            .IsEqualTo(RepositoryCiPipelineCoordinationDisposition.Recorded);
        await Assert.That(recorded.IsPlanned).IsTrue();
        await Assert.That(recorded.Plan!.Jobs.Count).IsEqualTo(2);
        await Assert.That(replay.Disposition)
            .IsEqualTo(RepositoryCiPipelineCoordinationDisposition.Duplicate);
        await Assert.That(replay.Plan!.Digest).IsEqualTo(recorded.Plan.Digest);
        await Assert.That(changedWindow.Disposition)
            .IsEqualTo(RepositoryCiPipelineCoordinationDisposition.IdentityConflict);
        await Assert.That(pathReads).IsEqualTo(1);
        await Assert.That(graphReads).IsEqualTo(1);
        await Assert.That(graphPaths).IsEquivalentTo(["src/file.cs"]);
        await Assert.That(objects.Count).IsEqualTo(1);
    }

    [Test]
    public async Task MissingIgnoredAndPromotionTriggersNeverResolveSources()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var objects = new TestObjectStore();
        var triggers = new ForgejoCiTriggerJournal(ledger);
        var calls = 0;
        var coordinator = new RepositoryCiPipelineCoordinator(
            triggers,
            new RepositoryCiPipelineJournal(ledger, objects),
            (_, _) =>
            {
                calls++;
                return Task.FromResult<IReadOnlyList<string>>(["src/file.cs"]);
            },
            (_, _, _) =>
            {
                calls++;
                return Task.FromResult(Graph());
            });
        var missing = Trigger(payload: new string('b', 64));
        var ignored = Trigger(sourceRef: "refs/heads/feature/test", payload: new string('c', 64));
        var promotion = Trigger(sourceRef: "refs/heads/main", payload: new string('d', 64));
        await RecordTrigger(triggers, ignored);
        await RecordTrigger(triggers, promotion);

        var missingReceipt = await Coordinate(coordinator, missing.Envelope.DedupeKey);
        var ignoredReceipt = await Coordinate(coordinator, ignored.Envelope.DedupeKey);
        var promotionReceipt = await Coordinate(coordinator, promotion.Envelope.DedupeKey);

        await Assert.That(missingReceipt.Disposition)
            .IsEqualTo(RepositoryCiPipelineCoordinationDisposition.TriggerMissing);
        await Assert.That(ignoredReceipt.Disposition)
            .IsEqualTo(RepositoryCiPipelineCoordinationDisposition.TriggerNotDispatchable);
        await Assert.That(promotionReceipt.Disposition)
            .IsEqualTo(RepositoryCiPipelineCoordinationDisposition.TriggerNotDispatchable);
        await Assert.That(calls).IsEqualTo(0);
        await Assert.That(objects.Count).IsEqualTo(0);
    }

    [Test]
    public async Task AuthorityLossAfterChangedPathsStopsBeforeGraphResolution()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var objects = new TestObjectStore();
        var triggers = new ForgejoCiTriggerJournal(ledger);
        var trigger = Trigger();
        await RecordTrigger(triggers, trigger);
        var graphReads = 0;
        var checks = 0;
        var coordinator = new RepositoryCiPipelineCoordinator(
            triggers,
            new RepositoryCiPipelineJournal(ledger, objects),
            static (_, _) => Task.FromResult<IReadOnlyList<string>>(["src/file.cs"]),
            (_, _, _) =>
            {
                graphReads++;
                return Task.FromResult(Graph());
            });

        var receipt = await Coordinate(
            coordinator,
            trigger.Envelope.DedupeKey,
            () => ++checks == 1);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiPipelineCoordinationDisposition.AuthorityLost);
        await Assert.That(receipt.Plan).IsNull();
        await Assert.That(graphReads).IsEqualTo(0);
        await Assert.That(objects.Count).IsEqualTo(0);
        await Assert.That(ledger.Mutations).IsEqualTo(1);
    }

    [Test]
    public async Task SubstitutedTriggeringSourceFailsBeforeDurablePipelineWrite()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var objects = new TestObjectStore();
        var triggers = new ForgejoCiTriggerJournal(ledger);
        var trigger = Trigger();
        await RecordTrigger(triggers, trigger);
        var substitutedCommit = new string('d', 40);
        var coordinator = new RepositoryCiPipelineCoordinator(
            triggers,
            new RepositoryCiPipelineJournal(ledger, objects),
            static (_, _) => Task.FromResult<IReadOnlyList<string>>(["src/file.cs"]),
            (_, _, _) => Task.FromResult(new RepositoryCiPipelineGraph(
                [Descriptor(substitutedCommit)],
                [new(Repository, substitutedCommit, Tree, signatureVerified: false)])));

        await Assert.That(async () => await Coordinate(coordinator, trigger.Envelope.DedupeKey))
            .Throws<ArgumentException>();
        await Assert.That(objects.Count).IsEqualTo(0);
        await Assert.That(ledger.Mutations).IsEqualTo(1);
    }

    private static Task<RepositoryCiPipelineCoordinationReceipt> Coordinate(
        RepositoryCiPipelineCoordinator coordinator,
        string dedupeKey,
        Func<bool>? authorityStillValid = null,
        long generation = 7) => coordinator.CoordinateAsync(
        dedupeKey,
        generation,
        minimumRunnerSequence: 10,
        maximumRunnerSequence: 100,
        authorityEpoch: 5,
        sequence: 11,
        authorityStillValid ?? (static () => true));

    private static Task<ForgejoCiTriggerJournalReceipt> RecordTrigger(
        ForgejoCiTriggerJournal journal,
        ForgejoCiTriggerPlan trigger) => journal.RecordAsync(
        trigger,
        authorityEpoch: 5,
        authorityRevision: 9,
        static () => true);

    private static ForgejoCiTriggerPlan Trigger(
        string sourceRef = "refs/heads/develop",
        string? payload = null) => ForgejoCiTriggerPlanner.Plan(new(
        Guid.Parse("f6266f16-1bf3-46a5-9ea4-602e06ead473"),
        ForgejoWebhookKind.Push,
        "push",
        Repository,
        Repository,
        BaseCommit,
        Commit,
        sourceRef,
        null,
        null,
        false,
        payload ?? new string('a', 64)));

    private static RepositoryCiPipelineGraph Graph() => new(
        [Descriptor(Commit)],
        [new(Repository, Commit, Tree, signatureVerified: false)]);

    private static ForgejoSourceFile Descriptor(string commit)
    {
        var content = Encoding.UTF8.GetBytes($$"""
            {
              "apiVersion":"terrascale.ci/v3",
              "repository":"{{Repository}}",
              "repositoryDependencies":[],
              "nodes":[
                {"id":"static","kind":"Static","resourceWeight":"Light","profiles":["Feature","Build"],"paths":["src/"]},
                {"id":"test","kind":"Test","resourceWeight":"Medium","profiles":["Feature","Build"],"paths":["src/"],"dependsOn":["static"]}
              ]
            }
            """);
        return new(
            Repository,
            commit,
            RepositoryCiImpactPlanner.DescriptorPath,
            Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(commit)))[..40],
            Convert.ToHexStringLower(SHA256.HashData(content)),
            content);
    }

    private sealed class TestObjectStore : IDeliveryObjectStore
    {
        private readonly Dictionary<string, byte[]> values = new(StringComparer.Ordinal);

        internal int Count => values.Count;

        public Task PutAsync(
            string name,
            ReadOnlyMemory<byte> content,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            values[name] = content.ToArray();
            return Task.CompletedTask;
        }

        public Task<byte[]> GetAsync(string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(values.TryGetValue(name, out var content)
                ? content.ToArray()
                : throw new IOException("Missing test object."));
        }
    }
}

