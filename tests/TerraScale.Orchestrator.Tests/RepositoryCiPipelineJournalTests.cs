using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

public sealed class RepositoryCiPipelineJournalTests
{
    private const string Repository = "TerraScale/TerraScale.Orchestrator";
    private const string Downstream = "TerraScale/TerraScale.Internals";
    private const string BaseCommit = "affe000000000000000000000000000000000001";
    private const string Commit = "bffeb74224043ba2feb48d137756c8a9331c449a";
    private const string Tree = "117eb74224043ba2feb48d137756c8a9331c44ff";
    private const string DownstreamCommit = "affe000000000000000000000000000000000002";
    private const string DownstreamTree = "affe000000000000000000000000000000000003";

    [Test]
    public async Task ExactCrossRepositoryPipelineSurvivesRestart()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var objects = new TestObjectStore();
        var journal = new RepositoryCiPipelineJournal(ledger, objects);

        var recorded = await RecordAsync(journal);
        var recovered = await new RepositoryCiPipelineJournal(ledger, objects)
            .ReadAsync(Trigger().Envelope.DedupeKey);

        await Assert.That(recorded.Disposition).IsEqualTo(RepositoryCiPipelineJournalDisposition.Recorded);
        await Assert.That(recorded.Plan.Jobs.Count).IsEqualTo(4);
        await Assert.That(recorded.Plan.Jobs.Select(static job => job.Plan.Repository).Distinct())
            .IsEquivalentTo([Repository, Downstream]);
        await Assert.That(recovered).IsNotNull();
        await Assert.That(recovered!.Digest).IsEqualTo(recorded.Plan.Digest);
        await Assert.That(recovered.Jobs.Select(static job => job.Request.Job))
            .IsEquivalentTo(recorded.Plan.Jobs.Select(static job => job.Request.Job));
        await Assert.That(objects.Count).IsEqualTo(1);
        await Assert.That(ledger.Mutations).IsEqualTo(1);
    }

    [Test]
    public async Task ConcurrentExactRecordsConvergeButChangedInputsConflict()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var objects = new TestObjectStore();
        var journal = new RepositoryCiPipelineJournal(ledger, objects);

        var receipts = await Task.WhenAll(Enumerable.Range(0, 12).Select(_ => RecordAsync(journal)));
        var conflict = await RecordAsync(journal, generation: 8);

        await Assert.That(receipts.Count(receipt =>
            receipt.Disposition == RepositoryCiPipelineJournalDisposition.Recorded)).IsEqualTo(1);
        await Assert.That(receipts.Count(receipt =>
            receipt.Disposition == RepositoryCiPipelineJournalDisposition.Duplicate)).IsEqualTo(11);
        await Assert.That(conflict.Disposition).IsEqualTo(RepositoryCiPipelineJournalDisposition.IdentityConflict);
        await Assert.That(conflict.Plan.Digest).IsEqualTo(receipts[0].Plan.Digest);
        await Assert.That(ledger.Values.Count).IsEqualTo(1);
        await Assert.That(objects.Count).IsEqualTo(1);
    }

    [Test]
    public async Task InterruptedPointerWriteResumesFromTheSameContentObject()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger(failOnMutation: 1);
        var objects = new TestObjectStore();
        var journal = new RepositoryCiPipelineJournal(ledger, objects);

        await Assert.That(async () => await RecordAsync(journal)).Throws<IOException>();
        var recovered = await RecordAsync(new RepositoryCiPipelineJournal(ledger, objects));

        await Assert.That(recovered.Disposition).IsEqualTo(RepositoryCiPipelineJournalDisposition.Recorded);
        await Assert.That(objects.Count).IsEqualTo(1);
        await Assert.That(ledger.Mutations).IsEqualTo(2);
    }

    [Test]
    public async Task AuthorityLossAndCorruptContentFailClosed()
    {
        var staleLedger = new ForgejoWebhookJournalTests.TestLedger();
        var staleObjects = new TestObjectStore();
        var stale = await RecordAsync(
            new RepositoryCiPipelineJournal(staleLedger, staleObjects),
            authorityStillValid: static () => false);

        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var objects = new TestObjectStore();
        var journal = new RepositoryCiPipelineJournal(ledger, objects);
        await RecordAsync(journal);
        objects.CorruptFirst();

        await Assert.That(stale.Disposition).IsEqualTo(RepositoryCiPipelineJournalDisposition.StaleAuthority);
        await Assert.That(staleLedger.Mutations).IsEqualTo(0);
        await Assert.That(staleObjects.Count).IsEqualTo(0);
        await Assert.That(async () => await journal.ReadAsync(Trigger().Envelope.DedupeKey))
            .Throws<InvalidDataException>();
    }

    [Test]
    public async Task DescriptorMustComeFromTheExactAffectedSourceRevision()
    {
        var journal = new RepositoryCiPipelineJournal(
            new ForgejoWebhookJournalTests.TestLedger(),
            new TestObjectStore());
        var descriptors = Descriptors();
        descriptors[0] = Descriptor(Repository, BaseCommit);

        await Assert.That(async () => await journal.PlanAndRecordAsync(
                Trigger(),
                descriptors,
                [new RepositoryCiChange(Repository, ["src/file.cs"])],
                Sources(),
                7,
                10,
                100,
                5,
                9,
                static () => true))
            .Throws<InvalidDataException>();
    }

    [Test]
    public async Task RetiredSchemaTwoPipelineObjectsAreRejectedWithAnActionableError()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var objects = new TestObjectStore();
        var journal = new RepositoryCiPipelineJournal(ledger, objects);
        await WriteRetiredSchemaTwoAsync(ledger, objects);

        var exception = Failure(() => journal.ReadAsync(Trigger().Envelope.DedupeKey));

        await Assert.That(exception).IsNotNull();
        await Assert.That(exception!.Message).Contains("retired schema 2");
        await Assert.That(exception.Message).Contains("candidate-promotion stage");
        await Assert.That(exception.Message).Contains("do not retry the same delivery");
    }

    /// <summary>
    /// Fabricates exactly what a pre-reconciliation deployment wrote: a schema-2 pipeline object
    /// with its intact content digest and pointer, so the rejection is exercised end to end.
    /// </summary>
    private static async Task WriteRetiredSchemaTwoAsync(
        ForgejoWebhookJournalTests.TestLedger ledger,
        TestObjectStore objects)
    {
        var trigger = Trigger();
        var plan = RepositoryCiPipelineJournal.CreatePlan(
            trigger,
            Descriptors(),
            [new RepositoryCiChange(Repository, ["src/file.cs"])],
            Sources(),
            7,
            10,
            100);
        var document = RepositoryCiPipelineObjectDocument.From(
            trigger,
            Descriptors(),
            [new RepositoryCiChange(Repository, ["src/file.cs"])],
            Sources(),
            7,
            10,
            100,
            plan) with { SchemaVersion = 2 };
        var content = JsonSerializer.SerializeToUtf8Bytes(
            document,
            RepositoryCiPipelineJournalJsonContext.Default.RepositoryCiPipelineObjectDocument);
        var contentDigest = Convert.ToHexStringLower(SHA256.HashData(content));
        var pointer = RepositoryCiPipelinePointerDocument.From(
            trigger.Envelope.DedupeKey,
            plan.Digest,
            contentDigest,
            5,
            9);
        await objects.PutAsync(pointer.ObjectName, content, default);
        var dedupeDigest = Convert.ToHexStringLower(SHA256.HashData(
            Encoding.UTF8.GetBytes(trigger.Envelope.DedupeKey)));
        await ledger.CreateAsync(
            $"ci-pipeline.{dedupeDigest}",
            JsonSerializer.Serialize(
                pointer,
                RepositoryCiPipelineJournalJsonContext.Default.RepositoryCiPipelinePointerDocument),
            default);
    }

    [Test]
    public async Task UnanchoredPipelineHistoryIsBoundedOldestFirst()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var objects = new TestObjectStore();
        var journal = new RepositoryCiPipelineJournal(ledger, objects, pipelineHistoryCap: 2);

        foreach (var index in new[] { 1, 2, 3 })
            await RecordDistinctAsync(journal, index);

        await Assert.That(await CountPipelinesAsync(ledger)).IsEqualTo(2);
        // The two retained pointers each own one immutable pipeline object; only the oldest
        // pointer/object pair is deleted when the cap is enforced.
        await Assert.That(objects.Count).IsEqualTo(2);
        await Assert.That(objects.Deletions).IsEqualTo(1);
    }

    [Test]
    public async Task PairedTriggerAndPipelineHistoryIsBoundedNotDeadlocked()
    {
        // Normal dispatch creates a (trigger, pipeline, object) triple for every event. The two
        // journals must NOT keep each other alive forever: past the bounded-age horizon the
        // trigger anchor goes first, which frees the pipeline pointer (and its object) on the
        // next append — the paired history stays bounded and ingestion never halts.
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var objects = new TestObjectStore();
        var journal = new RepositoryCiPipelineJournal(ledger, objects, pipelineHistoryCap: 2);
        var triggers = new ForgejoCiTriggerJournal(ledger, triggerHistoryCap: 2, dispatchAnchorRevisionHorizon: 0);
        foreach (var index in new[] { 1, 2, 3 })
        {
            await triggers.RecordAsync(DistinctTrigger(index), 7, 9, static () => true);
            await RecordDistinctAsync(journal, index);
        }

        await Assert.That(await CountTriggersAsync(ledger)).IsEqualTo(2);
        await Assert.That(await CountPipelinesAsync(ledger)).IsEqualTo(2);
        await Assert.That(objects.Count).IsEqualTo(2);
        await Assert.That(objects.Deletions).IsGreaterThanOrEqualTo(1);
        await Assert.That(await triggers.ReadAsync(DistinctTrigger(1).Envelope.DedupeKey)).IsNull();
        await Assert.That(await journal.ReadAsync(DistinctTrigger(3).Envelope.DedupeKey)).IsNotNull();
    }

    [Test]
    public async Task InsideTheHorizonAnchoredPipelinesStillFailClosed()
    {
        // Before the horizon passes, a trigger-anchored pipeline is NOT prunable and the cap
        // fails closed loudly instead of growing without bound (retention overflow is
        // operational: the consumer retries, never silently drops).
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var objects = new TestObjectStore();
        var journal = new RepositoryCiPipelineJournal(ledger, objects, pipelineHistoryCap: 2);
        var triggers = new ForgejoCiTriggerJournal(ledger, dispatchAnchorRevisionHorizon: 1_000);
        foreach (var index in new[] { 1, 2, 3 })
            await triggers.RecordAsync(DistinctTrigger(index), 7, 9, static () => true);
        foreach (var index in new[] { 1, 2 })
            await RecordDistinctAsync(journal, index);

        await Assert.That(async () => await RecordDistinctAsync(journal, 3))
            .Throws<JournalRetentionOverflowException>();
        await Assert.That(await CountPipelinesAsync(ledger)).IsEqualTo(3);
    }

    [Test]
    public async Task ASharedContentObjectSurvivesASiblingPointerPrune()
    {
        // Two dedupe keys can reference the same content-addressed object. Pruning one pointer
        // must never delete the object under the other: the sibling's next read would fail its
        // integrity check deterministically.
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var objects = new TestObjectStore();
        var journal = new RepositoryCiPipelineJournal(ledger, objects, pipelineHistoryCap: 2);
        var triggers = new ForgejoCiTriggerJournal(ledger);
        await triggers.RecordAsync(DistinctTrigger(1), 7, 9, static () => true);
        await RecordDistinctAsync(journal, 1);
        var firstDedupe = DistinctTrigger(1).Envelope.DedupeKey;
        var firstKey = "ci-pipeline." + Convert.ToHexStringLower(
            SHA256.HashData(Encoding.UTF8.GetBytes(firstDedupe)));
        var sharedJson = (await ledger.GetAsync(firstKey, default))!.Value;
        var objectsBefore = objects.Count;

        // A second pointer at a different dedupe key referencing the SAME object bytes.
        var secondDedupe = DistinctTrigger(2).Envelope.DedupeKey;
        var secondKey = "ci-pipeline." + Convert.ToHexStringLower(
            SHA256.HashData(Encoding.UTF8.GetBytes(secondDedupe)));
        await ledger.CreateAsync(secondKey, sharedJson, default);

        // Recording a third pair trips the cap: the oldest PRUNABLE pointer (the unanchored
        // shared sibling) goes, but the shared object must survive for the anchored pointer.
        await triggers.RecordAsync(DistinctTrigger(3), 7, 9, static () => true);
        await RecordDistinctAsync(journal, 3);

        await Assert.That(await ledger.GetAsync(secondKey, default)).IsNull();
        await Assert.That(await ledger.GetAsync(firstKey, default)).IsNotNull();
        // The shared object survives the sibling's prune; only the third pair's OWN object was
        // added since the snapshot.
        await Assert.That(objects.Count).IsEqualTo(objectsBefore + 1);
        await Assert.That(objects.Deletions).IsEqualTo(0);
    }

    private static async Task<int> CountTriggersAsync(ForgejoWebhookJournalTests.TestLedger ledger)
    {
        var count = 0;
        await foreach (var key in ledger.ListKeysAsync("ci-trigger.>", default))
            count++;
        return count;
    }

    private static async Task<RepositoryCiPipelineJournalReceipt> RecordDistinctAsync(
        RepositoryCiPipelineJournal journal,
        int seed) => await journal.PlanAndRecordAsync(
        DistinctTrigger(seed),
        [
            Descriptor(Downstream, DownstreamCommit, Repository),
            Descriptor(Repository, SeedCommit(seed)),
        ],
        [new RepositoryCiChange(Repository, ["src/file.cs"])],
        [
            new(Downstream, DownstreamCommit, DownstreamTree, false),
            new(Repository, SeedCommit(seed), Tree, false),
        ],
        7,
        10,
        100,
        5,
        9,
        static () => true);

    private static ForgejoCiTriggerPlan DistinctTrigger(int seed) => ForgejoCiTriggerPlanner.Plan(new(
        Guid.Parse($"00000000-0000-0000-0000-{seed:d12}"),
        ForgejoWebhookKind.Push,
        "push",
        Repository,
        Repository,
        BaseCommit,
        SeedCommit(seed),
        "refs/heads/develop",
        null,
        null,
        false,
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes($"distinct:{seed}")))));

    private static string SeedCommit(int seed) =>
        seed.ToString("x40", System.Globalization.CultureInfo.InvariantCulture)
            .Replace("0", "1", StringComparison.Ordinal);

    private static async Task<int> CountPipelinesAsync(ForgejoWebhookJournalTests.TestLedger ledger)
    {
        var count = 0;
        await foreach (var key in ledger.ListKeysAsync("ci-pipeline.>", default))
            count++;
        return count;
    }

    private static InvalidDataException? Failure(Func<Task> read)
    {
        try
        {
            read().GetAwaiter().GetResult();
            return null;
        }
        catch (InvalidDataException exception)
        {
            return exception;
        }
    }

    private static Task<RepositoryCiPipelineJournalReceipt> RecordAsync(
        RepositoryCiPipelineJournal journal,
        long generation = 7,
        Func<bool>? authorityStillValid = null) => journal.PlanAndRecordAsync(
            Trigger(),
            Descriptors().Reverse(),
            [new RepositoryCiChange(Repository, ["src/file.cs"])],
            Sources().Reverse(),
            generation,
            10,
            100,
            5,
            9,
            authorityStillValid ?? (() => true));

    internal static RepositoryCiPipelinePlan Pipeline() => RepositoryCiPipelineJournal.CreatePlan(
        Trigger(),
        Descriptors(),
        [new RepositoryCiChange(Repository, ["src/file.cs"])],
        Sources(),
        7,
        10,
        100);

    private static ForgejoCiTriggerPlan Trigger() => ForgejoCiTriggerPlanner.Plan(new(
        Guid.Parse("f6266f16-1bf3-46a5-9ea4-602e06ead473"),
        ForgejoWebhookKind.Push,
        "push",
        Repository,
        Repository,
        BaseCommit,
        Commit,
        "refs/heads/develop",
        null,
        null,
        false,
        new string('a', 64)));

    private static ForgejoResolvedRevision[] Sources() =>
    [
        new(Repository, Commit, Tree, false),
        new(Downstream, DownstreamCommit, DownstreamTree, false),
    ];

    private static ForgejoSourceFile[] Descriptors() =>
    [
        Descriptor(Repository, Commit),
        Descriptor(Downstream, DownstreamCommit, Repository),
    ];

    private static ForgejoSourceFile Descriptor(string repository, string commit, string? dependency = null)
    {
        var dependencies = dependency is null
            ? string.Empty
            : $$"""{"repository":"{{dependency}}","reason":"upstream product contract"}""";
        var content = Encoding.UTF8.GetBytes($$"""
            {
              "apiVersion":"terrascale.ci/v3",
              "repository":"{{repository}}",
              "repositoryDependencies":[{{dependencies}}],
              "nodes":[
                {"id":"build","kind":"Build","resourceWeight":"Medium","profiles":["Feature","Build"],"paths":["src/"],"dependsOn":["static"]},
                {"id":"static","kind":"Static","resourceWeight":"Light","profiles":["Feature","Build"],"paths":["src/"]}
              ]
            }
            """);
        return new(
            repository,
            commit,
            RepositoryCiImpactPlanner.DescriptorPath,
            Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(repository)))[..40],
            Convert.ToHexStringLower(SHA256.HashData(content)),
            content);
    }

    private sealed class TestObjectStore : IDeliveryObjectStore, IDeliveryRetentionObjectStore
    {
        private readonly Dictionary<string, byte[]> values = new(StringComparer.Ordinal);
        private readonly object sync = new();

        internal int Count { get { lock (sync) return values.Count; } }

        public Task PutAsync(string name, ReadOnlyMemory<byte> content, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (sync) values[name] = content.ToArray();
            return Task.CompletedTask;
        }

        public Task<byte[]> GetAsync(string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (sync)
                return Task.FromResult(values.TryGetValue(name, out var content)
                    ? content.ToArray()
                    : throw new IOException("Missing test object."));
        }

        internal int Deletions { get; private set; }

        public Task DeleteIfExistsAsync(string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (sync) values.Remove(name);
            Deletions++;
            return Task.CompletedTask;
        }

        internal void RewriteFirstSchemaVersion(int schemaVersion)
        {
            lock (sync)
            {
                var name = values.Keys.Order(StringComparer.Ordinal).First();
                var node = System.Text.Json.Nodes.JsonNode.Parse(
                    System.Text.Encoding.UTF8.GetString(values[name]));
                node!["SchemaVersion"] = schemaVersion;
                values[name] = System.Text.Encoding.UTF8.GetBytes(node.ToJsonString());
            }
        }

        internal void CorruptFirst()
        {
            lock (sync)
            {
                var first = values.First();
                values[first.Key] = "corrupt"u8.ToArray();
            }
        }
    }
}

