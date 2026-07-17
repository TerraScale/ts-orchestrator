using System.Security.Cryptography;
using System.Text;
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
        await Assert.That(recovered.CandidateRetentionDays).IsEqualTo(7);
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
              "apiVersion":"terrascale.ci/v2",
              "repository":"{{repository}}",
              "candidateRetentionDays":7,
              "promotion":"None",
              "repositoryDependencies":[{{dependencies}}],
              "nodes":[
                {"id":"build","kind":"Build","resourceWeight":"Medium","profiles":["Feature","Release"],"paths":["src/"],"dependsOn":["static"]},
                {"id":"static","kind":"Static","resourceWeight":"Light","profiles":["Feature","Release"],"paths":["src/"]}
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

    private sealed class TestObjectStore : IDeliveryObjectStore
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
