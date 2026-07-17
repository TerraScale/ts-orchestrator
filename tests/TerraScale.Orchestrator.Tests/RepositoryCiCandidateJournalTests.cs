using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

public sealed class RepositoryCiCandidateJournalTests
{
    [Test]
    public async Task CandidateAndQualificationRoundTripAcrossJournalInstances()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var objects = new TestObjectStore();
        var qualified = RepositoryCiCandidateResolverTests.QualifiedCandidate();
        var journal = new RepositoryCiCandidateJournal(ledger, objects);

        var candidateReceipt = await journal.RecordCandidateAsync(
            qualified.Candidate, 7, 1, static () => true);
        var qualifiedReceipt = await journal.RecordQualifiedAsync(
            qualified, 7, 2, static () => true);
        var recovered = await new RepositoryCiCandidateJournal(ledger, objects)
            .ReadQualifiedAsync(qualified.Digest);

        await Assert.That(candidateReceipt.Disposition)
            .IsEqualTo(RepositoryCiCandidateJournalDisposition.Recorded);
        await Assert.That(qualifiedReceipt.Disposition)
            .IsEqualTo(RepositoryCiCandidateJournalDisposition.Recorded);
        await Assert.That(recovered).IsNotNull();
        await Assert.That(recovered!.Digest).IsEqualTo(qualified.Digest);
        await Assert.That(recovered.Candidate.Digest).IsEqualTo(qualified.Candidate.Digest);
        await Assert.That(recovered.Candidate.Artifacts).IsEquivalentTo(qualified.Candidate.Artifacts);
        await Assert.That(recovered.Sources).IsEquivalentTo(qualified.Sources);
    }

    [Test]
    public async Task QualificationRequiresItsExactDurableCandidate()
    {
        var qualified = RepositoryCiCandidateResolverTests.QualifiedCandidate();
        var journal = new RepositoryCiCandidateJournal(
            new ForgejoWebhookJournalTests.TestLedger(),
            new TestObjectStore());

        await Assert.That(async () => await journal.RecordQualifiedAsync(
                qualified, 7, 1, static () => true))
            .Throws<InvalidDataException>();
    }

    [Test]
    public async Task InterruptedPointerCreationResumesFromTheContentObject()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger(failOnMutation: 1);
        var objects = new TestObjectStore();
        var candidate = RepositoryCiCandidateResolverTests.QualifiedCandidate().Candidate;
        var journal = new RepositoryCiCandidateJournal(ledger, objects);

        await Assert.That(async () => await journal.RecordCandidateAsync(
                candidate, 7, 1, static () => true))
            .Throws<IOException>();
        var recovered = await new RepositoryCiCandidateJournal(ledger, objects)
            .RecordCandidateAsync(candidate, 7, 1, static () => true);

        await Assert.That(recovered.Disposition)
            .IsEqualTo(RepositoryCiCandidateJournalDisposition.Recorded);
        await Assert.That(objects.Count).IsEqualTo(1);
    }

    [Test]
    public async Task ConcurrentExactRecordsConvergeOnOnePointer()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var objects = new TestObjectStore();
        var candidate = RepositoryCiCandidateResolverTests.QualifiedCandidate().Candidate;
        var journal = new RepositoryCiCandidateJournal(ledger, objects);

        var receipts = await Task.WhenAll(Enumerable.Range(0, 16).Select(_ =>
            journal.RecordCandidateAsync(candidate, 7, 1, static () => true)));

        await Assert.That(receipts.Count(receipt =>
            receipt.Disposition == RepositoryCiCandidateJournalDisposition.Recorded)).IsEqualTo(1);
        await Assert.That(receipts.Count(receipt =>
            receipt.Disposition == RepositoryCiCandidateJournalDisposition.Duplicate)).IsEqualTo(15);
        await Assert.That(ledger.Mutations).IsEqualTo(1);
    }

    [Test]
    public async Task LostAuthorityCannotCommitEvenAfterContentStorage()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var objects = new TestObjectStore();
        var candidate = RepositoryCiCandidateResolverTests.QualifiedCandidate().Candidate;
        var journal = new RepositoryCiCandidateJournal(ledger, objects);
        var checks = 0;

        var receipt = await journal.RecordCandidateAsync(
            candidate,
            7,
            1,
            () => ++checks == 1);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiCandidateJournalDisposition.StaleAuthority);
        await Assert.That(ledger.Mutations).IsEqualTo(0);
        await Assert.That(objects.Count).IsEqualTo(1);
    }

    [Test]
    public async Task CorruptContentAndPointerFailClosed()
    {
        var candidate = RepositoryCiCandidateResolverTests.QualifiedCandidate().Candidate;
        var contentLedger = new ForgejoWebhookJournalTests.TestLedger();
        var objects = new TestObjectStore();
        var journal = new RepositoryCiCandidateJournal(contentLedger, objects);
        await journal.RecordCandidateAsync(candidate, 7, 1, static () => true);
        objects.CorruptFirst();

        await Assert.That(async () => await journal.ReadCandidateAsync(candidate.Digest))
            .Throws<InvalidDataException>();

        var pointerLedger = new ForgejoWebhookJournalTests.TestLedger();
        var pointerJournal = new RepositoryCiCandidateJournal(pointerLedger, new TestObjectStore());
        await pointerJournal.RecordCandidateAsync(candidate, 7, 1, static () => true);
        pointerLedger.CorruptFirst();
        await Assert.That(async () => await pointerJournal.ReadCandidateAsync(candidate.Digest))
            .Throws<InvalidDataException>();
    }

    [Test]
    public async Task GlobalTopologySeparatesBoundedPointersFromLargeCandidateObjects()
    {
        var topology = new GlobalNatsTopology(3);

        await Assert.That(topology.Releases.MaxValueSize).IsEqualTo(16 * 1024);
        await Assert.That(topology.Bundles.Bucket).IsEqualTo("GLOBAL_BUNDLES");
        await Assert.That(topology.Bundles.MaxBytes).IsEqualTo(1024L * 1024 * 1024);
        await Assert.That(topology.Bundles.NumberOfReplicas).IsEqualTo(3);
    }

    private sealed class TestObjectStore : INativeGitOpsManifestStore
    {
        private readonly Dictionary<string, byte[]> values = new(StringComparer.Ordinal);
        private readonly object sync = new();

        internal int Count { get { lock (sync) return values.Count; } }

        public Task PutAsync(
            string name,
            ReadOnlyMemory<byte> content,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (sync) values[name] = content.ToArray();
            return Task.CompletedTask;
        }

        public Task<byte[]> GetAsync(string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (sync)
            {
                if (!values.TryGetValue(name, out var content)) throw new IOException("Missing test object.");
                return Task.FromResult(content.ToArray());
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
