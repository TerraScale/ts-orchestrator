using System.Text.Json;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

public sealed class RepositoryCiCandidateJournalTests
{
    private static readonly DateTimeOffset RetentionStart =
        new(2026, 7, 17, 12, 0, 0, TimeSpan.Zero);

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
        await Assert.That(recovered.Candidate.CandidateRetentionDays).IsEqualTo(7);
        await Assert.That(recovered.Candidate.Artifacts).IsEquivalentTo(qualified.Candidate.Artifacts);
        await Assert.That(recovered.Sources).IsEquivalentTo(qualified.Sources);
        var lifecycle = await LifecycleAsync(ledger, qualified.Candidate.Digest);
        await Assert.That(lifecycle.State).IsEqualTo(RepositoryCiCandidateLifecycleState.Qualified);
        await Assert.That(lifecycle.QualifiedDigest).IsEqualTo(qualified.Digest);
        await Assert.That(lifecycle.RetainUntilUtc - lifecycle.CreatedAtUtc).IsEqualTo(TimeSpan.FromDays(7));
    }

    [Test]
    public async Task SignedMainTreeSetFindsTheCandidateInAnyInputOrder()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var objects = new TestObjectStore();
        var qualified = RepositoryCiCandidateResolverTests.QualifiedCandidate();
        var journal = new RepositoryCiCandidateJournal(ledger, objects);
        await journal.RecordCandidateAsync(qualified.Candidate, 7, 1, static () => true);
        var observations = MainObservations(qualified);

        var first = await journal.FindCandidateAsync(observations);
        var reversed = await journal.FindCandidateAsync(observations.Reverse());
        var missing = await journal.FindCandidateAsync(
            observations.Select((observation, index) => index == 0
                ? new ForgejoBranchObservation(
                    "main",
                    true,
                    new(
                        observation.Revision.Repository,
                        observation.Revision.Commit,
                        "effe000000000000000000000000000000000005",
                        true))
                : observation));

        await Assert.That(first!.Digest).IsEqualTo(qualified.Candidate.Digest);
        await Assert.That(reversed!.Digest).IsEqualTo(qualified.Candidate.Digest);
        await Assert.That(missing).IsNull();
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
    public async Task InterruptedTreeIndexCreationIsRepairedByAnExactRetry()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger(failOnMutation: 2);
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
        await Assert.That(await journal.FindCandidateAsync(
            candidate.Sources.Select(static source => new ForgejoBranchObservation(
                "main",
                true,
                new(source.Repository, source.Commit, source.Tree, true))))).IsNotNull();
    }

    [Test]
    public async Task InterruptedLifecycleCreationIsRepairedByAnExactRetry()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger(failOnMutation: 3);
        var objects = new TestObjectStore();
        var candidate = RepositoryCiCandidateResolverTests.QualifiedCandidate().Candidate;
        var journal = new RepositoryCiCandidateJournal(ledger, objects);

        await Assert.That(async () => await journal.RecordCandidateAsync(
                candidate, 7, 1, static () => true))
            .Throws<IOException>();
        var recovered = await journal.RecordCandidateAsync(candidate, 7, 1, static () => true);

        await Assert.That(recovered.Disposition)
            .IsEqualTo(RepositoryCiCandidateJournalDisposition.Recorded);
        await Assert.That((await LifecycleAsync(ledger, candidate.Digest)).State)
            .IsEqualTo(RepositoryCiCandidateLifecycleState.Active);
    }

    [Test]
    public async Task InterruptedQualificationResumesFromItsPreparedLifecycle()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger(failOnMutation: 5);
        var objects = new TestObjectStore();
        var qualified = RepositoryCiCandidateResolverTests.QualifiedCandidate();
        var journal = new RepositoryCiCandidateJournal(ledger, objects);
        await journal.RecordCandidateAsync(qualified.Candidate, 7, 1, static () => true);

        await Assert.That(async () => await journal.RecordQualifiedAsync(
                qualified, 7, 2, static () => true))
            .Throws<IOException>();
        await Assert.That((await LifecycleAsync(ledger, qualified.Candidate.Digest)).State)
            .IsEqualTo(RepositoryCiCandidateLifecycleState.QualificationPrepared);

        var recovered = await journal.RecordQualifiedAsync(qualified, 7, 2, static () => true);

        await Assert.That(recovered.Disposition)
            .IsEqualTo(RepositoryCiCandidateJournalDisposition.Recorded);
        await Assert.That((await LifecycleAsync(ledger, qualified.Candidate.Digest)).State)
            .IsEqualTo(RepositoryCiCandidateLifecycleState.Qualified);
    }

    [Test]
    public async Task QualifiedPointerIsInvisibleUntilItsLifecycleCommit()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger(failOnMutation: 6);
        var objects = new TestObjectStore();
        var qualified = RepositoryCiCandidateResolverTests.QualifiedCandidate();
        var journal = new RepositoryCiCandidateJournal(ledger, objects);
        await journal.RecordCandidateAsync(qualified.Candidate, 7, 1, static () => true);

        await Assert.That(async () => await journal.RecordQualifiedAsync(
                qualified, 7, 2, static () => true))
            .Throws<IOException>();
        await Assert.That(async () => await journal.ReadQualifiedAsync(qualified.Digest))
            .Throws<InvalidDataException>();

        var recovered = await journal.RecordQualifiedAsync(qualified, 7, 2, static () => true);

        await Assert.That(recovered.Disposition)
            .IsEqualTo(RepositoryCiCandidateJournalDisposition.Recorded);
        await Assert.That(await journal.ReadQualifiedAsync(qualified.Digest)).IsNotNull();
    }

    [Test]
    public async Task ExpiryDeletesOnlyAnUnqualifiedCandidateAndLeavesATombstone()
    {
        var clock = new AdjustableTimeProvider(RetentionStart);
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var objects = new TestObjectStore();
        var candidate = RepositoryCiCandidateResolverTests.QualifiedCandidate().Candidate;
        var journal = new RepositoryCiCandidateJournal(ledger, objects, clock);
        await journal.RecordCandidateAsync(candidate, 7, 1, static () => true);
        clock.Advance(TimeSpan.FromDays(7));

        var summary = await new RepositoryCiCandidateRetentionCoordinator(journal, ledger)
            .RunOnceAsync(7, 2, static () => true);

        await Assert.That(summary.Deleted).IsEqualTo(1);
        await Assert.That(summary.Deferred).IsEqualTo(0);
        await Assert.That(objects.Count).IsEqualTo(0);
        await Assert.That(await journal.ReadCandidateAsync(candidate.Digest)).IsNull();
        await Assert.That((await LifecycleAsync(ledger, candidate.Digest)).State)
            .IsEqualTo(RepositoryCiCandidateLifecycleState.Deleted);
        await Assert.That((await journal.RecordCandidateAsync(candidate, 7, 3, static () => true)).Disposition)
            .IsEqualTo(RepositoryCiCandidateJournalDisposition.IdentityConflict);

        var replay = await new RepositoryCiCandidateRetentionCoordinator(journal, ledger)
            .RunOnceAsync(7, 4, static () => true);
        await Assert.That(replay.AlreadyDeleted).IsEqualTo(1);
        await Assert.That(objects.Count).IsEqualTo(0);
    }

    [Test]
    public async Task RetentionDeadlineAndQualificationBothPreventDeletion()
    {
        var clock = new AdjustableTimeProvider(RetentionStart);
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var objects = new TestObjectStore();
        var qualified = RepositoryCiCandidateResolverTests.QualifiedCandidate();
        var journal = new RepositoryCiCandidateJournal(ledger, objects, clock);
        var retention = new RepositoryCiCandidateRetentionCoordinator(journal, ledger);
        await journal.RecordCandidateAsync(qualified.Candidate, 7, 1, static () => true);

        clock.Advance(TimeSpan.FromDays(7) - TimeSpan.FromTicks(1));
        var early = await retention.RunOnceAsync(7, 2, static () => true);
        await Assert.That(early.NotExpired).IsEqualTo(1);
        await Assert.That(await journal.ReadCandidateAsync(qualified.Candidate.Digest)).IsNotNull();

        await journal.RecordQualifiedAsync(qualified, 7, 3, static () => true);
        clock.Advance(TimeSpan.FromTicks(1));
        var retained = await retention.RunOnceAsync(7, 4, static () => true);
        await Assert.That(retained.Retained).IsEqualTo(1);
        await Assert.That(objects.Count).IsEqualTo(2);
        await Assert.That(await journal.ReadQualifiedAsync(qualified.Digest)).IsNotNull();
    }

    [Test]
    public async Task InterruptedLedgerDeletionResumesFromPreparedEvidence()
    {
        var clock = new AdjustableTimeProvider(RetentionStart);
        var ledger = new ForgejoWebhookJournalTests.TestLedger(failOnMutation: 6);
        var objects = new TestObjectStore();
        var candidate = RepositoryCiCandidateResolverTests.QualifiedCandidate().Candidate;
        var journal = new RepositoryCiCandidateJournal(ledger, objects, clock);
        await journal.RecordCandidateAsync(candidate, 7, 1, static () => true);
        clock.Advance(TimeSpan.FromDays(7));

        await Assert.That(async () => await journal.DeleteExpiredAsync(
                candidate.Digest, 7, 2, static () => true))
            .Throws<IOException>();
        await Assert.That((await LifecycleAsync(ledger, candidate.Digest)).State)
            .IsEqualTo(RepositoryCiCandidateLifecycleState.DeletionPrepared);

        var recovered = await journal.DeleteExpiredAsync(candidate.Digest, 8, 3, static () => true);
        await Assert.That(recovered.Disposition)
            .IsEqualTo(RepositoryCiCandidateRetentionDisposition.Deleted);
        await Assert.That(objects.Count).IsEqualTo(0);
    }

    [Test]
    public async Task InterruptedObjectDeletionAndFinalCommitBothResumeExactly()
    {
        var clock = new AdjustableTimeProvider(RetentionStart);
        var objectLedger = new ForgejoWebhookJournalTests.TestLedger();
        var objects = new TestObjectStore(failOnDeletion: 1);
        var candidate = RepositoryCiCandidateResolverTests.QualifiedCandidate().Candidate;
        var objectJournal = new RepositoryCiCandidateJournal(objectLedger, objects, clock);
        await objectJournal.RecordCandidateAsync(candidate, 7, 1, static () => true);
        clock.Advance(TimeSpan.FromDays(7));

        await Assert.That(async () => await objectJournal.DeleteExpiredAsync(
                candidate.Digest, 7, 2, static () => true))
            .Throws<IOException>();
        var objectRecovered = await objectJournal.DeleteExpiredAsync(
            candidate.Digest, 8, 3, static () => true);
        await Assert.That(objectRecovered.Disposition)
            .IsEqualTo(RepositoryCiCandidateRetentionDisposition.Deleted);

        var commitClock = new AdjustableTimeProvider(RetentionStart);
        var commitLedger = new ForgejoWebhookJournalTests.TestLedger(failOnMutation: 7);
        var commitObjects = new TestObjectStore();
        var commitJournal = new RepositoryCiCandidateJournal(commitLedger, commitObjects, commitClock);
        await commitJournal.RecordCandidateAsync(candidate, 7, 1, static () => true);
        commitClock.Advance(TimeSpan.FromDays(7));
        await Assert.That(async () => await commitJournal.DeleteExpiredAsync(
                candidate.Digest, 7, 2, static () => true))
            .Throws<IOException>();

        var commitRecovered = await commitJournal.DeleteExpiredAsync(
            candidate.Digest, 8, 3, static () => true);
        await Assert.That(commitRecovered.Disposition)
            .IsEqualTo(RepositoryCiCandidateRetentionDisposition.Deleted);
        await Assert.That((await LifecycleAsync(commitLedger, candidate.Digest)).State)
            .IsEqualTo(RepositoryCiCandidateLifecycleState.Deleted);
    }

    [Test]
    public async Task AuthorityLossAfterPreparationStopsBeforeAnyDeletion()
    {
        var clock = new AdjustableTimeProvider(RetentionStart);
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var objects = new TestObjectStore();
        var candidate = RepositoryCiCandidateResolverTests.QualifiedCandidate().Candidate;
        var journal = new RepositoryCiCandidateJournal(ledger, objects, clock);
        await journal.RecordCandidateAsync(candidate, 7, 1, static () => true);
        clock.Advance(TimeSpan.FromDays(7));
        var checks = 0;

        var stopped = await journal.DeleteExpiredAsync(candidate.Digest, 7, 2, () => ++checks == 1);

        await Assert.That(stopped.Disposition)
            .IsEqualTo(RepositoryCiCandidateRetentionDisposition.StaleAuthority);
        await Assert.That((await LifecycleAsync(ledger, candidate.Digest)).State)
            .IsEqualTo(RepositoryCiCandidateLifecycleState.DeletionPrepared);
        await Assert.That(objects.Count).IsEqualTo(1);
        var recovered = await journal.DeleteExpiredAsync(candidate.Digest, 8, 3, static () => true);
        await Assert.That(recovered.Disposition)
            .IsEqualTo(RepositoryCiCandidateRetentionDisposition.Deleted);
    }

    [Test]
    public async Task RetentionWorkerRunsOnlyUnderTheObservedGlobalLeader()
    {
        var clock = new AdjustableTimeProvider(RetentionStart);
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var objects = new TestObjectStore();
        var candidate = RepositoryCiCandidateResolverTests.QualifiedCandidate().Candidate;
        var journal = new RepositoryCiCandidateJournal(ledger, objects, clock);
        await journal.RecordCandidateAsync(candidate, 7, 1, static () => true);
        clock.Advance(TimeSpan.FromDays(7));
        var now = DateTimeOffset.UtcNow;
        var observed = new RegionalAuthoritySnapshot(
            "follower", false, 7, 2, now.AddMinutes(1), now, null);
        await using var worker = RepositoryCiCandidateRetentionWorker.Start(
            new(journal, ledger),
            () => observed);

        await Assert.That(await worker.SweepOnceAsync()).IsNull();
        await Assert.That(objects.Count).IsEqualTo(1);

        observed = observed with { State = "leader", IsLeader = true };
        var summary = await worker.SweepOnceAsync();

        await Assert.That(summary).IsNotNull();
        await Assert.That(summary!.Deleted).IsEqualTo(1);
        await Assert.That(objects.Count).IsEqualTo(0);
    }

    [Test]
    public async Task QualificationAndExpiryHaveExactlyOneLifecycleWinner()
    {
        var entrants = 0;
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        async Task BeforeUpdate(string key, CancellationToken cancellationToken)
        {
            if (!key.StartsWith("ci-candidate-lifecycle.", StringComparison.Ordinal) ||
                Interlocked.Increment(ref entrants) > 2)
                return;
            if (entrants == 2) release.TrySetResult();
            await release.Task.WaitAsync(TimeSpan.FromSeconds(5), cancellationToken);
        }

        var clock = new AdjustableTimeProvider(RetentionStart);
        var ledger = new ForgejoWebhookJournalTests.TestLedger(beforeUpdate: BeforeUpdate);
        var objects = new TestObjectStore();
        var qualified = RepositoryCiCandidateResolverTests.QualifiedCandidate();
        var journal = new RepositoryCiCandidateJournal(ledger, objects, clock);
        await journal.RecordCandidateAsync(qualified.Candidate, 7, 1, static () => true);
        clock.Advance(TimeSpan.FromDays(7));

        var qualificationTask = journal.RecordQualifiedAsync(qualified, 7, 2, static () => true);
        var deletionTask = journal.DeleteExpiredAsync(
            qualified.Candidate.Digest, 7, 3, static () => true);
        await Task.WhenAll(qualificationTask, deletionTask);
        var qualification = await qualificationTask;
        var deletion = await deletionTask;
        var qualificationWon =
            qualification.Disposition == RepositoryCiCandidateJournalDisposition.Recorded &&
            deletion.Disposition == RepositoryCiCandidateRetentionDisposition.Retained;
        var deletionWon =
            qualification.Disposition == RepositoryCiCandidateJournalDisposition.IdentityConflict &&
            deletion.Disposition == RepositoryCiCandidateRetentionDisposition.Deleted;

        await Assert.That(qualificationWon ^ deletionWon).IsTrue();
        var lifecycle = await LifecycleAsync(ledger, qualified.Candidate.Digest);
        await Assert.That(lifecycle.State).IsEqualTo(qualificationWon
            ? RepositoryCiCandidateLifecycleState.Qualified
            : RepositoryCiCandidateLifecycleState.Deleted);
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
        await Assert.That(ledger.Mutations).IsEqualTo(3);
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
    public async Task LookupRejectsUnprotectedUnsignedOrDuplicateSources()
    {
        var qualified = RepositoryCiCandidateResolverTests.QualifiedCandidate();
        var journal = new RepositoryCiCandidateJournal(
            new ForgejoWebhookJournalTests.TestLedger(),
            new TestObjectStore());
        var sources = MainObservations(qualified);

        await Assert.That(async () => await journal.FindCandidateAsync(
                sources.Select((source, index) => index == 0
                    ? new ForgejoBranchObservation("main", false, source.Revision)
                    : source)))
            .Throws<InvalidDataException>();
        await Assert.That(async () => await journal.FindCandidateAsync(
                [sources[0], sources[0]]))
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

    private static ForgejoBranchObservation[] MainObservations(
        RepositoryCiQualifiedCandidate qualified) => qualified.Sources
        .Select(static source => new ForgejoBranchObservation(
            "main",
            true,
            new(source.Repository, source.MainCommit, source.Tree, true)))
        .ToArray();

    private static async Task<RepositoryCiCandidateLifecycleDocument> LifecycleAsync(
        IForgejoDeliveryLedger ledger,
        string candidateDigest)
    {
        var entry = await ledger.GetAsync($"ci-candidate-lifecycle.{candidateDigest}", default)
            ?? throw new InvalidDataException("Missing candidate lifecycle test record.");
        return JsonSerializer.Deserialize(
            entry.Value,
            RepositoryCiCandidateJournalJsonContext.Default.RepositoryCiCandidateLifecycleDocument)
            ?? throw new InvalidDataException("Invalid candidate lifecycle test record.");
    }

    private sealed class TestObjectStore(int failOnDeletion = 0) :
        IDeliveryObjectStore,
        IDeliveryRetentionObjectStore
    {
        private readonly Dictionary<string, byte[]> values = new(StringComparer.Ordinal);
        private readonly object sync = new();
        private int deletionAttempts;
        private bool deletionFailed;

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

        public Task DeleteIfExistsAsync(string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (sync)
            {
                deletionAttempts++;
                if (!deletionFailed && deletionAttempts == failOnDeletion)
                {
                    deletionFailed = true;
                    throw new IOException("simulated object deletion crash");
                }
                values.Remove(name);
                return Task.CompletedTask;
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

    private sealed class AdjustableTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset value = now;

        public override DateTimeOffset GetUtcNow() => value;

        internal void Advance(TimeSpan duration) => value = value.Add(duration);
    }
}
