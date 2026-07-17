using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

public sealed class RepositoryCiQualificationCoordinatorTests
{
    private const string Repository = "TerraScale/TerraScale.Orchestrator";

    [Test]
    public async Task ExactProtectedMainTreesRecordQualificationAndReplayConverges()
    {
        var fixture = await Fixture.CreateAsync();
        var reads = 0;
        var coordinator = fixture.Coordinator((_, _) =>
        {
            reads++;
            return Task.FromResult<IReadOnlyList<ForgejoBranchObservation>>(fixture.Observations);
        });

        var recorded = await coordinator.CoordinateAsync(
            fixture.Trigger.Envelope.DedupeKey, 7, 3, static () => true);
        var replayed = await coordinator.CoordinateAsync(
            fixture.Trigger.Envelope.DedupeKey, 7, 3, static () => true);
        var recovered = await fixture.Candidates.ReadQualifiedAsync(recorded.Qualified!.Digest);

        await Assert.That(recorded.Disposition)
            .IsEqualTo(RepositoryCiQualificationCoordinationDisposition.Recorded);
        await Assert.That(replayed.Disposition)
            .IsEqualTo(RepositoryCiQualificationCoordinationDisposition.Duplicate);
        await Assert.That(recorded.IsQualified && replayed.IsQualified).IsTrue();
        await Assert.That(replayed.Qualified!.Digest).IsEqualTo(recorded.Qualified.Digest);
        await Assert.That(recovered!.Digest).IsEqualTo(recorded.Qualified.Digest);
        await Assert.That(reads).IsEqualTo(2);
        await Assert.That(fixture.Objects.Count).IsEqualTo(2);
    }

    [Test]
    public async Task MissingAndNonQualificationTriggersNeverReadMainSources()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var triggers = new ForgejoCiTriggerJournal(ledger);
        var candidates = new RepositoryCiCandidateJournal(ledger, new TestObjectStore());
        var reads = 0;
        var coordinator = new RepositoryCiQualificationCoordinator(
            triggers,
            candidates,
            (_, _) =>
            {
                reads++;
                return Task.FromResult<IReadOnlyList<ForgejoBranchObservation>>([]);
            });
        var develop = ForgejoCiTriggerPlanner.Plan(Push("refs/heads/develop", new string('d', 40)));
        await triggers.RecordAsync(develop, 7, 1, static () => true);

        var missing = await coordinator.CoordinateAsync("missing", 7, 2, static () => true);
        var notQualification = await coordinator.CoordinateAsync(
            develop.Envelope.DedupeKey, 7, 2, static () => true);

        await Assert.That(missing.Disposition)
            .IsEqualTo(RepositoryCiQualificationCoordinationDisposition.TriggerMissing);
        await Assert.That(notQualification.Disposition)
            .IsEqualTo(RepositoryCiQualificationCoordinationDisposition.TriggerNotQualification);
        await Assert.That(reads).IsEqualTo(0);
    }

    [Test]
    public async Task ExactTreesWithoutDurableCandidateRemainPending()
    {
        var fixture = await Fixture.CreateAsync(recordCandidate: false);
        var coordinator = fixture.Coordinator((_, _) =>
            Task.FromResult<IReadOnlyList<ForgejoBranchObservation>>(fixture.Observations));

        var receipt = await coordinator.CoordinateAsync(
            fixture.Trigger.Envelope.DedupeKey, 7, 2, static () => true);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiQualificationCoordinationDisposition.CandidateMissing);
        await Assert.That(receipt.Qualified).IsNull();
        await Assert.That(fixture.Ledger.Mutations).IsEqualTo(1);
        await Assert.That(fixture.Objects.Count).IsEqualTo(0);
    }

    [Test]
    public async Task AuthorityLossAfterSourceReadCreatesNoQualification()
    {
        var fixture = await Fixture.CreateAsync();
        var mutations = fixture.Ledger.Mutations;
        var objectCount = fixture.Objects.Count;
        var checks = 0;
        var coordinator = fixture.Coordinator((_, _) =>
            Task.FromResult<IReadOnlyList<ForgejoBranchObservation>>(fixture.Observations));

        var receipt = await coordinator.CoordinateAsync(
            fixture.Trigger.Envelope.DedupeKey,
            7,
            3,
            () => ++checks == 1);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiQualificationCoordinationDisposition.AuthorityLost);
        await Assert.That(receipt.Qualified).IsNull();
        await Assert.That(fixture.Ledger.Mutations).IsEqualTo(mutations);
        await Assert.That(fixture.Objects.Count).IsEqualTo(objectCount);
    }

    [Test]
    public async Task SubstitutedTriggeringMainCommitFailsBeforeQualificationWrite()
    {
        var fixture = await Fixture.CreateAsync();
        var mutations = fixture.Ledger.Mutations;
        var objectCount = fixture.Objects.Count;
        var substituted = fixture.Observations.Select(observation =>
            observation.Revision.Repository == Repository
                ? new ForgejoBranchObservation(
                    observation.Branch,
                    observation.Protected,
                    new(
                        observation.Revision.Repository,
                        new string('e', 40),
                        observation.Revision.Tree,
                        observation.Revision.SignatureVerified))
                : observation).ToArray();
        var coordinator = fixture.Coordinator((_, _) =>
            Task.FromResult<IReadOnlyList<ForgejoBranchObservation>>(substituted));

        await Assert.That(async () => await coordinator.CoordinateAsync(
                fixture.Trigger.Envelope.DedupeKey, 7, 3, static () => true))
            .Throws<InvalidDataException>();
        await Assert.That(fixture.Ledger.Mutations).IsEqualTo(mutations);
        await Assert.That(fixture.Objects.Count).IsEqualTo(objectCount);
    }

    private static ForgejoWebhookEnvelope Push(string sourceRef, string commit) => new(
        Guid.NewGuid(),
        ForgejoWebhookKind.Push,
        "push",
        Repository,
        Repository,
        new string('c', 40),
        commit,
        sourceRef,
        null,
        null,
        false,
        new string('a', 64));

    private sealed record Fixture(
        ForgejoCiTriggerPlan Trigger,
        ForgejoCiTriggerJournal Triggers,
        RepositoryCiCandidateJournal Candidates,
        ForgejoWebhookJournalTests.TestLedger Ledger,
        TestObjectStore Objects,
        ForgejoBranchObservation[] Observations)
    {
        internal RepositoryCiQualificationCoordinator Coordinator(
            Func<ForgejoCiTriggerPlan, CancellationToken, Task<IReadOnlyList<ForgejoBranchObservation>>> reader) =>
            new(Triggers, Candidates, reader);

        internal static async Task<Fixture> CreateAsync(bool recordCandidate = true)
        {
            var expected = RepositoryCiCandidateResolverTests.QualifiedCandidate();
            var triggering = expected.Sources.Single(static source => source.Repository == Repository);
            var trigger = ForgejoCiTriggerPlanner.Plan(Push("refs/heads/main", triggering.MainCommit));
            var ledger = new ForgejoWebhookJournalTests.TestLedger();
            var objects = new TestObjectStore();
            var triggers = new ForgejoCiTriggerJournal(ledger);
            var candidates = new RepositoryCiCandidateJournal(ledger, objects);
            await triggers.RecordAsync(trigger, 7, 1, static () => true);
            if (recordCandidate)
                await candidates.RecordCandidateAsync(expected.Candidate, 7, 2, static () => true);
            var observations = expected.Sources.Select(static source => new ForgejoBranchObservation(
                "main",
                true,
                new(source.Repository, source.MainCommit, source.Tree, true)))
                .ToArray();
            return new(trigger, triggers, candidates, ledger, objects, observations);
        }
    }

    private sealed class TestObjectStore : IDeliveryObjectStore
    {
        private readonly Dictionary<string, byte[]> values = new(StringComparer.Ordinal);

        internal int Count => values.Count;

        public Task PutAsync(string name, ReadOnlyMemory<byte> content, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            values[name] = content.ToArray();
            return Task.CompletedTask;
        }

        public Task<byte[]> GetAsync(string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!values.TryGetValue(name, out var content)) throw new IOException("Missing test object.");
            return Task.FromResult(content.ToArray());
        }
    }
}
