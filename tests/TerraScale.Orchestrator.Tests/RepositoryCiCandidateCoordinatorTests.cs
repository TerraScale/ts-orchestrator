using System.Globalization;
using System.Text;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

public sealed class RepositoryCiCandidateCoordinatorTests
{
    private const string Repository = "TerraScale/TerraScale.Orchestrator";

    [Test]
    public async Task SucceededReleaseRunRecordsCandidateAndExactReplayConverges()
    {
        var pipeline = ReleasePipeline();
        var results = Results(pipeline);
        var artifacts = Artifacts(pipeline);
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var objects = new TestObjectStore();
        var artifactReads = 0;
        var coordinator = new RepositoryCiCandidateCoordinator(
            new(ledger, objects),
            (_, _) => Task.FromResult(Run(RepositoryCiPipelineRunState.Succeeded, results)),
            (_, _, _) =>
            {
                artifactReads++;
                return Task.FromResult<IReadOnlyList<RepositoryCiArtifactResult>>(artifacts);
            });

        var recorded = await coordinator.CoordinateAsync(pipeline, 7, 1, static () => true);
        var replayed = await coordinator.CoordinateAsync(pipeline, 7, 1, static () => true);
        var found = await new RepositoryCiCandidateJournal(ledger, objects).FindCandidateAsync(
            recorded.Candidate!.Sources.Select(static source => new ForgejoBranchObservation(
                "main",
                true,
                new(source.Repository, source.Commit, source.Tree, true))));

        await Assert.That(recorded.Disposition)
            .IsEqualTo(RepositoryCiCandidateCoordinationDisposition.Recorded);
        await Assert.That(replayed.Disposition)
            .IsEqualTo(RepositoryCiCandidateCoordinationDisposition.Duplicate);
        await Assert.That(recorded.IsRecorded && replayed.IsRecorded).IsTrue();
        await Assert.That(replayed.Candidate!.Digest).IsEqualTo(recorded.Candidate.Digest);
        await Assert.That(found!.Digest).IsEqualTo(recorded.Candidate.Digest);
        await Assert.That(artifactReads).IsEqualTo(2);
        await Assert.That(objects.Count).IsEqualTo(1);
    }

    [Test]
    public async Task NonReleaseActiveAndFailedRunsNeverReadArtifacts()
    {
        var release = ReleasePipeline();
        var artifactReads = 0;
        var state = RepositoryCiPipelineRunState.Active;
        var coordinator = new RepositoryCiCandidateCoordinator(
            new(new ForgejoWebhookJournalTests.TestLedger(), new TestObjectStore()),
            (_, _) => Task.FromResult(Run(state, [])),
            (_, _, _) =>
            {
                artifactReads++;
                return Task.FromResult<IReadOnlyList<RepositoryCiArtifactResult>>([]);
            });

        var feature = await coordinator.CoordinateAsync(
            RepositoryCiPipelineJournalTests.Pipeline(), 7, 1, static () => true);
        var active = await coordinator.CoordinateAsync(release, 7, 1, static () => true);
        state = RepositoryCiPipelineRunState.Failed;
        var failed = await coordinator.CoordinateAsync(release, 7, 1, static () => true);

        await Assert.That(feature.Disposition)
            .IsEqualTo(RepositoryCiCandidateCoordinationDisposition.NotReleasePipeline);
        await Assert.That(active.Disposition)
            .IsEqualTo(RepositoryCiCandidateCoordinationDisposition.PipelineActive);
        await Assert.That(failed.Disposition)
            .IsEqualTo(RepositoryCiCandidateCoordinationDisposition.PipelineFailed);
        await Assert.That(artifactReads).IsEqualTo(0);
    }

    [Test]
    public async Task AuthorityLossAfterArtifactReadStoresNothing()
    {
        var pipeline = ReleasePipeline();
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var objects = new TestObjectStore();
        var checks = 0;
        var coordinator = Coordinator(pipeline, ledger, objects, Artifacts(pipeline));

        var receipt = await coordinator.CoordinateAsync(pipeline, 7, 1, () => ++checks == 1);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiCandidateCoordinationDisposition.AuthorityLost);
        await Assert.That(receipt.Candidate).IsNull();
        await Assert.That(ledger.Mutations).IsEqualTo(0);
        await Assert.That(objects.Count).IsEqualTo(0);
    }

    [Test]
    public async Task SubstitutedArtifactFailsBeforeDurableWrite()
    {
        var pipeline = ReleasePipeline();
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var objects = new TestObjectStore();
        var artifacts = Artifacts(pipeline);
        var buildJob = pipeline.Jobs.Single(static job => job.Plan.Node.Kind == RepositoryCiNodeKind.Build);
        artifacts[0] = artifacts[0] with { Job = buildJob.Request.Job };
        var coordinator = Coordinator(pipeline, ledger, objects, artifacts);

        await Assert.That(async () => await coordinator.CoordinateAsync(
                pipeline, 7, 1, static () => true))
            .Throws<InvalidDataException>();
        await Assert.That(ledger.Mutations).IsEqualTo(0);
        await Assert.That(objects.Count).IsEqualTo(0);
    }

    private static RepositoryCiCandidateCoordinator Coordinator(
        RepositoryCiPipelinePlan pipeline,
        ForgejoWebhookJournalTests.TestLedger ledger,
        TestObjectStore objects,
        IReadOnlyList<RepositoryCiArtifactResult> artifacts) => new(
            new(ledger, objects),
            (_, _) => Task.FromResult(Run(
                RepositoryCiPipelineRunState.Succeeded,
                Results(pipeline))),
            (_, _, _) => Task.FromResult(artifacts));

    private static RepositoryCiPipelineRunSnapshot Run(
        RepositoryCiPipelineRunState state,
        IReadOnlyList<RepositoryCiJobResult> results) => new(state, [], [], results);

    internal static RepositoryCiPipelinePlan ReleasePipeline(string promotion = "Package")
    {
        var descriptor = RepositoryCiDescriptor.Parse(Encoding.UTF8.GetBytes($$"""
            {
              "apiVersion":"terrascale.ci/v2",
              "repository":"{{Repository}}",
              "candidateRetentionDays":7,
              "promotion":"{{promotion}}",
              "repositoryDependencies":[],
              "nodes":[
                {"id":"candidate","kind":"Artifact","resourceWeight":"Heavy","profiles":["Release"],"dependsOn":["build","release-tests"]},
                {"id":"release-tests","kind":"Test","resourceWeight":"Heavy","profiles":["Release"],"dependsOn":["build"]},
                {"id":"build","kind":"Build","resourceWeight":"Heavy","profiles":["Feature","Release"],"paths":["src/"],"dependsOn":["static"]},
                {"id":"static","kind":"Static","resourceWeight":"Light","profiles":["Feature","Release"],"paths":["src/"]}
              ]
            }
            """));
        var impact = RepositoryCiImpactPlanner.Plan(
            [descriptor],
            [new RepositoryCiChange(Repository, ["src/file.cs"])],
            RepositoryCiProfile.Release);
        var trigger = ForgejoCiTriggerPlanner.Plan(new ForgejoWebhookEnvelope(
            Guid.Parse("f6266f16-1bf3-46a5-9ea4-602e06ead473"),
            ForgejoWebhookKind.PullRequest,
            "synchronized",
            Repository,
            Repository,
            new string('d', 40),
            new string('b', 40),
            "develop",
            "main",
            42,
            false,
            new string('a', 64)));
        return RepositoryCiPipelinePlanner.Plan(
            trigger,
            impact,
            [new ForgejoResolvedRevision(Repository, new string('b', 40), new string('c', 40), true)],
            7,
            10,
            100);
    }

    private static RepositoryCiJobResult[] Results(RepositoryCiPipelinePlan pipeline) => pipeline.Jobs
        .Select((job, index) => new RepositoryCiJobResult(
            job.Request.Job,
            1,
            true,
            0,
            Digest(index + 1)))
        .ToArray();

    private static RepositoryCiArtifactResult[] Artifacts(RepositoryCiPipelinePlan pipeline) => pipeline.Jobs
        .Where(static job => job.Plan.Node.Kind == RepositoryCiNodeKind.Artifact)
        .SelectMany(job => job.Plan.Node.Architectures.Select((architecture, index) =>
        {
            var digest = new DigestId(Digest(index + 100));
            return new RepositoryCiArtifactResult(
                job.Plan.Repository,
                job.Plan.Promotion,
                job.Request.Job,
                new($"artifact-{architecture}"),
                architecture,
                digest,
                architecture == RepositoryCiArchitecture.Any ? [] : ["app"],
                new("trusted-build-signer"),
                new($"signature-{architecture}"),
                true,
                architecture == RepositoryCiArchitecture.Any ? null : digest);
        }))
        .ToArray();

    private static string Digest(int value) => value.ToString("x64", CultureInfo.InvariantCulture);

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
