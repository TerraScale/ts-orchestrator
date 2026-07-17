using System.Globalization;
using System.Text;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

public sealed class RepositoryCiCandidateResolverTests
{
    private const string Repository = "TerraScale/TerraScale.Orchestrator";
    private const string Downstream = "TerraScale/Downstream";
    private const string CandidateCommit = "bffeb74224043ba2feb48d137756c8a9331c449a";
    private const string CandidateTree = "117eb74224043ba2feb48d137756c8a9331c44ff";
    private const string DownstreamCommit = "affe000000000000000000000000000000000001";
    private const string DownstreamTree = "affe000000000000000000000000000000000002";
    private const string MainCommit = "cffe000000000000000000000000000000000003";
    private const string DownstreamMainCommit = "dffe000000000000000000000000000000000004";

    internal static RepositoryCiQualifiedCandidate QualifiedCandidate() =>
        RepositoryCiCandidateResolver.Resolve(
            ForgejoCiTriggerPlanner.Plan(Push(MainCommit)),
            Candidate(),
            CurrentMain());

    [Test]
    public async Task DifferentMergeCommitsQualifyOnlyWhenEveryTestedTreeIsExact()
    {
        var candidate = Candidate();
        var trigger = ForgejoCiTriggerPlanner.Plan(Push(MainCommit));
        var current = CurrentMain();

        var first = RepositoryCiCandidateResolver.Resolve(trigger, candidate, current);
        var second = RepositoryCiCandidateResolver.Resolve(trigger, candidate, current.Reverse());

        await Assert.That(first.Id).IsEqualTo($"qualified-{first.Digest}");
        await Assert.That(first.Digest.Length).IsEqualTo(64);
        await Assert.That(first.Sources.Count).IsEqualTo(2);
        await Assert.That(first.Sources.Single(static source => source.Repository == Repository).CandidateCommit)
            .IsEqualTo(CandidateCommit);
        await Assert.That(first.Sources.Single(static source => source.Repository == Repository).MainCommit)
            .IsEqualTo(MainCommit);
        await Assert.That(first.Sources.Single(static source => source.Repository == Repository).Tree)
            .IsEqualTo(CandidateTree);
        await Assert.That(second.Digest).IsEqualTo(first.Digest);
    }

    [Test]
    public async Task AnyChangedTreeInvalidatesTheWholeReleaseSet()
    {
        var current = CurrentMain();
        current[1] = MainObservation(
            Downstream,
            DownstreamMainCommit,
            new string('e', 40));

        await Assert.That(() => RepositoryCiCandidateResolver.Resolve(
                ForgejoCiTriggerPlanner.Plan(Push(MainCommit)), Candidate(), current))
            .Throws<InvalidDataException>();
    }

    [Test]
    public async Task MissingExtraDuplicateAndUnsignedMainSourcesFailClosed()
    {
        var candidate = Candidate();
        var trigger = ForgejoCiTriggerPlanner.Plan(Push(MainCommit));
        var current = CurrentMain();
        var cases = new ForgejoBranchObservation[][]
        {
            [current[0]],
            [.. current, MainObservation("TerraScale/Extra", new string('e', 40), new string('f', 40))],
            [current[0], current[0]],
            [current[0], MainObservation(Downstream, DownstreamMainCommit, DownstreamTree, signatureVerified: false)],
            [current[0], new("main", false, new(Downstream, DownstreamMainCommit, DownstreamTree, true))],
            [current[0], new("develop", true, new(Downstream, DownstreamMainCommit, DownstreamTree, true))],
        };

        foreach (var value in cases)
            await Assert.That(() => RepositoryCiCandidateResolver.Resolve(trigger, candidate, value))
                .Throws<InvalidDataException>();
    }

    [Test]
    public async Task WebhookRevisionMustMatchTheResolvedTriggeringMainCommit()
    {
        await Assert.That(() => RepositoryCiCandidateResolver.Resolve(
                ForgejoCiTriggerPlanner.Plan(Push(new string('e', 40))),
                Candidate(),
                CurrentMain()))
            .Throws<InvalidDataException>();
    }

    [Test]
    public async Task CandidateBuildTriggerCannotEnterMainResolution()
    {
        var releaseTrigger = ForgejoCiTriggerPlanner.Plan(PullRequest());

        await Assert.That(() => RepositoryCiCandidateResolver.Resolve(
                releaseTrigger, Candidate(), CurrentMain()))
            .Throws<InvalidOperationException>();
    }

    private static RepositoryCiCandidate Candidate()
    {
        var impact = RepositoryCiImpactPlanner.Plan(
            [Descriptor(Repository), Descriptor(Downstream, Repository)],
            [new RepositoryCiChange(Repository, ["src/file.cs"])],
            RepositoryCiProfile.Release);
        var pipeline = RepositoryCiPipelinePlanner.Plan(
            ForgejoCiTriggerPlanner.Plan(PullRequest()),
            impact,
            [
                new(Repository, CandidateCommit, CandidateTree, true),
                new(Downstream, DownstreamCommit, DownstreamTree, true),
            ],
            7,
            10,
            100);
        var results = pipeline.Jobs.Select((job, index) => new RepositoryCiJobResult(
            job.Request.Job, 1, true, 0, Digest(index + 1)));
        var artifacts = pipeline.Jobs
            .Where(static job => job.Plan.Node.Kind == RepositoryCiNodeKind.Artifact)
            .Select((job, index) => new RepositoryCiArtifactResult(
                job.Request.Job,
                new($"artifact-{index}"),
                RepositoryCiArchitecture.Any,
                new(Digest(index + 100)),
                new("trusted-build-signer"),
                new($"signature-{index}"),
                true,
                null));
        return RepositoryCiCandidateAssembler.Assemble(pipeline, results, artifacts);
    }

    private static ForgejoBranchObservation[] CurrentMain() =>
    [
        MainObservation(Repository, MainCommit, CandidateTree),
        MainObservation(Downstream, DownstreamMainCommit, DownstreamTree),
    ];

    private static ForgejoBranchObservation MainObservation(
        string repository,
        string commit,
        string tree,
        bool signatureVerified = true) => new(
            "main",
            true,
            new ForgejoResolvedRevision(repository, commit, tree, signatureVerified));

    private static ForgejoWebhookEnvelope Push(string commit) => new(
        Guid.NewGuid(),
        ForgejoWebhookKind.Push,
        "push",
        Repository,
        Repository,
        commit,
        "refs/heads/main",
        null,
        null,
        false,
        new string('a', 64));

    private static ForgejoWebhookEnvelope PullRequest() => new(
        Guid.NewGuid(),
        ForgejoWebhookKind.PullRequest,
        "synchronized",
        Repository,
        Repository,
        CandidateCommit,
        "develop",
        "main",
        42,
        false,
        new string('b', 64));

    private static RepositoryCiDescriptorV2 Descriptor(string repository, string? dependency = null)
    {
        var dependencies = dependency is null
            ? string.Empty
            : $$"""{"repository":"{{dependency}}","reason":"Upstream changes require consumer validation"}""";
        return RepositoryCiDescriptor.Parse(Encoding.UTF8.GetBytes($$"""
            {
              "apiVersion":"terrascale.ci/v2",
              "repository":"{{repository}}",
              "candidateRetentionDays":7,
              "promotion":"Package",
              "repositoryDependencies":[{{dependencies}}],
              "nodes":[
                {"id":"candidate","kind":"Artifact","resourceWeight":"Heavy","profiles":["Release"],"dependsOn":["build","release-tests"]},
                {"id":"release-tests","kind":"Test","resourceWeight":"Heavy","profiles":["Release"],"dependsOn":["build"]},
                {"id":"build","kind":"Build","resourceWeight":"Heavy","profiles":["Feature","Release"],"paths":["src/"],"dependsOn":["static"]},
                {"id":"static","kind":"Static","resourceWeight":"Light","profiles":["Feature","Release"],"paths":["src/"]}
              ]
            }
            """));
    }

    private static string Digest(int value) => value.ToString("x64", CultureInfo.InvariantCulture);
}
