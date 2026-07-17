using System.Text;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

public sealed class RepositoryCiPipelinePlannerTests
{
    private const string Repository = "TerraScale/TerraScale.Orchestrator";
    private const string Downstream = "TerraScale/Downstream";
    private const string Commit = "bffeb74224043ba2feb48d137756c8a9331c449a";
    private const string Tree = "117eb74224043ba2feb48d137756c8a9331c44ff";
    private const string DownstreamCommit = "affe000000000000000000000000000000000001";
    private const string DownstreamTree = "affe000000000000000000000000000000000002";

    [Test]
    public async Task FeatureDagCreatesOnlyLeastPrivilegeUntrustedJobs()
    {
        var trigger = ForgejoCiTriggerPlanner.Plan(PullRequest("feature/native-ci", "develop"));
        var impact = Impact(RepositoryCiProfile.Feature);

        var pipeline = RepositoryCiPipelinePlanner.Plan(
            trigger,
            impact,
            Sources(signatureVerified: false),
            7,
            10,
            100);

        await Assert.That(pipeline.Profile).IsEqualTo(RepositoryCiProfile.Feature);
        await Assert.That(pipeline.Digest.Length).IsEqualTo(64);
        await Assert.That(pipeline.Jobs.Count).IsEqualTo(4);
        await Assert.That(pipeline.Jobs.All(static job => job.Request.Kind == JobKind.ProductValidation)).IsTrue();
        await Assert.That(pipeline.Jobs.All(static job => job.Request.AllowedZones
            .SequenceEqual([TrustZone.UntrustedProduct]))).IsTrue();
        await Assert.That(pipeline.Jobs.SelectMany(static job => job.Request.RequiredCapabilities)
            .All(static capability => capability is RunnerCapability.Compile or RunnerCapability.Test)).IsTrue();
        await Assert.That(pipeline.Jobs.All(static job => !job.MayPublishCandidateArtifact)).IsTrue();
        foreach (var job in pipeline.Jobs)
        {
            var decision = DeliveryEngine.DecideJob(
                job.Request,
                [new(new($"runner-{job.Plan.Node.Id}"), TrustZone.UntrustedProduct, 20, true,
                    job.Request.RequiredCapabilities)],
                96);
            await Assert.That(decision.Errors).IsEmpty();
        }
    }

    [Test]
    public async Task ReleaseDagSignsCandidateWithoutProductionCapabilities()
    {
        var trigger = ForgejoCiTriggerPlanner.Plan(PullRequest("develop", "main"));
        var impact = Impact(RepositoryCiProfile.Release);

        var pipeline = RepositoryCiPipelinePlanner.Plan(trigger, impact, Sources(), 8, 10, 100);

        await Assert.That(pipeline.Jobs.Count).IsEqualTo(8);
        await Assert.That(pipeline.Jobs.All(static job => job.Request.Kind == JobKind.TrustedBuild)).IsTrue();
        await Assert.That(pipeline.Jobs.All(static job => job.Request.AllowedZones
            .SequenceEqual([TrustZone.TrustedBuild]))).IsTrue();
        await Assert.That(pipeline.Jobs.SelectMany(static job => job.Request.RequiredCapabilities))
            .DoesNotContain(RunnerCapability.Promote);
        await Assert.That(pipeline.Jobs.SelectMany(static job => job.Request.RequiredCapabilities))
            .DoesNotContain(RunnerCapability.ProductionDeploy);
        var artifacts = pipeline.Jobs.Where(static job => job.Plan.Node.Kind == RepositoryCiNodeKind.Artifact).ToArray();
        await Assert.That(artifacts.Length).IsEqualTo(2);
        await Assert.That(artifacts.All(static job => job.MayPublishCandidateArtifact)).IsTrue();
        await Assert.That(artifacts.All(static job => job.Request.RequiredCapabilities
            .SequenceEqual([RunnerCapability.Compile, RunnerCapability.Sign]))).IsTrue();
        foreach (var job in pipeline.Jobs)
        {
            var decision = DeliveryEngine.DecideJob(
                job.Request,
                [new(new($"runner-{job.Plan.Node.Id}"), TrustZone.TrustedBuild, 20, true,
                    job.Request.RequiredCapabilities)],
                96);
            await Assert.That(decision.Errors).IsEmpty();
        }
    }

    [Test]
    public async Task EveryDagEdgeMapsToTheExactDeterministicJobIdentity()
    {
        var trigger = ForgejoCiTriggerPlanner.Plan(PullRequest("feature/native-ci", "develop"));
        var impact = Impact(RepositoryCiProfile.Feature);

        var first = RepositoryCiPipelinePlanner.Plan(trigger, impact, Sources(false), 7, 10, 100);
        var second = RepositoryCiPipelinePlanner.Plan(
            trigger,
            impact,
            Sources(false).Reverse(),
            7,
            10,
            100);

        await Assert.That(second.Digest).IsEqualTo(first.Digest);
        await Assert.That(second.Jobs.Select(static job => job.Request.Job))
            .IsEquivalentTo(first.Jobs.Select(static job => job.Request.Job));
        var downstreamBuild = first.Jobs.Single(static job => job.Plan.Id == $"{Downstream}:build");
        var expected = first.Jobs.Where(job => job.Plan.Id is $"{Downstream}:static" or $"{Repository}:build")
            .Select(static job => job.Request.Job)
            .ToArray();
        await Assert.That(downstreamBuild.DependsOn).IsEquivalentTo(expected);
        await Assert.That(first.Jobs.Select(static job => job.Request.Idempotency).Distinct().Count())
            .IsEqualTo(first.Jobs.Count);
    }

    [Test]
    public async Task MismatchedUnsignedOrIncompleteSourceSetsFailClosed()
    {
        var releaseTrigger = ForgejoCiTriggerPlanner.Plan(PullRequest("develop", "main"));
        var releaseImpact = Impact(RepositoryCiProfile.Release);
        await Assert.That(() => RepositoryCiPipelinePlanner.Plan(
                releaseTrigger, releaseImpact, Sources(signatureVerified: false), 8, 10, 100))
            .Throws<InvalidOperationException>();
        await Assert.That(() => RepositoryCiPipelinePlanner.Plan(
                releaseTrigger, releaseImpact, [Resolved(Repository, Commit, Tree)], 8, 10, 100))
            .Throws<ArgumentException>();
        await Assert.That(() => RepositoryCiPipelinePlanner.Plan(
                releaseTrigger,
                releaseImpact,
                [Resolved(Repository, new string('a', 40), Tree), Resolved(Downstream, DownstreamCommit, DownstreamTree)],
                8,
                10,
                100))
            .Throws<ArgumentException>();
        await Assert.That(() => RepositoryCiPipelinePlanner.Plan(
                releaseTrigger, Impact(RepositoryCiProfile.Feature), Sources(), 8, 10, 100))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task MainPromotionCannotReenterTheBuildPipeline()
    {
        var trigger = ForgejoCiTriggerPlanner.Plan(new ForgejoWebhookEnvelope(
            Guid.NewGuid(),
            ForgejoWebhookKind.Push,
            "push",
            Repository,
            Repository,
            Commit,
            "refs/heads/main",
            null,
            null,
            false,
            new string('a', 64)));

        await Assert.That(() => RepositoryCiPipelinePlanner.Plan(
                trigger, Impact(RepositoryCiProfile.Release), Sources(), 9, 10, 100))
            .Throws<InvalidOperationException>();
    }

    private static RepositoryCiImpactPlan Impact(RepositoryCiProfile profile) =>
        RepositoryCiImpactPlanner.Plan(
            [Descriptor(Repository), Descriptor(Downstream, Repository)],
            [new RepositoryCiChange(Repository, ["src/file.cs"])],
            profile);

    private static ForgejoResolvedRevision[] Sources(bool signatureVerified = true) =>
    [
        Resolved(Repository, Commit, Tree, signatureVerified),
        Resolved(Downstream, DownstreamCommit, DownstreamTree, signatureVerified),
    ];

    private static ForgejoResolvedRevision Resolved(
        string repository,
        string commit,
        string tree,
        bool signatureVerified = true) => new(repository, commit, tree, signatureVerified);

    private static ForgejoWebhookEnvelope PullRequest(string sourceRef, string targetRef) => new(
        Guid.NewGuid(),
        ForgejoWebhookKind.PullRequest,
        "synchronized",
        Repository,
        Repository,
        Commit,
        sourceRef,
        targetRef,
        42,
        false,
        new string('a', 64));

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
}
