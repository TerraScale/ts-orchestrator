using System.Text;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

public sealed class RepositoryCiImpactPlannerTests
{
    [Test]
    public async Task FeatureChangeSelectsLocalAndCrossRepositoryWorkWithReasons()
    {
        var upstream = Descriptor("TerraScale/Upstream");
        var downstream = Descriptor(
            "TerraScale/Downstream",
            [("TerraScale/Upstream", "Public runtime changes require consumer validation")]);

        var plan = RepositoryCiImpactPlanner.Plan(
            [downstream, upstream],
            [new RepositoryCiChange("TerraScale/Upstream", ["src/core/file.cs"])],
            RepositoryCiProfile.Feature);

        await Assert.That(plan.Digest.Length).IsEqualTo(64);
        await Assert.That(plan.CandidateRetentionDays).IsEqualTo(7);
        await Assert.That(plan.Jobs.Count).IsEqualTo(4);
        await Assert.That(plan.Jobs.Any(static job => job.Node.Kind is RepositoryCiNodeKind.Test or RepositoryCiNodeKind.Artifact)).IsFalse();
        var upstreamBuild = plan.Jobs.Single(static job => job.Id == "TerraScale/Upstream:build");
        await Assert.That(upstreamBuild.Reasons).Contains("changed:src/core/file.cs");
        var downstreamStatic = plan.Jobs.Single(static job => job.Id == "TerraScale/Downstream:static");
        await Assert.That(downstreamStatic.DependsOn).IsEmpty();
        var downstreamBuild = plan.Jobs.Single(static job => job.Id == "TerraScale/Downstream:build");
        await Assert.That(downstreamBuild.DependsOn)
            .IsEquivalentTo(["TerraScale/Downstream:static", "TerraScale/Upstream:build"]);
        await Assert.That(downstreamBuild.Reasons.Any(static reason =>
            reason.Contains("Public runtime changes require consumer validation", StringComparison.Ordinal))).IsTrue();
    }

    [Test]
    public async Task ReleaseGraphClosesDependenciesAndDependentsThroughCandidate()
    {
        var descriptor = Descriptor("TerraScale/Product");

        var plan = RepositoryCiImpactPlanner.Plan(
            [descriptor],
            [new RepositoryCiChange("TerraScale/Product", ["src/product.cs"])],
            RepositoryCiProfile.Release);

        await Assert.That(string.Join(',', plan.Jobs.Select(static job => job.Node.Id)))
            .IsEqualTo("static,build,release-tests,candidate");
        var candidate = plan.Jobs.Single(static job => job.Node.Id == "candidate");
        await Assert.That(candidate.DependsOn)
            .IsEquivalentTo(["TerraScale/Product:build", "TerraScale/Product:release-tests"]);
        await Assert.That(candidate.Reasons).Contains("depends-on:build");
        await Assert.That(candidate.Reasons).Contains("depends-on:release-tests");
    }

    [Test]
    public async Task CrossRepositoryPlanRetainsCandidatesForTheLongestAffectedPolicy()
    {
        var upstream = Descriptor("TerraScale/Upstream", retentionDays: 3);
        var downstream = Descriptor(
            "TerraScale/Downstream",
            [("TerraScale/Upstream", "Public runtime changes require consumer validation")],
            retentionDays: 21);

        var plan = RepositoryCiImpactPlanner.Plan(
            [upstream, downstream],
            [new RepositoryCiChange("TerraScale/Upstream", ["src/core/file.cs"])],
            RepositoryCiProfile.Release);

        await Assert.That(plan.CandidateRetentionDays).IsEqualTo(21);
    }

    [Test]
    public async Task DescriptorChangesSelectTheWholeApplicablePolicyButUnmappedPathsFail()
    {
        var descriptor = Descriptor("TerraScale/Product");
        var descriptorPlan = RepositoryCiImpactPlanner.Plan(
            [descriptor],
            [new RepositoryCiChange("TerraScale/Product", [RepositoryCiImpactPlanner.DescriptorPath])],
            RepositoryCiProfile.Feature);

        await Assert.That(descriptorPlan.Jobs.Count).IsEqualTo(2);
        await Assert.That(descriptorPlan.Jobs.All(job =>
            job.Reasons.Contains($"changed:{RepositoryCiImpactPlanner.DescriptorPath}"))).IsTrue();
        await Assert.That(() => RepositoryCiImpactPlanner.Plan(
                [descriptor],
                [new RepositoryCiChange("TerraScale/Product", ["docs/readme.md"])],
                RepositoryCiProfile.Feature))
            .Throws<InvalidDataException>();
        await Assert.That(() => new RepositoryCiChange("TerraScale/Product", ["../secret"]))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task MissingAndCyclicRepositoryDescriptorsFailClosed()
    {
        var missing = Descriptor(
            "TerraScale/Downstream",
            [("TerraScale/Missing", "Missing upstream")]);
        await Assert.That(() => RepositoryCiImpactPlanner.Plan(
                [missing],
                [new RepositoryCiChange("TerraScale/Downstream", ["src/file.cs"])],
                RepositoryCiProfile.Feature))
            .Throws<InvalidDataException>();

        var left = Descriptor("TerraScale/Left", [("TerraScale/Right", "Right feeds left")]);
        var right = Descriptor("TerraScale/Right", [("TerraScale/Left", "Left feeds right")]);
        await Assert.That(() => RepositoryCiImpactPlanner.Plan(
                [left, right],
                [new RepositoryCiChange("TerraScale/Left", ["src/file.cs"])],
                RepositoryCiProfile.Feature))
            .Throws<InvalidDataException>();
    }

    [Test]
    public async Task PlanDigestAndJobOrderAreIndependentOfInputOrder()
    {
        var upstream = Descriptor("TerraScale/Upstream");
        var downstream = Descriptor(
            "TerraScale/Downstream",
            [("TerraScale/Upstream", "Upstream compatibility")]);
        var change = new RepositoryCiChange("TerraScale/Upstream", ["src/z.cs", "src/a.cs"]);

        var first = RepositoryCiImpactPlanner.Plan(
            [upstream, downstream], [change], RepositoryCiProfile.Release);
        var second = RepositoryCiImpactPlanner.Plan(
            [downstream, upstream],
            [new RepositoryCiChange("TerraScale/Upstream", ["src/a.cs", "src/z.cs"])],
            RepositoryCiProfile.Release);

        await Assert.That(second.Digest).IsEqualTo(first.Digest);
        await Assert.That(second.Jobs).IsEquivalentTo(first.Jobs);
    }

    private static RepositoryCiDescriptorV2 Descriptor(
        string repository,
        (string Repository, string Reason)[]? dependencies = null,
        int retentionDays = 7)
    {
        dependencies ??= [];
        var dependencyJson = string.Join(',', dependencies.Select(static dependency =>
            $$"""{"repository":"{{dependency.Repository}}","reason":"{{dependency.Reason}}"}"""));
        return RepositoryCiDescriptor.Parse(Encoding.UTF8.GetBytes($$"""
            {
              "apiVersion":"terrascale.ci/v2",
              "repository":"{{repository}}",
              "candidateRetentionDays":{{retentionDays}},
              "promotion":"Package",
              "repositoryDependencies":[{{dependencyJson}}],
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
