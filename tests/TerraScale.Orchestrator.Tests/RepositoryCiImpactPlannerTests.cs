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
    public async Task BuildGraphClosesDependenciesAndDependentsThroughArtifacts()
    {
        var descriptor = Descriptor("TerraScale/Product");

        var plan = RepositoryCiImpactPlanner.Plan(
            [descriptor],
            [new RepositoryCiChange("TerraScale/Product", ["src/product.cs"])],
            RepositoryCiProfile.Build);

        await Assert.That(string.Join(',', plan.Jobs.Select(static job => job.Node.Id)))
            .IsEqualTo("static,build,test,artifact");
        var artifact = plan.Jobs.Single(static job => job.Node.Id == "artifact");
        await Assert.That(artifact.DependsOn)
            .IsEquivalentTo(["TerraScale/Product:build", "TerraScale/Product:test"]);
        await Assert.That(artifact.Reasons).Contains("depends-on:build");
        await Assert.That(artifact.Reasons).Contains("depends-on:test");
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
            [upstream, downstream], [change], RepositoryCiProfile.Build);
        var second = RepositoryCiImpactPlanner.Plan(
            [downstream, upstream],
            [new RepositoryCiChange("TerraScale/Upstream", ["src/a.cs", "src/z.cs"])],
            RepositoryCiProfile.Build);

        await Assert.That(second.Digest).IsEqualTo(first.Digest);
        await Assert.That(second.Jobs).IsEquivalentTo(first.Jobs);
    }

    private static RepositoryCiDescriptorV2 Descriptor(
        string repository,
        (string Repository, string Reason)[]? dependencies = null)
    {
        dependencies ??= [];
        var dependencyJson = string.Join(',', dependencies.Select(static dependency =>
            $$"""{"repository":"{{dependency.Repository}}","reason":"{{dependency.Reason}}"}"""));
        return RepositoryCiDescriptor.Parse(Encoding.UTF8.GetBytes($$"""
            {
              "apiVersion":"terrascale.ci/v3",
              "repository":"{{repository}}",
              "repositoryDependencies":[{{dependencyJson}}],
              "nodes":[
                {"id":"artifact","kind":"Artifact","resourceWeight":"Heavy","profiles":["Build"],"dependsOn":["build","test"]},
                {"id":"test","kind":"Test","resourceWeight":"Heavy","profiles":["Build"],"dependsOn":["build"]},
                {"id":"build","kind":"Build","resourceWeight":"Heavy","profiles":["Feature","Build"],"paths":["src/"],"dependsOn":["static"]},
                {"id":"static","kind":"Static","resourceWeight":"Light","profiles":["Feature","Build"],"paths":["src/"]}
              ]
            }
            """));
    }
}

