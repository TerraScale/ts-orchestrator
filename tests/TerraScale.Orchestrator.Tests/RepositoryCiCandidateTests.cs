using System.Globalization;
using System.Text;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

public sealed class RepositoryCiCandidateTests
{
    private const string Repository = "TerraScale/TerraScale.Orchestrator";
    private const string Commit = "bffeb74224043ba2feb48d137756c8a9331c449a";
    private const string Tree = "117eb74224043ba2feb48d137756c8a9331c44ff";

    [Test]
    public async Task CompleteReleaseEvidenceProducesOneDeterministicBuildOnceCandidate()
    {
        var pipeline = Pipeline(RepositoryCiPromotionStrategy.Package);
        var results = Results(pipeline);
        var artifacts = Artifacts(pipeline);

        var first = RepositoryCiCandidateAssembler.Assemble(pipeline, results, artifacts);
        var second = RepositoryCiCandidateAssembler.Assemble(
            pipeline,
            results.Reverse(),
            artifacts.Reverse());

        await Assert.That(first.Id).IsEqualTo($"candidate-{first.Digest}");
        await Assert.That(first.Digest.Length).IsEqualTo(64);
        await Assert.That(first.Pipeline).IsEqualTo(pipeline.Pipeline);
        await Assert.That(first.PipelineDigest).IsEqualTo(pipeline.Digest);
        await Assert.That(first.ImpactDigest).IsEqualTo(pipeline.ImpactDigest);
        await Assert.That(first.Sources).HasSingleItem();
        await Assert.That(first.Sources[0].Tree).IsEqualTo(Tree);
        await Assert.That(first.Artifacts).HasSingleItem();
        await Assert.That(first.Artifacts[0].Architecture).IsEqualTo(RepositoryCiArchitecture.Any);
        await Assert.That(second.Digest).IsEqualTo(first.Digest);
    }

    [Test]
    public async Task NativeCandidateRequiresBothArchitecturesAndExactRuntimeDigests()
    {
        var pipeline = Pipeline(RepositoryCiPromotionStrategy.NativeRolling);
        var artifacts = Artifacts(pipeline);

        var candidate = RepositoryCiCandidateAssembler.Assemble(pipeline, Results(pipeline), artifacts);

        await Assert.That(candidate.Artifacts.Select(static artifact => artifact.Architecture))
            .IsEquivalentTo([RepositoryCiArchitecture.LinuxX64, RepositoryCiArchitecture.LinuxArm64]);
        await Assert.That(candidate.Artifacts.All(static artifact =>
            artifact.ObservedRuntimeDigest == artifact.Digest)).IsTrue();

        var missingRuntime = artifacts.Select((artifact, index) => index == 0
            ? artifact with { ObservedRuntimeDigest = null }
            : artifact).ToArray();
        await Assert.That(() => RepositoryCiCandidateAssembler.Assemble(
                pipeline, Results(pipeline), missingRuntime))
            .Throws<InvalidDataException>();
    }

    [Test]
    public async Task FailedSkippedRetriedMissingAndDuplicateJobsFailQualification()
    {
        var pipeline = Pipeline(RepositoryCiPromotionStrategy.Package);
        var results = Results(pipeline);
        var cases = new[]
        {
            results[..^1],
            Replace(results, 0, results[0] with { Succeeded = false }),
            Replace(results, 0, results[0] with { RequiredTestSkips = 1 }),
            Replace(results, 0, results[0] with { Attempt = 2 }),
            Replace(results, ^1, results[0]),
        };

        foreach (var value in cases)
            await Assert.That(() => RepositoryCiCandidateAssembler.Assemble(
                    pipeline, value, Artifacts(pipeline)))
                .Throws<InvalidDataException>();
    }

    [Test]
    public async Task MissingDuplicateUnsignedAndUnexpectedArtifactsFailQualification()
    {
        var pipeline = Pipeline(RepositoryCiPromotionStrategy.Package);
        var artifacts = Artifacts(pipeline);
        var buildJob = pipeline.Jobs.Single(static job => job.Plan.Node.Kind == RepositoryCiNodeKind.Build);
        var cases = new[]
        {
            Array.Empty<RepositoryCiArtifactResult>(),
            [artifacts[0], artifacts[0]],
            [artifacts[0] with { SignatureVerified = false }],
            [artifacts[0] with { Job = buildJob.Request.Job }],
            [artifacts[0] with { ObservedRuntimeDigest = artifacts[0].Digest }],
            [artifacts[0] with { Artifact = new("../artifact") }],
        };

        foreach (var value in cases)
            await Assert.That(() => RepositoryCiCandidateAssembler.Assemble(
                    pipeline, Results(pipeline), value))
                .Throws<InvalidDataException>();
    }

    [Test]
    public async Task EvidenceOrArtifactChangeProducesAnotherCandidateIdentity()
    {
        var pipeline = Pipeline(RepositoryCiPromotionStrategy.Package);
        var results = Results(pipeline);
        var artifacts = Artifacts(pipeline);
        var first = RepositoryCiCandidateAssembler.Assemble(pipeline, results, artifacts);
        var evidenceChanged = RepositoryCiCandidateAssembler.Assemble(
            pipeline,
            Replace(results, 0, results[0] with { EvidenceDigest = Digest(900) }),
            artifacts);
        var artifactChanged = RepositoryCiCandidateAssembler.Assemble(
            pipeline,
            results,
            [artifacts[0] with { Digest = new(Digest(901)) }]);

        await Assert.That(evidenceChanged.Digest).IsNotEqualTo(first.Digest);
        await Assert.That(artifactChanged.Digest).IsNotEqualTo(first.Digest);
    }

    private static RepositoryCiPipelinePlan Pipeline(RepositoryCiPromotionStrategy strategy)
    {
        var descriptor = RepositoryCiDescriptor.Parse(Encoding.UTF8.GetBytes($$"""
            {
              "apiVersion":"terrascale.ci/v2",
              "repository":"{{Repository}}",
              "candidateRetentionDays":7,
              "promotion":"{{strategy}}",
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
        var envelope = new ForgejoWebhookEnvelope(
            Guid.Parse("f6266f16-1bf3-46a5-9ea4-602e06ead473"),
            ForgejoWebhookKind.PullRequest,
            "synchronized",
            Repository,
            Repository,
            Commit,
            "develop",
            "main",
            42,
            false,
            new string('a', 64));
        return RepositoryCiPipelinePlanner.Plan(
            ForgejoCiTriggerPlanner.Plan(envelope),
            impact,
            [new ForgejoResolvedRevision(Repository, Commit, Tree, true)],
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
                job.Request.Job,
                new($"artifact-{architecture}"),
                architecture,
                digest,
                new("trusted-build-signer"),
                new($"signature-{architecture}"),
                true,
                architecture == RepositoryCiArchitecture.Any ? null : digest);
        }))
        .ToArray();

    private static RepositoryCiJobResult[] Replace(
        RepositoryCiJobResult[] values,
        Index index,
        RepositoryCiJobResult replacement)
    {
        var copy = values.ToArray();
        copy[index] = replacement;
        return copy;
    }

    private static string Digest(int value) => value.ToString("x64", CultureInfo.InvariantCulture);
}
