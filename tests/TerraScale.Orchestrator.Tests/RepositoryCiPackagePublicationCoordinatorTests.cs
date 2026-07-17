using System.Globalization;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

[SupportedOSPlatform("linux")]
public sealed class RepositoryCiPackagePublicationCoordinatorTests
{
    private const string Repository = "TerraScale/TerraScale.Orchestrator";

    [Test]
    public async Task ExactQualifiedArchivePublishesOnceAndReplaysWithStableEvidence()
    {
        var fixture = Fixture.Create();
        var publisher = new TestPublisher(
            ForgejoGenericPackagePublicationDisposition.Recorded,
            ForgejoGenericPackagePublicationDisposition.Duplicate);
        var coordinator = fixture.Coordinator(publisher);

        var published = await coordinator.PublishAsync(fixture.Qualified, static () => true);
        var replay = await coordinator.PublishAsync(fixture.Qualified, static () => true);

        await Assert.That(published.Disposition)
            .IsEqualTo(RepositoryCiPackagePublicationDisposition.Published);
        await Assert.That(replay.Disposition)
            .IsEqualTo(RepositoryCiPackagePublicationDisposition.Duplicate);
        await Assert.That(published.EvidenceDigest.Length).IsEqualTo(64);
        await Assert.That(replay.EvidenceDigest).IsEqualTo(published.EvidenceDigest);
        await Assert.That(published.Packages).HasSingleItem();
        await Assert.That(published.Packages[0].Repository).IsEqualTo(Repository);
        await Assert.That(published.Packages[0].Package).IsEqualTo("ci-terrascale.orchestrator");
        await Assert.That(published.Packages[0].Version).IsEqualTo(fixture.Qualified.Candidate.Digest);
        await Assert.That(publisher.Calls.Count).IsEqualTo(2);
        await Assert.That(publisher.Calls.All(call => call.Content.SequenceEqual(fixture.Archive))).IsTrue();
    }

    [Test]
    public async Task CorruptDurableArchiveFailsBeforeAnyPublication()
    {
        var fixture = Fixture.Create();
        fixture.Store.Values[fixture.ArtifactObject][0] ^= 1;
        var publisher = new TestPublisher(ForgejoGenericPackagePublicationDisposition.Recorded);

        var receipt = await fixture.Coordinator(publisher)
            .PublishAsync(fixture.Qualified, static () => true);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiPackagePublicationDisposition.InvalidEvidence);
        await Assert.That(receipt.EvidenceDigest).IsEmpty();
        await Assert.That(publisher.Calls).IsEmpty();
    }

    [Test]
    public async Task PagesCandidateIsNotMisclassifiedAsAGenericPackage()
    {
        var fixture = Fixture.Create("Pages");
        var publisher = new TestPublisher(ForgejoGenericPackagePublicationDisposition.Recorded);

        var receipt = await fixture.Coordinator(publisher)
            .PublishAsync(fixture.Qualified, static () => true);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiPackagePublicationDisposition.NotApplicable);
        await Assert.That(publisher.Calls).IsEmpty();
    }

    [Test]
    public async Task NativeCandidatePublishesItsMultiArchitectureArchive()
    {
        var fixture = Fixture.Create("NativeOrdered");
        var publisher = new TestPublisher(ForgejoGenericPackagePublicationDisposition.Recorded);

        var receipt = await fixture.Coordinator(publisher)
            .PublishAsync(fixture.Qualified, static () => true);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiPackagePublicationDisposition.Published);
        await Assert.That(receipt.Packages).HasSingleItem();
        await Assert.That(publisher.Calls[0].Content.SequenceEqual(fixture.Archive)).IsTrue();
    }

    [Test]
    public async Task MissingAuthorityCannotReadOrPublishTheArchive()
    {
        var fixture = Fixture.Create();
        var publisher = new TestPublisher(ForgejoGenericPackagePublicationDisposition.Recorded);

        var receipt = await fixture.Coordinator(publisher)
            .PublishAsync(fixture.Qualified, static () => false);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiPackagePublicationDisposition.StaleAuthority);
        await Assert.That(publisher.Calls).IsEmpty();
    }

    [Test]
    public async Task ImmutableRemoteIdentityConflictFailsClosed()
    {
        var fixture = Fixture.Create();
        var publisher = new TestPublisher(ForgejoGenericPackagePublicationDisposition.IdentityConflict);

        var receipt = await fixture.Coordinator(publisher)
            .PublishAsync(fixture.Qualified, static () => true);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiPackagePublicationDisposition.IdentityConflict);
        await Assert.That(receipt.EvidenceDigest).IsEmpty();
        await Assert.That(publisher.Calls).HasSingleItem();
    }

    private sealed record Fixture(
        RepositoryCiQualifiedCandidate Qualified,
        TestObjectStore Store,
        byte[] Archive,
        string ArtifactObject)
    {
        internal static Fixture Create(string promotion = "Package")
        {
            var pipeline = RepositoryCiCandidateCoordinatorTests.ReleasePipeline(promotion);
            var planned = pipeline.Jobs.Single(static value =>
                value.Plan.Node.Kind == RepositoryCiNodeKind.Artifact);
            var archive = "canonical package archive"u8.ToArray();
            var outputDigest = Digest(100);
            var workload = new CiRunnerWorkloadEvidence(
                1,
                "trusted-package-runner",
                pipeline.Digest,
                planned.Request.Job.Value,
                Digest(102),
                Digest(103),
                Digest(104),
                Digest(105),
                10,
                11,
                1,
                1,
                Digest(106),
                Digest(107),
                Digest(108),
                Digest(109),
                CiRunnerBuildKitExecutionDisposition.Succeeded,
                0,
                Hash([]),
                0,
                Digest(110),
                outputDigest,
                planned.Plan.Node.Architectures.Count,
                1024,
                true,
                RepositoryCiJobFailureKind.Unspecified,
                CiRunnerWorkloadFailureCode.Unspecified);
            var artifactObject = $"ci-result-artifact-{outputDigest}";
            var declarations = planned.Plan.Node.Architectures.Select((architecture, index) => new
                CiRunnerStoredArtifactEvidence(
                    $"release-{architecture}",
                    architecture,
                    architecture == RepositoryCiArchitecture.Any
                        ? "package"
                        : architecture.ToString().ToLowerInvariant(),
                    Digest(101 + index),
                    1,
                    256,
                    architecture == RepositoryCiArchitecture.Any ? [] : ["app"])).ToArray();
            var stored = new CiRunnerStoredWorkloadEvidence(
                2,
                workload,
                $"ci-result-log-{workload.LogSha256}",
                workload.LogSha256,
                0,
                artifactObject,
                Hash(archive),
                archive.LongLength,
                declarations,
                0,
                CiRunnerDurableResultSink.RetentionDays);
            var evidenceContent = JsonSerializer.SerializeToUtf8Bytes(
                stored,
                CiRunnerDurableResultJsonContext.Default.CiRunnerStoredWorkloadEvidence);
            var evidenceDigest = Hash(evidenceContent);
            var results = pipeline.Jobs.Select((job, index) => new RepositoryCiJobResult(
                job.Request.Job,
                1,
                true,
                0,
                job == planned ? evidenceDigest : Digest(200 + index))).ToArray();
            var artifacts = declarations.Select(declaration =>
            {
                var digest = new DigestId(declaration.Digest);
                return new RepositoryCiArtifactResult(
                    planned.Plan.Repository,
                    planned.Plan.Promotion,
                    planned.Request.Job,
                    new(declaration.Artifact),
                    declaration.Architecture,
                    digest,
                    declaration.Entrypoints,
                    new("trusted-build-signer"),
                    new($"release-{declaration.Architecture}-signature"),
                    true,
                    declaration.Architecture == RepositoryCiArchitecture.Any ? null : digest);
            }).ToArray();
            var candidate = RepositoryCiCandidateAssembler.Assemble(pipeline, results, artifacts);
            var source = candidate.Sources.Single();
            var trigger = ForgejoCiTriggerPlanner.Plan(new ForgejoWebhookEnvelope(
                Guid.Parse("21fdbeb4-e903-4ff8-a3bc-73e56399c252"),
                ForgejoWebhookKind.Push,
                "push",
                source.Repository,
                source.Repository,
                new string('d', 40),
                source.Commit,
                "refs/heads/main",
                null,
                null,
                false,
                new string('a', 64)));
            var qualified = RepositoryCiCandidateResolver.Resolve(
                trigger,
                candidate,
                [new ForgejoBranchObservation(
                    "main",
                    true,
                    new(source.Repository, source.Commit, source.Tree, true))]);
            var store = new TestObjectStore();
            store.Values[$"ci-result-evidence-{evidenceDigest}"] = evidenceContent;
            store.Values[artifactObject] = archive;
            return new(qualified, store, archive, artifactObject);
        }

        internal RepositoryCiPackagePublicationCoordinator Coordinator(TestPublisher publisher) => new(
            new CiRunnerDurableEvidenceVerifier(Store),
            Store,
            publisher);
    }

    private sealed class TestPublisher(
        params ForgejoGenericPackagePublicationDisposition[] dispositions)
        : IForgejoGenericPackagePublisher
    {
        private readonly Queue<ForgejoGenericPackagePublicationDisposition> remaining = new(dispositions);

        internal List<PublicationCall> Calls { get; } = [];

        public async Task<ForgejoGenericPackagePublicationReceipt> PublishAsync(
            string repository,
            string package,
            string version,
            string fileName,
            string sha256,
            long bytes,
            Func<Stream, CancellationToken, Task> copyContent,
            Func<bool> authorityStillValid,
            CancellationToken cancellationToken = default)
        {
            using var content = new MemoryStream();
            await copyContent(content, cancellationToken);
            Calls.Add(new(repository, package, version, fileName, sha256, bytes, content.ToArray()));
            return new(remaining.Dequeue());
        }
    }

    private sealed record PublicationCall(
        string Repository,
        string Package,
        string Version,
        string FileName,
        string Sha256,
        long Bytes,
        byte[] Content);

    private sealed class TestObjectStore : IDeliveryObjectStore
    {
        internal Dictionary<string, byte[]> Values { get; } = new(StringComparer.Ordinal);

        public Task PutAsync(string name, ReadOnlyMemory<byte> content, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Values[name] = content.ToArray();
            return Task.CompletedTask;
        }

        public Task<byte[]> GetAsync(string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(Values[name].ToArray());
        }
    }

    private static string Digest(int value) => value.ToString("x64", CultureInfo.InvariantCulture);

    private static string Hash(ReadOnlySpan<byte> value) =>
        Convert.ToHexStringLower(SHA256.HashData(value));
}
