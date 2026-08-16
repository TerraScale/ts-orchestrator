using System.Globalization;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

[SupportedOSPlatform("linux")]
public sealed class RepositoryCiOciImagePublicationCoordinatorTests
{
    [Test]
    public async Task OciCandidateReadsExactDurableArchiveAndPublishesOnce()
    {
        var fixture = Fixture.Create("OciImage");
        var publisher = new TestPublisher(
            new(RepositoryCiOciRegistryPublicationDisposition.Published, "terrascale/terrascale/terrascale.orchestrator",
                fixture.Qualified.Candidate.Digest, "sha256:" + Digest(300)));

        var receipt = await fixture.Coordinator(publisher)
            .PublishAsync(fixture.Qualified, static () => true);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiOciImagePublicationDisposition.Published);
        await Assert.That(receipt.EvidenceDigest.Length).IsEqualTo(64);
        await Assert.That(receipt.Images).HasSingleItem();
        await Assert.That(publisher.Calls).HasSingleItem();
        await Assert.That(publisher.Calls[0].Archive.SequenceEqual(fixture.Archive)).IsTrue();
        await Assert.That(publisher.Calls[0].Tag).IsEqualTo(fixture.Qualified.Candidate.Digest);
    }

    [Test]
    public async Task PackageCandidateIsNotApplicableAndNeverReachesOciPublisher()
    {
        var fixture = Fixture.Create("Package");
        var publisher = new TestPublisher(
            new(RepositoryCiOciRegistryPublicationDisposition.Published, "unused", "unused", "sha256:" + Digest(301)));

        var receipt = await fixture.Coordinator(publisher)
            .PublishAsync(fixture.Qualified, static () => true);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiOciImagePublicationDisposition.NotApplicable);
        await Assert.That(publisher.Calls).IsEmpty();
    }

    [Test]
    public async Task CorruptDurableArchiveFailsBeforeRegistryDelegation()
    {
        var fixture = Fixture.Create("OciImage");
        fixture.Store.Values[fixture.ArtifactObject][0] ^= 1;
        var publisher = new TestPublisher(
            new(RepositoryCiOciRegistryPublicationDisposition.Published, "unused", "unused", "sha256:" + Digest(302)));

        var receipt = await fixture.Coordinator(publisher)
            .PublishAsync(fixture.Qualified, static () => true);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiOciImagePublicationDisposition.InvalidEvidence);
        await Assert.That(publisher.Calls).IsEmpty();
    }

    [Test]
    public async Task AuthorityLossStopsBeforeRegistryDelegation()
    {
        var fixture = Fixture.Create("OciImage");
        var publisher = new TestPublisher(
            new(RepositoryCiOciRegistryPublicationDisposition.Published, "unused", "unused", "sha256:" + Digest(303)));

        var receipt = await fixture.Coordinator(publisher)
            .PublishAsync(fixture.Qualified, static () => false);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiOciImagePublicationDisposition.StaleAuthority);
        await Assert.That(publisher.Calls).IsEmpty();
    }

    [Test]
    public async Task DuplicateAndIdentityConflictRemainImmutableOutcomes()
    {
        var fixture = Fixture.Create("OciImage");
        var duplicate = new TestPublisher(
            new(RepositoryCiOciRegistryPublicationDisposition.Duplicate, "terrascale/terrascale/terrascale.orchestrator",
                fixture.Qualified.Candidate.Digest, "sha256:" + Digest(304)));
        var duplicateReceipt = await fixture.Coordinator(duplicate)
            .PublishAsync(fixture.Qualified, static () => true);
        var conflict = new TestPublisher(
            new(RepositoryCiOciRegistryPublicationDisposition.IdentityConflict, "unused", "unused", "sha256:" + Digest(305)));
        var conflictReceipt = await fixture.Coordinator(conflict)
            .PublishAsync(fixture.Qualified, static () => true);

        await Assert.That(duplicateReceipt.Disposition)
            .IsEqualTo(RepositoryCiOciImagePublicationDisposition.Duplicate);
        await Assert.That(duplicateReceipt.EvidenceDigest.Length).IsEqualTo(64);
        await Assert.That(conflictReceipt.Disposition)
            .IsEqualTo(RepositoryCiOciImagePublicationDisposition.IdentityConflict);
    }

    private sealed record Fixture(
        RepositoryCiQualifiedCandidate Qualified,
        TestObjectStore Store,
        byte[] Archive,
        string ArtifactObject)
    {
        internal static Fixture Create(string promotion)
        {
            var pipeline = RepositoryCiCandidateCoordinatorTests.ReleasePipeline(promotion);
            var planned = pipeline.Jobs.Single(static value =>
                value.Plan.Node.Kind == RepositoryCiNodeKind.Artifact);
            var archive = "canonical oci outer archive"u8.ToArray();
            var outputDigest = Digest(400);
            var workload = new CiRunnerWorkloadEvidence(
                1,
                "trusted-oci-runner",
                pipeline.Digest,
                planned.Request.Job.Value,
                Digest(401),
                Digest(402),
                Digest(403),
                Digest(404),
                10,
                11,
                1,
                1,
                Digest(405),
                Digest(406),
                Digest(407),
                Digest(408),
                CiRunnerBuildKitExecutionDisposition.Succeeded,
                0,
                Hash([]),
                0,
                Digest(409),
                outputDigest,
                1,
                1024,
                true,
                RepositoryCiJobFailureKind.Unspecified,
                CiRunnerWorkloadFailureCode.Unspecified);
            var artifactObject = $"ci-result-artifact-{outputDigest}";
            var declaration = new CiRunnerStoredArtifactEvidence(
                "oci-image",
                RepositoryCiArchitecture.Any,
                "oci/image.tar",
                Digest(410),
                1,
                256,
                []);
            var stored = new CiRunnerStoredWorkloadEvidence(
                2,
                workload,
                $"ci-result-log-{workload.LogSha256}",
                workload.LogSha256,
                0,
                artifactObject,
                Hash(archive),
                archive.LongLength,
                [declaration],
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
                job == planned ? evidenceDigest : Digest(420 + index))).ToArray();
            var artifact = new RepositoryCiArtifactResult(
                planned.Plan.Repository,
                planned.Plan.Promotion,
                planned.Request.Job,
                new("oci-image"),
                RepositoryCiArchitecture.Any,
                new(declaration.Digest),
                [],
                new("trusted-build-signer"),
                new("oci-image-signature"),
                true,
                null);
            var candidate = RepositoryCiCandidateAssembler.Assemble(
                pipeline,
                results,
                [artifact]);
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

        internal RepositoryCiOciImagePublicationCoordinator Coordinator(TestPublisher publisher) => new(
            new CiRunnerDurableEvidenceVerifier(Store),
            Store,
            publisher);
    }

    private sealed class TestPublisher(RepositoryCiOciRegistryPublicationReceipt receipt)
        : IRepositoryCiOciRegistryPublisher
    {
        internal List<PublicationCall> Calls { get; } = [];

        public async Task<RepositoryCiOciRegistryPublicationReceipt> PublishAsync(
            string artifactRepository,
            string candidateDigest,
            string archiveSha256,
            long archiveBytes,
            Func<Stream, CancellationToken, Task> copyArchive,
            Func<bool> authorityStillValid,
            CancellationToken cancellationToken = default)
        {
            using var content = new MemoryStream();
            await copyArchive(content, cancellationToken);
            Calls.Add(new(artifactRepository, candidateDigest, archiveSha256, archiveBytes, content.ToArray()));
            return receipt;
        }
    }

    private sealed record PublicationCall(
        string Repository,
        string Tag,
        string ArchiveSha256,
        long ArchiveBytes,
        byte[] Archive);

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
