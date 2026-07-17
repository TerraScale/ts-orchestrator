using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

public sealed class RepositoryCiCandidateArtifactReaderTests
{
    [Test]
    public async Task ExactSignedRuntimeObservedArtifactsBecomeCandidateInput()
    {
        var fixture = Fixture.Create();

        var artifacts = await fixture.Reader.ReadAsync(fixture.Pipeline, fixture.Run);

        await Assert.That(artifacts.Count).IsEqualTo(2);
        await Assert.That(artifacts.All(static value => value.SignatureVerified)).IsTrue();
        await Assert.That(artifacts.All(static value => value.ObservedRuntimeDigest == value.Digest)).IsTrue();
        await Assert.That(fixture.Attestations.Subjects.Select(static value => value.Architecture))
            .IsEquivalentTo([
                RepositoryCiArchitecture.LinuxX64,
                RepositoryCiArchitecture.LinuxArm64,
            ]);
    }

    [Test]
    public async Task MissingCryptographicAttestationFailsClosed()
    {
        var fixture = Fixture.Create(attestation: static _ => null);

        await Assert.That(async () => await fixture.Reader.ReadAsync(fixture.Pipeline, fixture.Run))
            .Throws<InvalidDataException>();
    }

    [Test]
    public async Task NativeArtifactWithoutExactRuntimeObservationFailsClosed()
    {
        var fixture = Fixture.Create(attestation: static _ => new(
            new("trusted-build-signer"),
            new("artifact-signature"),
            null));

        await Assert.That(async () => await fixture.Reader.ReadAsync(fixture.Pipeline, fixture.Run))
            .Throws<InvalidDataException>();
    }

    [Test]
    public async Task ExecutionFromAnotherJobIdentityNeverReachesAttestation()
    {
        var fixture = Fixture.Create(substituteExecutionJobDigest: true);

        await Assert.That(async () => await fixture.Reader.ReadAsync(fixture.Pipeline, fixture.Run))
            .Throws<InvalidDataException>();
        await Assert.That(fixture.Attestations.Subjects).IsEmpty();
    }

    [Test]
    public async Task IncompleteArchitectureOutputNeverReachesAttestation()
    {
        var fixture = Fixture.Create(omitArm64: true);

        await Assert.That(async () => await fixture.Reader.ReadAsync(fixture.Pipeline, fixture.Run))
            .Throws<InvalidDataException>();
        await Assert.That(fixture.Attestations.Subjects).IsEmpty();
    }

    private sealed record Fixture(
        RepositoryCiPipelinePlan Pipeline,
        RepositoryCiPipelineRunSnapshot Run,
        RepositoryCiCandidateArtifactReader Reader,
        TestAttestationVerifier Attestations)
    {
        internal static Fixture Create(
            Func<RepositoryCiArtifactSubject, RepositoryCiVerifiedArtifactAttestation?>? attestation = null,
            bool substituteExecutionJobDigest = false,
            bool omitArm64 = false)
        {
            var pipeline = RepositoryCiCandidateCoordinatorTests.ReleasePipeline("NativeRolling");
            var planned = pipeline.Jobs.Single(static value =>
                value.Plan.Node.Kind == RepositoryCiNodeKind.Artifact);
            var runner = "trusted-artifact-runner";
            var operation = "artifact-operation";
            var streamSequence = 41UL;
            var acceptanceRevision = 42UL;
            var jobDigest = RepositoryCiJobJournal.JobDigest(pipeline, planned);
            var executionJobDigest = substituteExecutionJobDigest ? Digest(900) : jobDigest;
            var sourceDigest = Digest(901);
            var outputDigest = Digest(902);
            var archive = "canonical artifact archive"u8.ToArray();
            var declarations = new List<CiRunnerStoredArtifactEvidence>
            {
                new(
                    "TerraScale/TerraScale.Orchestrator",
                    RepositoryCiArchitecture.LinuxX64,
                    "linux-x64",
                    Digest(903)),
            };
            if (!omitArm64)
                declarations.Add(new(
                    "TerraScale/TerraScale.Orchestrator",
                    RepositoryCiArchitecture.LinuxArm64,
                    "linux-arm64",
                    Digest(904)));
            var workload = new CiRunnerWorkloadEvidence(
                1,
                runner,
                pipeline.Digest,
                planned.Request.Job.Value,
                executionJobDigest,
                Digest(905),
                Digest(906),
                Digest(907),
                streamSequence,
                acceptanceRevision,
                1,
                1,
                Digest(908),
                sourceDigest,
                Digest(909),
                Digest(910),
                CiRunnerBuildKitExecutionDisposition.Succeeded,
                0,
                Hash([]),
                0,
                Digest(911),
                outputDigest,
                2,
                1024,
                true,
                RepositoryCiJobFailureKind.Unspecified,
                CiRunnerWorkloadFailureCode.Unspecified);
            var stored = new CiRunnerStoredWorkloadEvidence(
                1,
                workload,
                $"ci-result-log-{workload.LogSha256}",
                workload.LogSha256,
                0,
                $"ci-result-artifact-{outputDigest}",
                Hash(archive),
                archive.LongLength,
                declarations.ToArray(),
                0,
                30);
            var content = JsonSerializer.SerializeToUtf8Bytes(
                stored,
                CiRunnerDurableResultJsonContext.Default.CiRunnerStoredWorkloadEvidence);
            var evidenceDigest = Hash(content);
            var executionDocument = new RepositoryCiJobExecutionDocument(
                1,
                runner,
                pipeline.Digest,
                planned.Request.Job.Value,
                executionJobDigest,
                planned.Request.Generation,
                1,
                5,
                7,
                workload.ExecutionIdentityDigest,
                workload.PayloadDigest,
                workload.SignatureDigest,
                streamSequence,
                acceptanceRevision,
                RepositoryCiJobExecutionPhase.Succeeded,
                operation,
                1,
                1_782_000_000_000,
                1_782_000_000_001,
                1_782_000_000_002,
                1_782_000_300_002,
                1_782_000_000_003,
                evidenceDigest,
                0,
                RepositoryCiJobFailureKind.Unspecified);
            executionDocument.Validate();
            var execution = new RepositoryCiJobExecutionSnapshot(executionDocument, 43);
            var snapshots = pipeline.Jobs.Select((job, index) => Snapshot(
                pipeline,
                job,
                runner,
                operation,
                streamSequence,
                job == planned ? evidenceDigest : Digest(920 + index))).ToArray();
            var run = new RepositoryCiPipelineRunSnapshot(
                RepositoryCiPipelineRunState.Succeeded,
                snapshots,
                [],
                snapshots.Select(static value => new RepositoryCiJobResult(
                    value.Job.Request.Job,
                    1,
                    true,
                    0,
                    value.EvidenceDigest)).ToArray());
            var store = new TestObjectStore();
            store.Values[$"ci-result-evidence-{evidenceDigest}"] = content;
            store.Values[stored.ArtifactObject] = archive;
            var verifier = new TestAttestationVerifier(attestation ?? (static subject => new(
                new("trusted-build-signer"),
                new($"signature-{subject.Architecture}"),
                subject.Digest)));
            var reader = new RepositoryCiCandidateArtifactReader(
                (_, token) =>
                {
                    token.ThrowIfCancellationRequested();
                    return Task.FromResult<RepositoryCiJobExecutionSnapshot?>(execution);
                },
                new(store),
                verifier);
            return new(pipeline, run, reader, verifier);
        }

        private static RepositoryCiJobSnapshot Snapshot(
            RepositoryCiPipelinePlan pipeline,
            RepositoryCiPipelineJob job,
            string runner,
            string operation,
            ulong streamSequence,
            string evidenceDigest)
        {
            var sourceDigest = Digest(901);
            var document = RepositoryCiJobDocument.Pending(
                pipeline,
                job,
                RepositoryCiJobJournal.JobDigest(pipeline, job),
                5,
                9) with
            {
                PreviousPhase = RepositoryCiJobPhase.Running,
                Phase = RepositoryCiJobPhase.Succeeded,
                PhaseSequence = 4,
                ControllerId = "gru-controller-1",
                AuthorityEpoch = 5,
                FencingToken = 7,
                RunnerId = runner,
                RunnerSequence = 20,
                IsolationDigest = Digest(930),
                OperationId = operation,
                EvidenceDigest = evidenceDigest,
                PreparedAtUnixMilliseconds = 1_782_000_000_001,
                ExpiresAtUnixMilliseconds = 1_782_007_200_001,
                DispatchStreamSequence = streamSequence,
                SourceBundleObject = RepositoryCiSourceBundlePublisher.ObjectName(sourceDigest),
                SourceBundleSha256 = sourceDigest,
                SourceBundleBytes = 1024,
            };
            document.Validate();
            return new(job, document, 44);
        }
    }

    private sealed class TestAttestationVerifier(
        Func<RepositoryCiArtifactSubject, RepositoryCiVerifiedArtifactAttestation?> result)
        : IRepositoryCiArtifactAttestationVerifier
    {
        internal List<RepositoryCiArtifactSubject> Subjects { get; } = [];

        public Task<RepositoryCiVerifiedArtifactAttestation?> VerifyAsync(
            RepositoryCiArtifactSubject subject,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Subjects.Add(subject);
            return Task.FromResult(result(subject));
        }
    }

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
            if (!Values.TryGetValue(name, out var value)) throw new IOException("Missing test object.");
            return Task.FromResult(value.ToArray());
        }
    }

    private static string Digest(int value) => value.ToString("x64", CultureInfo.InvariantCulture);

    private static string Hash(ReadOnlySpan<byte> value) =>
        Convert.ToHexStringLower(SHA256.HashData(value));
}
