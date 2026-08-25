using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Regression coverage for the direct-delivery reconciliation of the retired candidate stage:
/// the acknowledge gate must attest exact artifact subjects from verified durable evidence,
/// fail closed on missing or mismatched evidence, and respect authority fencing and retries.
/// </summary>
public sealed class RepositoryCiArtifactAttestationGateTests
{
    [Test]
    public async Task ExactVerifiedArtifactsAreAttestedAndReplayConverges()
    {
        var fixture = Fixture.Create();

        var first = await fixture.Gate().RecordAsync(fixture.Pipeline, 7, 20, static () => true);
        var replay = await fixture.Gate().RecordAsync(fixture.Pipeline, 7, 21, static () => true);

        await Assert.That(first.Disposition).IsEqualTo(RepositoryCiArtifactAttestationGateDisposition.Attested);
        await Assert.That(replay.Disposition).IsEqualTo(RepositoryCiArtifactAttestationGateDisposition.Attested);
        foreach (var architecture in new[]
                 {
                     RepositoryCiArchitecture.LinuxX64,
                     RepositoryCiArchitecture.LinuxArm64,
                 })
        {
            var artifact = await fixture.Journal.ReadArtifactAsync(fixture.Subject(architecture));
            await Assert.That(artifact).IsNotNull();
            await Assert.That(artifact!.SigningIdentity.Value).IsEqualTo(fixture.ArtifactTrust.Identity);
        }
        // Two runner evidence objects plus two runtime observations and two minted artifact
        // signatures; the replay mints nothing new.
        await Assert.That(fixture.Ledger.Mutations).IsEqualTo(4);
        await Assert.That(fixture.Store.Values.Count).IsEqualTo(6);
    }

    [Test]
    public async Task MissingExecutionEvidenceFailsClosedBeforeAnyAttestation()
    {
        var fixture = Fixture.Create(execution: static () => null);

        await Assert.That(async () => await fixture.Gate().RecordAsync(fixture.Pipeline, 7, 20, static () => true))
            .Throws<InvalidDataException>();
        await Assert.That(await fixture.Journal.ReadArtifactAsync(fixture.Subject(RepositoryCiArchitecture.LinuxX64)))
            .IsNull();
    }

    [Test]
    public async Task ExecutionFromAnotherJobIdentityNeverReachesAttestation()
    {
        var fixture = Fixture.Create(substituteExecutionJobDigest: true);

        await Assert.That(async () => await fixture.Gate().RecordAsync(fixture.Pipeline, 7, 20, static () => true))
            .Throws<InvalidDataException>();
        await Assert.That(await fixture.Journal.ReadArtifactAsync(fixture.Subject(RepositoryCiArchitecture.LinuxX64)))
            .IsNull();
    }

    [Test]
    public async Task IncompleteArchitectureOutputFailsClosed()
    {
        var fixture = Fixture.Create(omitArm64: true);

        await Assert.That(async () => await fixture.Gate().RecordAsync(fixture.Pipeline, 7, 20, static () => true))
            .Throws<InvalidDataException>();
        await Assert.That(await fixture.Journal.ReadArtifactAsync(fixture.Subject(RepositoryCiArchitecture.LinuxX64)))
            .IsNull();
    }

    [Test]
    public async Task MissingRuntimeEvidenceIsATypedRetryableDispositionThatConverges()
    {
        // The runner's serial proof consumer has not persisted the X64 observation yet: the gate
        // must return ProofNotYetConsumed (never throw, never go terminal) and converge on retry.
        var fixture = Fixture.Create(omitRuntimeFor: RepositoryCiArchitecture.LinuxX64);

        var pending = await fixture.Gate().RecordAsync(fixture.Pipeline, 7, 20, static () => true);

        await Assert.That(pending.Disposition)
            .IsEqualTo(RepositoryCiArtifactAttestationGateDisposition.ProofNotYetConsumed);

        var subject = fixture.Subject(RepositoryCiArchitecture.LinuxX64);
        await fixture.Journal.RecordRuntimeAsync(
            RepositoryCiArtifactAttestation.ObserveRuntime(subject, subject.Digest, fixture.RuntimeTrust),
            7,
            12,
            static () => true);
        var retried = await fixture.Gate().RecordAsync(fixture.Pipeline, 7, 23, static () => true);

        await Assert.That(retried.Disposition)
            .IsEqualTo(RepositoryCiArtifactAttestationGateDisposition.Attested);
    }

    [Test]
    public async Task AVerifiedButMismatchedProofIsTerminalEvidenceMismatch()
    {
        // The observation exists for the exact subject but is signed by an untrusted runtime key:
        // not the not-yet-consumed race, a permanent mismatch.
        var fixture = Fixture.Create(omitRuntimeFor: RepositoryCiArchitecture.LinuxX64);
        var subject = fixture.Subject(RepositoryCiArchitecture.LinuxX64);
        await fixture.Journal.RecordRuntimeAsync(
            RepositoryCiArtifactAttestation.ObserveRuntime(subject, subject.Digest, new HashSignature(9)),
            7,
            12,
            static () => true);

        var receipt = await fixture.Gate().RecordAsync(fixture.Pipeline, 7, 20, static () => true);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiArtifactAttestationGateDisposition.EvidenceMismatch);
    }

    [Test]
    public async Task RetriedJobAttemptsRemainAttestableWhenExactnessHolds()
    {
        var fixture = Fixture.Create(jobAttempt: 2);

        var receipt = await fixture.Gate().RecordAsync(fixture.Pipeline, 7, 20, static () => true);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiArtifactAttestationGateDisposition.Attested);
    }

    [Test]
    public async Task AttestedArtifactsRecordDeliveryEvidenceAProductionDeliveryVerifies()
    {
        var fixture = Fixture.Create();
        var deliveryLedger = new ForgejoWebhookJournalTests.TestLedger();
        var evidenceJournal = new DirectDeliveryArtifactEvidenceJournal(
            new DirectDeliveryProductionAdapterTests.LedgerAdapter(deliveryLedger));

        var receipt = await fixture.Gate(deliveryEvidence: evidenceJournal)
            .RecordAsync(fixture.Pipeline, 7, 20, static () => true);

        await Assert.That(receipt.Disposition).IsEqualTo(RepositoryCiArtifactAttestationGateDisposition.Attested);
        var planned = fixture.Pipeline.Jobs.Single(static value =>
            value.Plan.Node.Kind == RepositoryCiNodeKind.Artifact);
        var declared = fixture.Declarations.Single(static value =>
            value.Architecture == RepositoryCiArchitecture.LinuxX64);
        var subject = fixture.Subject(RepositoryCiArchitecture.LinuxX64);
        var expectedDigest = "sha256:" + declared.Digest;
        var recorded = await evidenceJournal.ReadAsync(expectedDigest, default);
        await Assert.That(recorded).IsNotNull();
        await Assert.That(recorded!.Evidence.Repository).IsEqualTo(planned.Source.Repository);
        await Assert.That(recorded.Evidence.Commit).IsEqualTo(planned.Source.Commit);
        await Assert.That(recorded.Evidence.TreeDigest).IsEqualTo(CiTreeDigest(planned.Source.Tree));
        await Assert.That(recorded.Evidence.ManifestDigest)
            .IsEqualTo("sha256:" + RepositoryCiArtifactAttestation.SubjectDigest(subject));
        await Assert.That(recorded.Evidence.Kind).IsEqualTo("package");

        // The closed loop the ticket asks for: a published artifact becomes deliverable in
        // production because its evidence exists and verifies against the signing trust root.
        var provenance = new DirectDeliveryProductionProvenance(evidenceJournal, fixture.ArtifactTrust);
        var verified = await provenance.VerifyAsync(
            new(
                1,
                "operation-ci-evidence",
                new(planned.Source.Repository, planned.Source.Commit, CiTreeDigest(planned.Source.Tree)),
                new(expectedDigest, recorded.Evidence.ManifestDigest, "package"),
                new("authentication", "development", ["gru"]),
                "sha256:" + new string('a', 64),
                null,
                "actor-1",
                "direct customer change"),
            new(expectedDigest, recorded.Evidence.ManifestDigest, "package"),
            default);
        var unrecorded = await provenance.VerifyAsync(
            new(
                1,
                "operation-ci-evidence-2",
                new(planned.Source.Repository, planned.Source.Commit, CiTreeDigest(planned.Source.Tree)),
                new("sha256:" + new string('f', 64), recorded.Evidence.ManifestDigest, "package"),
                new("authentication", "development", ["gru"]),
                "sha256:" + new string('a', 64),
                null,
                "actor-1",
                "direct customer change"),
            new("sha256:" + new string('f', 64), recorded.Evidence.ManifestDigest, "package"),
            default);
        await Assert.That(verified.Verified).IsTrue();
        await Assert.That(unrecorded.Verified).IsFalse();
    }

    [Test]
    public async Task AConflictingDurableDeliveryClaimIsTerminalEvidenceMismatch()
    {
        var fixture = Fixture.Create();
        var deliveryLedger = new ForgejoWebhookJournalTests.TestLedger();
        var evidenceJournal = new DirectDeliveryArtifactEvidenceJournal(
            new DirectDeliveryProductionAdapterTests.LedgerAdapter(deliveryLedger));
        var declared = fixture.Declarations.Single(static value =>
            value.Architecture == RepositoryCiArchitecture.LinuxX64);
        // A different, already-durable claim for the same artifact digest: the publication can
        // never be attested as that digest, so the acknowledge goes terminal, not retry.
        await evidenceJournal.RecordAsync(
            new DirectDeliveryArtifactEvidence(
                "TerraScale/TerraScale.Orchestrator",
                new string('e', 40),
                "sha256:" + new string('1', 64),
                "sha256:" + declared.Digest,
                "sha256:" + new string('2', 64),
                "package"),
            fixture.ArtifactTrust,
            default);

        var receipt = await fixture.Gate(deliveryEvidence: evidenceJournal)
            .RecordAsync(fixture.Pipeline, 7, 20, static () => true);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiArtifactAttestationGateDisposition.EvidenceMismatch);
    }

    [Test]
    public async Task AnUnreachableDeliveryEvidenceJournalIsRetryableNotAcknowledged()
    {
        var fixture = Fixture.Create();
        var gate = fixture.Gate(deliveryEvidence: new DirectDeliveryArtifactEvidenceJournal(
            new DirectDeliveryProductionAdapterTests.UnavailableLedger()));

        var receipt = await gate.RecordAsync(fixture.Pipeline, 7, 20, static () => true);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiArtifactAttestationGateDisposition.DeliveryEvidenceJournalUnavailable);
    }

    /// <summary>The CI source's Git tree object identity, re-encoded into the delivery digest vocabulary.</summary>
    private static string CiTreeDigest(string tree) =>
        "sha256:" + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(tree)));

    [Test]
    public async Task StaleAuthorityFencesTheGateAndALaterAttemptConverges()
    {
        var fixture = Fixture.Create();

        var fenced = await fixture.Gate().RecordAsync(fixture.Pipeline, 7, 20, static () => false);

        await Assert.That(fenced.Disposition)
            .IsEqualTo(RepositoryCiArtifactAttestationGateDisposition.AuthorityLost);
        // The fenced attempt minted no artifact signature before returning.
        await Assert.That(await fixture.Journal.ReadArtifactAsync(fixture.Subject(RepositoryCiArchitecture.LinuxX64)))
            .IsNull();

        var recovery = await fixture.Gate().RecordAsync(fixture.Pipeline, 8, 22, static () => true);
        await Assert.That(recovery.Disposition)
            .IsEqualTo(RepositoryCiArtifactAttestationGateDisposition.Attested);
    }

    [Test]
    public async Task LostProofAuthorityDuringVerificationFailsTheGate()
    {
        var fixture = Fixture.Create();
        var gate = fixture.Gate(runtimeVerifier: new FailingRuntimeVerifier());

        await Assert.That(async () => await gate.RecordAsync(fixture.Pipeline, 7, 20, static () => true))
            .Throws<RepositoryCiArtifactProofAuthorityLostException>();
        // The gate never reported success: the acknowledge wiring treats the exception as a retry.
    }

    [Test]
    public async Task NonBuildPipelinesAndNonTerminalRunsNeverReachAttestation()
    {
        var fixture = Fixture.Create();
        var feature = await fixture.Gate().RecordAsync(
            RepositoryCiPipelineJournalTests.Pipeline(),
            7,
            20,
            static () => true);
        var active = await fixture.GateForRun(fixture.Run with
        {
            State = RepositoryCiPipelineRunState.Active,
        }).RecordAsync(fixture.Pipeline, 7, 20, static () => true);
        var failed = await fixture.GateForRun(fixture.Run with
        {
            State = RepositoryCiPipelineRunState.Failed,
        }).RecordAsync(fixture.Pipeline, 7, 20, static () => true);

        await Assert.That(feature.Disposition)
            .IsEqualTo(RepositoryCiArtifactAttestationGateDisposition.NotBuildPipeline);
        await Assert.That(active.Disposition)
            .IsEqualTo(RepositoryCiArtifactAttestationGateDisposition.PipelineActive);
        await Assert.That(failed.Disposition)
            .IsEqualTo(RepositoryCiArtifactAttestationGateDisposition.PipelineFailed);
        await Assert.That(fixture.Ledger.Mutations).IsEqualTo(2);
    }

    private sealed class Fixture
    {
        internal required RepositoryCiPipelinePlan Pipeline { get; init; }
        internal required RepositoryCiPipelineRunSnapshot Run { get; init; }
        internal required RepositoryCiJobExecutionSnapshot Execution { get; init; }
        internal required Func<RepositoryCiJobExecutionSnapshot?>? ExecutionFactory { get; init; }
        internal required CiRunnerDurableEvidenceVerifier Evidence { get; init; }
        internal required RepositoryCiArtifactAttestationJournal Journal { get; init; }
        internal required HashSignature ArtifactTrust { get; init; }
        internal required HashSignature RuntimeTrust { get; init; }
        internal required ForgejoWebhookJournalTests.TestLedger Ledger { get; init; }
        internal required TestObjectStore Store { get; init; }
        internal required CiRunnerStoredArtifactEvidence[] Declarations { get; init; }

        internal RepositoryCiArtifactAttestationGate Gate(
            IRepositoryCiArtifactSignatureVerifier? runtimeVerifier = null,
            DirectDeliveryArtifactEvidenceJournal? deliveryEvidence = null) =>
            new(
                (_, token) =>
                {
                    token.ThrowIfCancellationRequested();
                    return Task.FromResult(Run);
                },
                (_, token) =>
                {
                    token.ThrowIfCancellationRequested();
                    return Task.FromResult<RepositoryCiJobExecutionSnapshot?>(
                        ExecutionFactory is null ? Execution : ExecutionFactory());
                },
                Evidence,
                Journal,
                ArtifactTrust,
                ArtifactTrust,
                runtimeVerifier ?? RuntimeTrust,
                deliveryEvidence);

        internal RepositoryCiArtifactAttestationGate GateForRun(RepositoryCiPipelineRunSnapshot run) =>
            new(
                (_, token) =>
                {
                    token.ThrowIfCancellationRequested();
                    return Task.FromResult(run);
                },
                (_, token) =>
                {
                    token.ThrowIfCancellationRequested();
                    return Task.FromResult<RepositoryCiJobExecutionSnapshot?>(
                        ExecutionFactory is null ? Execution : ExecutionFactory());
                },
                Evidence,
                Journal,
                ArtifactTrust,
                ArtifactTrust,
                RuntimeTrust);

        internal RepositoryCiArtifactSubject Subject(RepositoryCiArchitecture architecture)
        {
            var planned = Pipeline.Jobs.Single(static value =>
                value.Plan.Node.Kind == RepositoryCiNodeKind.Artifact);
            var declared = Declarations.Single(value => value.Architecture == architecture);
            return new RepositoryCiArtifactSubject(
                Pipeline.Digest,
                planned.Request.Job,
                new(declared.Artifact),
                architecture,
                new(declared.Digest),
                RepositoryCiArtifactAttestation.EntrypointsDigest(architecture, declared.Entrypoints));
        }

        internal static Fixture Create(
            bool substituteExecutionJobDigest = false,
            bool omitArm64 = false,
            Func<RepositoryCiJobExecutionSnapshot?>? execution = null,
            RepositoryCiArchitecture? omitRuntimeFor = null,
            int jobAttempt = 1)
        {
            var artifactTrust = new HashSignature(1);
            var runtimeTrust = new HashSignature(2);
            var pipeline = BuildPipeline();
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
                    Digest(903),
                    1,
                    256,
                    ["app"]),
            };
            if (!omitArm64)
                declarations.Add(new(
                    "TerraScale/TerraScale.Orchestrator",
                    RepositoryCiArchitecture.LinuxArm64,
                    "linux-arm64",
                    Digest(904),
                    1,
                    256,
                    ["app"]));
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
                jobAttempt,
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
                2,
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
                jobAttempt,
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
            var executionSnapshot = new RepositoryCiJobExecutionSnapshot(executionDocument, 43);
            var snapshots = pipeline.Jobs.Select((job, index) => Snapshot(
                pipeline,
                job,
                runner,
                operation,
                streamSequence,
                job == planned ? evidenceDigest : Digest(920 + index),
                jobAttempt)).ToArray();
            var run = new RepositoryCiPipelineRunSnapshot(
                RepositoryCiPipelineRunState.Succeeded,
                snapshots,
                []);
            var store = new TestObjectStore();
            store.Values[$"ci-result-evidence-{evidenceDigest}"] = content;
            store.Values[stored.ArtifactObject] = archive;
            var ledger = new ForgejoWebhookJournalTests.TestLedger();
            var journal = new RepositoryCiArtifactAttestationJournal(ledger, store);
            var fixture = new Fixture
            {
                Pipeline = pipeline,
                Run = run,
                Execution = executionSnapshot,
                ExecutionFactory = execution,
                Evidence = new CiRunnerDurableEvidenceVerifier(store),
                Journal = journal,
                ArtifactTrust = artifactTrust,
                RuntimeTrust = runtimeTrust,
                Ledger = ledger,
                Store = store,
                Declarations = declarations.ToArray(),
            };
            // The runner records its native runtime observations before the gate runs; the gate
            // only mints and verifies the immutable artifact signatures against them.
            foreach (var architecture in pipeline.Jobs
                .Where(static value => value.Plan.Node.Kind == RepositoryCiNodeKind.Artifact)
                .SelectMany(static value => value.Plan.Node.Architectures))
            {
                if (omitArm64 && architecture == RepositoryCiArchitecture.LinuxArm64) continue;
                if (omitRuntimeFor == architecture) continue;
                var subject = fixture.Subject(architecture);
                journal.RecordRuntimeAsync(
                    RepositoryCiArtifactAttestation.ObserveRuntime(subject, subject.Digest, runtimeTrust),
                    7,
                    11,
                    static () => true).GetAwaiter().GetResult();
            }
            return fixture;
        }

        private static RepositoryCiPipelinePlan BuildPipeline()
        {
            var descriptor = RepositoryCiDescriptor.Parse(Encoding.UTF8.GetBytes($$"""
                {
                  "apiVersion":"terrascale.ci/v3",
                  "repository":"TerraScale/TerraScale.Orchestrator",
                  "repositoryDependencies":[],
                  "nodes":[
                    {"id":"artifact","kind":"Artifact","resourceWeight":"Heavy","profiles":["Build"],"architectures":["LinuxX64","LinuxArm64"],"dependsOn":["build","test"]},
                    {"id":"test","kind":"Test","resourceWeight":"Heavy","profiles":["Build"],"dependsOn":["build"]},
                    {"id":"build","kind":"Build","resourceWeight":"Heavy","profiles":["Feature","Build"],"paths":["src/"],"dependsOn":["static"]},
                    {"id":"static","kind":"Static","resourceWeight":"Light","profiles":["Feature","Build"],"paths":["src/"]}
                  ]
                }
                """));
            var impact = RepositoryCiImpactPlanner.Plan(
                [descriptor],
                [new RepositoryCiChange("TerraScale/TerraScale.Orchestrator", ["src/file.cs"])],
                RepositoryCiProfile.Build);
            var trigger = ForgejoCiTriggerPlanner.Plan(new ForgejoWebhookEnvelope(
                Guid.Parse("f6266f16-1bf3-46a5-9ea4-602e06ead473"),
                ForgejoWebhookKind.PullRequest,
                "synchronized",
                "TerraScale/TerraScale.Orchestrator",
                "TerraScale/TerraScale.Orchestrator",
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
                [new ForgejoResolvedRevision(
                    "TerraScale/TerraScale.Orchestrator",
                    new string('b', 40),
                    new string('c', 40),
                    true)],
                7,
                10,
                100);
        }

        private static RepositoryCiJobSnapshot Snapshot(
            RepositoryCiPipelinePlan pipeline,
            RepositoryCiPipelineJob job,
            string runner,
            string operation,
            ulong streamSequence,
            string evidenceDigest,
            int attempt)
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
                Attempt = attempt,
                AttemptChainDigest = attempt == 1 ? string.Empty : Digest(940),
                RetryAuthorizationDigest = attempt == 1 ? string.Empty : Digest(941),
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

    private sealed class FailingRuntimeVerifier : IRepositoryCiArtifactSignatureVerifier
    {
        public VerificationOutcome Verify(
            string signingIdentity,
            ReadOnlyMemory<byte> canonicalMaterial,
            OpaqueSignature signature) => throw new RepositoryCiArtifactProofAuthorityLostException();
    }

    private sealed class HashSignature(byte domain) :
        IRepositoryCiArtifactAttestationSigner,
        IRepositoryCiArtifactSignatureVerifier
    {
        public string Identity => $"test-key-{domain}";

        public OpaqueSignature Sign(ReadOnlyMemory<byte> canonicalMaterial)
        {
            var bytes = new byte[canonicalMaterial.Length + 1];
            bytes[0] = domain;
            canonicalMaterial.Span.CopyTo(bytes.AsSpan(1));
            OpaqueSignature.TryCopyFrom(SHA256.HashData(bytes), out var signature);
            return signature!;
        }

        public VerificationOutcome Verify(
            string signingIdentity,
            ReadOnlyMemory<byte> canonicalMaterial,
            OpaqueSignature signature) => signingIdentity == Identity && Sign(canonicalMaterial).Equals(signature)
            ? VerificationOutcome.Valid
            : VerificationOutcome.Invalid;
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
            if (!Values.TryGetValue(name, out var content)) throw new IOException("Missing test object.");
            return Task.FromResult(content.ToArray());
        }
    }

    private static string Digest(int value) => value.ToString("x64");

    private static string Hash(ReadOnlySpan<byte> value) =>
        Convert.ToHexStringLower(SHA256.HashData(value));
}
