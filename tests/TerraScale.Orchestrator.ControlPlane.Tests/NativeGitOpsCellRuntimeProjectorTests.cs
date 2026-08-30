using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.ControlPlane.Runtime;
using TerraScale.Orchestrator.Delivery;
using HostArchitecture = TerraScale.Orchestrator.Runtime.HostArchitecture;
using HostArtifactDigest = TerraScale.Orchestrator.Runtime.ArtifactDigest;
using HostRole = TerraScale.Orchestrator.Runtime.AdmittedRole;
using HostRuntimeAllocationId = TerraScale.Orchestrator.Runtime.RuntimeAllocationId;
using HostRuntimeDriver = TerraScale.Orchestrator.Runtime.RuntimeDriver;
using HostRuntimePlan = TerraScale.Orchestrator.Runtime.HostRuntimePlan;
using HostRuntimeResources = TerraScale.Orchestrator.Runtime.RuntimeResourceLimits;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class NativeGitOpsCellRuntimeProjectorTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 17, 12, 0, 30, TimeSpan.Zero);

    [Test]
    public async Task ExactDurableApplyProjectsOneCanonicalConvergeCommand()
    {
        var fixture = Fixture();

        var command = NativeGitOpsCellRuntimeProjector.Project(
            fixture.Scope, fixture.Accepted, fixture.Verified, fixture.Assignment, Now);

        await Assert.That(command.Request.Action).IsEqualTo(LifecycleAction.Converge);
        await Assert.That(command.Request.Cell).IsEqualTo(fixture.Scope.Cell);
        await Assert.That(command.Request.Node).IsEqualTo(fixture.Scope.Node);
        await Assert.That(command.Request.AcceptedConvergenceDigest.Sha256)
            .IsEqualTo(fixture.Checkpoint.CheckpointDigest);
        await Assert.That(command.Request.PlanFingerprint).IsEqualTo(fixture.Assignment.ExpectedPlanFingerprint);
        await Assert.That(command.AcceptedOperationId)
            .IsEqualTo($"gitops/{fixture.Accepted.HandoffDigest}/gru");
        await Assert.That(command.AcceptedIdempotencyKey)
            .IsEqualTo($"gitops/{fixture.Accepted.PayloadSha256}");
        await Assert.That(command.CanonicalDigest.Sha256).Length().IsEqualTo(64);
    }

    [Test]
    public async Task ExactReplayHasStableRequestIdentityAndCanonicalDigest()
    {
        var fixture = Fixture();

        var first = NativeGitOpsCellRuntimeProjector.Project(
            fixture.Scope, fixture.Accepted, fixture.Verified, fixture.Assignment, Now);
        var replay = NativeGitOpsCellRuntimeProjector.Project(
            fixture.Scope, fixture.Accepted, fixture.Verified, fixture.Assignment, Now);

        await Assert.That(replay.Request.OperationKey).IsEqualTo(first.Request.OperationKey);
        await Assert.That(replay.Request.PlanFingerprint).IsEqualTo(first.Request.PlanFingerprint);
        await Assert.That(replay.CanonicalDigest).IsEqualTo(first.CanonicalDigest);
    }

    [Test]
    public async Task MismatchedAcceptedOrConvergenceBindingsRejectBeforeOutput()
    {
        var fixture = Fixture();
        var mismatchedAccepted = fixture.Accepted with { PayloadSha256 = Hash("foreign-payload") };
        var mismatchedCheckpoint = fixture.Checkpoint with { CheckpointDigest = Hash("foreign-checkpoint") };
        var mismatchedReceipt = new NativeGitOpsCellConvergenceJournalReceipt(
            NativeGitOpsCellConvergenceJournalDisposition.Recorded,
            mismatchedCheckpoint);

        await Assert.That(() => NativeGitOpsCellRuntimeProjector.Project(
                fixture.Scope, mismatchedAccepted, fixture.Verified, fixture.Assignment, Now))
            .Throws<InvalidOperationException>();
        await Assert.That(() => NativeGitOpsCellRuntimeProjector.Project(
                fixture.Scope, fixture.Accepted,
                NativeGitOpsVerifiedConvergenceDispatchV1.FromAuthoritativeJournalReceipt(mismatchedReceipt),
                fixture.Assignment, Now))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task StaleGenerationEpochAndForeignCellOrNodeRejectBeforeOutput()
    {
        var fixture = Fixture();
        var staleGeneration = Assignment(fixture.Accepted, fixture.Checkpoint, workloadGeneration: 2);
        var staleEpoch = Assignment(fixture.Accepted, fixture.Checkpoint, writerEpoch: 8);
        var foreignScope = new RuntimeAssignmentProjectionScopeV1(new("gru"), new("node-b"), new(7));

        await Assert.That(() => NativeGitOpsCellRuntimeProjector.Project(
                fixture.Scope, fixture.Accepted, fixture.Verified, staleGeneration, Now))
            .Throws<InvalidOperationException>();
        await Assert.That(() => NativeGitOpsCellRuntimeProjector.Project(
                fixture.Scope, fixture.Accepted, fixture.Verified, staleEpoch, Now))
            .Throws<InvalidOperationException>();
        await Assert.That(() => NativeGitOpsCellRuntimeProjector.Project(
                foreignScope, fixture.Accepted, fixture.Verified, fixture.Assignment, Now))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task HeldAndNonApplyConvergenceResultsRejectBeforeOutput()
    {
        var fixture = Fixture();
        var held = fixture.Checkpoint with
        {
            Decision = new(
                NativeGitOpsCellConvergenceState.Held,
                NativeGitOpsCellConvergenceHoldReason.InvalidObservation,
                null,
                null)
        };
        var nonApply = fixture.Checkpoint with
        {
            Decision = fixture.Checkpoint.Decision with
            {
                Intent = fixture.Checkpoint.Decision.Intent! with
                {
                    Kind = NativeGitOpsCellConvergenceIntentKind.Observe
                }
            }
        };

        await Assert.That(() => NativeGitOpsVerifiedConvergenceDispatchV1.FromAuthoritativeJournalReceipt(
                new(NativeGitOpsCellConvergenceJournalDisposition.Recorded, held)))
            .Throws<InvalidOperationException>();
        await Assert.That(() => NativeGitOpsCellRuntimeProjector.Project(
                fixture.Scope, fixture.Accepted,
                NativeGitOpsVerifiedConvergenceDispatchV1.FromAuthoritativeJournalReceipt(
                    new(NativeGitOpsCellConvergenceJournalDisposition.Recorded, nonApply)), fixture.Assignment, Now))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task ExpiredEvidenceUnknownVersionsAndPlanTamperingRejectBeforeOutput()
    {
        var fixture = Fixture();
        var expired = fixture.Accepted with { ExpiresAt = Now };
        var unknownVersion = fixture.Accepted with { ProtocolVersion = 2 };
        var futureIssued = fixture.Accepted with { IssuedAt = Now.AddTicks(1) };
        var futureAccepted = fixture.Accepted with { AcceptedAt = Now.AddTicks(1) };
        var impossibleAccepted = fixture.Accepted with { AcceptedAt = fixture.Accepted.ExpiresAt };
        var tamperedPlan = Assignment(fixture.Accepted, fixture.Checkpoint, planFingerprint: Hash("tampered-plan"));

        await Assert.That(() => NativeGitOpsCellRuntimeProjector.Project(
                fixture.Scope, expired, fixture.Verified, fixture.Assignment, Now))
            .Throws<InvalidOperationException>();
        await Assert.That(() => NativeGitOpsCellRuntimeProjector.Project(
                fixture.Scope, unknownVersion, fixture.Verified, fixture.Assignment, Now))
            .Throws<InvalidOperationException>();
        await Assert.That(() => NativeGitOpsCellRuntimeProjector.Project(
                fixture.Scope, futureIssued, fixture.Verified, fixture.Assignment, Now))
            .Throws<InvalidOperationException>();
        await Assert.That(() => NativeGitOpsCellRuntimeProjector.Project(
                fixture.Scope, futureAccepted, fixture.Verified, fixture.Assignment, Now))
            .Throws<InvalidOperationException>();
        await Assert.That(() => NativeGitOpsCellRuntimeProjector.Project(
                fixture.Scope, impossibleAccepted, fixture.Verified, fixture.Assignment, Now))
            .Throws<InvalidOperationException>();
        await Assert.That(() => NativeGitOpsCellRuntimeProjector.Project(
                fixture.Scope, fixture.Accepted, fixture.Verified, tamperedPlan, Now))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task PathsAndSecretBytesCannotEnterThePersistedAssignmentContract()
    {
        await Assert.That(() => new RuntimeConfigId("/etc/terrascale/config.json"))
            .Throws<ArgumentException>();
        await Assert.That(() => new RuntimeSecretVersionId("/var/lib/terrascale/secret"))
            .Throws<ArgumentException>();

        var assignmentProperties = typeof(RuntimeHostAssignmentV1)
            .GetProperties(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
        await Assert.That(assignmentProperties.Any(property =>
                property.PropertyType == typeof(byte[]) ||
                property.PropertyType == typeof(ReadOnlyMemory<byte>) ||
                property.Name.Contains("Path", StringComparison.Ordinal)))
            .IsFalse();
    }

    [Test]
    public async Task ProjectedCommandDoesNotRetainRawAcceptedPayloadOrCheckpointObjects()
    {
        var fixture = Fixture();
        var command = NativeGitOpsCellRuntimeProjector.Project(
            fixture.Scope, fixture.Accepted, fixture.Verified, fixture.Assignment, Now);
        var digest = command.CanonicalDigest;
        var properties = typeof(RuntimeCommandV1)
            .GetProperties(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);

        fixture.MutablePayload[0] ^= 0x01;

        await Assert.That(properties.Any(property =>
                property.PropertyType == typeof(NativeGitOpsAcceptedCellSpec) ||
                property.PropertyType == typeof(NativeGitOpsCellConvergenceCheckpoint) ||
                property.PropertyType == typeof(byte[]) ||
                property.PropertyType == typeof(ReadOnlyMemory<byte>)))
            .IsFalse();
        await Assert.That(command.CanonicalDigest).IsEqualTo(digest);
        await Assert.That(command.AcceptedPayloadDigest.Sha256).IsEqualTo(fixture.Assignment.AcceptedPayloadDigest.Sha256);
    }

    [Test]
    public async Task VerifiedReceiptRejectsTamperedGenesisAndSequenceChains()
    {
        var fixture = Fixture();
        var badGenesis = fixture.Checkpoint with { PreviousCheckpointDigest = Hash("wrong-genesis") };
        var zeroSequence = fixture.Checkpoint with { CheckpointSequence = 0 };
        var missingPredecessor = fixture.Checkpoint with
        {
            CheckpointSequence = 2,
            PreviousCheckpointDigest = Hash("missing-predecessor")
        };

        await Assert.That(() => NativeGitOpsVerifiedConvergenceDispatchV1.FromAuthoritativeJournalReceipt(
                new(NativeGitOpsCellConvergenceJournalDisposition.Recorded, badGenesis)))
            .Throws<InvalidOperationException>();
        await Assert.That(() => NativeGitOpsVerifiedConvergenceDispatchV1.FromAuthoritativeJournalReceipt(
                new(NativeGitOpsCellConvergenceJournalDisposition.Recorded, zeroSequence)))
            .Throws<InvalidOperationException>();
        await Assert.That(() => NativeGitOpsVerifiedConvergenceDispatchV1.FromAuthoritativeJournalReceipt(
                new(NativeGitOpsCellConvergenceJournalDisposition.Recorded, missingPredecessor)))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task PersistedAssignmentCaptureBoundsOversizedAndHostileEnumerables()
    {
        var fixture = Fixture();
        var oversized = Enumerable.Range(0, RuntimeTechnicalLimits.MaximumCapturedItems + 1)
            .Select(static value => new RuntimeSecretVersionId($"secret-{value}"));

        await Assert.That(() => Assignment(fixture.Accepted, fixture.Checkpoint, secretVersions: oversized))
            .Throws<ArgumentException>();
        await Assert.That(() => Assignment(
                fixture.Accepted,
                fixture.Checkpoint,
                secretVersions: new EndlessSecretVersions()))
            .Throws<ArgumentException>();
        await Assert.That(() => Assignment(
                fixture.Accepted,
                fixture.Checkpoint,
                secretVersions: new ThrowingSecretVersions()))
            .Throws<ArgumentException>();
    }

    private static FixtureData Fixture()
    {
        var (accepted, mutablePayload) = Accepted();
        var workload = NativeGitOpsCellPayload.Parse(accepted).DesiredWorkloads.Single();
        var checkpoint = new NativeGitOpsCellConvergenceCheckpoint(
            accepted.Cell,
            accepted.Generation,
            accepted.GlobalPlanDigest,
            accepted.HandoffDigest,
            accepted.PayloadSha256,
            accepted.WriterEpoch,
            accepted.StreamSequence,
            accepted.SignatureSha256,
            accepted.JournalRevision,
            2,
            new(
                NativeGitOpsCellConvergenceState.Pending,
                NativeGitOpsCellConvergenceHoldReason.None,
                new(
                    NativeGitOpsCellConvergenceIntentKind.Apply,
                    workload.Id,
                    accepted.Generation,
                    NativeGitOpsCellSpecCompiler.WorkloadDigest(workload),
                    Hash("observation"),
                    null),
                null),
            1,
            GenesisDigest(),
            Hash("checkpoint"),
            2);
        var assignment = Assignment(accepted, checkpoint);
        var receipt = new NativeGitOpsCellConvergenceJournalReceipt(
            NativeGitOpsCellConvergenceJournalDisposition.Recorded,
            checkpoint);
        return new(
            new(new("gru"), new("node-a"), new(7)),
            accepted,
            checkpoint,
            NativeGitOpsVerifiedConvergenceDispatchV1.FromAuthoritativeJournalReceipt(receipt),
            assignment,
            mutablePayload);
    }

    private static RuntimeHostAssignmentV1 Assignment(
        NativeGitOpsAcceptedCellSpec accepted,
        NativeGitOpsCellConvergenceCheckpoint checkpoint,
        ulong workloadGeneration = 1,
        ulong writerEpoch = 7,
        string? planFingerprint = null,
        IEnumerable<RuntimeSecretVersionId>? secretVersions = null)
    {
        var resources = new HostRuntimeResources(512L * 1024 * 1024, 128, 100, 100, 100, 0);
        var plan = HostRuntimePlan.Create(
            HostRole.CustomerDashboard,
            HostRuntimeDriver.OciContainer,
            new HostRuntimeAllocationId("dashboard-a"),
            new HostArtifactDigest(Artifact),
            HostArchitecture.Arm64,
            resources);
        return new(
            RuntimeHostAssignmentV1.CurrentSchemaVersion,
            new("gru"),
            new("platform"),
            new("platform-a"),
            new("node-a"),
            new(workloadGeneration),
            new(workloadGeneration),
            new(writerEpoch),
            new((ulong)accepted.Generation),
            new(accepted.GlobalPlanDigest),
            new(accepted.HandoffDigest),
            new(accepted.PayloadSha256),
            accepted.StreamSequence,
            new(accepted.SignatureSha256),
            accepted.JournalRevision,
            checkpoint.JournalRevision,
            new(checkpoint.CheckpointDigest),
            HostRole.CustomerDashboard,
            HostRuntimeDriver.OciContainer,
            HostArchitecture.Arm64,
            new(Artifact),
            resources,
            new("platform-config-v1"),
            secretVersions ?? [new RuntimeSecretVersionId("platform-secret-v1")],
            [new RuntimeVolumeBinding(new("platform-state"), VolumeRetention.Ephemeral)],
            [new RuntimePort(8443)],
            new(planFingerprint ?? RuntimeLifecycleFingerprint.Plan(plan).Value),
            new(new(Hash("authorization")), new(new(Hash("deadline")), 9), accepted.ExpiresAt));
    }

    private static (NativeGitOpsAcceptedCellSpec Accepted, byte[] MutablePayload) Accepted()
    {
        var content = Encoding.UTF8.GetBytes($$"""
            {"apiVersion":"terrascale.io/v1","kind":"TerraScaleDesiredState","generation":1,"workloads":[{"id":"platform","role":"CustomerDashboard","artifactDigest":"{{Artifact}}","cells":["gru"],"dependsOn":[],"suspended":false}]}
            """);
        var proposed = NativeGitOpsManifest.Parse(content);
        var handoff = NativeGitOpsCellSpecCompiler.Compile(new(
            new("TerraScale/TerraScale.Orchestrator", "bffeb74224043ba2feb48d137756c8a9331c449a", "117eb74224043ba2feb48d137756c8a9331c44ff", signatureVerified: true),
            new(
                "TerraScale/TerraScale.Orchestrator",
                "bffeb74224043ba2feb48d137756c8a9331c449a",
                NativeGitOpsSourceLoader.ManifestPath,
                "217eb74224043ba2feb48d137756c8a9331c44ee",
                Convert.ToHexStringLower(SHA256.HashData(content)),
                content),
            proposed,
            NativeGitOpsDiff.Compare(null, proposed)));
        var cell = handoff.Cells.Single();
        var mutablePayload = cell.Payload.ToArray();
        return (new(
            cell.Cell,
            cell.Generation,
            cell.GlobalPlanDigest,
            handoff.HandoffDigest,
            cell.PayloadSha256,
            mutablePayload,
            7,
            1,
            $"gitops/{handoff.HandoffDigest}/{cell.Cell}",
            $"gitops/{cell.PayloadSha256}",
            1,
            new(2026, 7, 17, 11, 59, 0, TimeSpan.Zero),
            new(2026, 7, 17, 12, 1, 0, TimeSpan.Zero),
            new(2026, 7, 17, 12, 0, 0, TimeSpan.Zero),
            1,
            Hash("signature"),
            1), mutablePayload);
    }

    private static string Hash(string value) => Convert.ToHexStringLower(
        SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static string GenesisDigest() => Hash("TerraScale.NativeGitOpsCellConvergence.v1");

    private sealed record FixtureData(
        RuntimeAssignmentProjectionScopeV1 Scope,
        NativeGitOpsAcceptedCellSpec Accepted,
        NativeGitOpsCellConvergenceCheckpoint Checkpoint,
        NativeGitOpsVerifiedConvergenceDispatchV1 Verified,
        RuntimeHostAssignmentV1 Assignment,
        byte[] MutablePayload);

    private sealed class ThrowingSecretVersions : IEnumerable<RuntimeSecretVersionId>
    {
        public IEnumerator<RuntimeSecretVersionId> GetEnumerator() => throw new InvalidOperationException("hostile enumerator");
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }

    private sealed class EndlessSecretVersions : IEnumerable<RuntimeSecretVersionId>
    {
        public IEnumerator<RuntimeSecretVersionId> GetEnumerator()
        {
            while (true) yield return new RuntimeSecretVersionId("endless-secret");
        }

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }

    private const string Artifact = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
}
