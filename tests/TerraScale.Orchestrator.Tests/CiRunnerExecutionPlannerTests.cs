using System.Collections.Concurrent;
using System.Text;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Tests;

public sealed class CiRunnerExecutionPlannerTests
{
    private const string Repository = "TerraScale/TerraScale.Orchestrator";
    private static readonly DateTimeOffset Now = new(2026, 7, 17, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task UntrustedNodeCompilesToOneFixedCommandFreeBuildKitTarget()
    {
        var accepted = await RepositoryCiJobInboxTests.AcceptedAsync();
        var runner = Runner(accepted.Command);
        var isolation = Isolation(accepted.Command);

        var first = CiRunnerExecutionPlanner.Create(accepted, runner, isolation);
        var second = CiRunnerExecutionPlanner.Create(accepted, runner, isolation);

        await Assert.That(first.Source.Repository).IsEqualTo(accepted.Command.Repository);
        await Assert.That(first.Source.Commit).IsEqualTo(accepted.Command.SourceCommit);
        await Assert.That(first.Source.Tree).IsEqualTo(accepted.Command.SourceTree);
        await Assert.That(first.Source.BundleObject).IsEqualTo(accepted.Command.SourceBundleObject);
        await Assert.That(first.Source.BundleSha256).IsEqualTo(accepted.Command.SourceBundleSha256);
        await Assert.That(first.Source.BundleBytes).IsEqualTo(accepted.Command.SourceBundleBytes);
        await Assert.That(first.Source.DescriptorPath).IsEqualTo(".terrascale/ci-v2.json");
        await Assert.That(first.Source.RecipePath).IsEqualTo(".terrascale/ci.Dockerfile");
        await Assert.That(first.Build.Frontend).IsEqualTo("dockerfile.v0");
        await Assert.That(first.Build.Target).IsEqualTo($"ci-{accepted.Command.NodeId}");
        await Assert.That(first.Build.Architectures).IsEquivalentTo([RepositoryCiArchitecture.Any]);
        await Assert.That(first.Build.Output).IsEqualTo(CiRunnerExecutionOutputKind.Evidence);
        await Assert.That(first.Build.Network).IsEqualTo(CiRunnerNetworkScope.PublicDependenciesOnly);
        await Assert.That(first.Build.Credentials).IsEqualTo(CiRunnerCredentialProfile.None);
        await Assert.That(first.Build.CacheNamespace).IsEqualTo($"untrusted-{accepted.Command.JobDigest}");
        await Assert.That(first.Build.Timeout).IsEqualTo(TimeSpan.FromMinutes(15));
        await Assert.That(first.Digest).IsEqualTo(second.Digest);
    }

    [Test]
    public async Task NativeArtifactRetainsBothPlatformsAndTrustedPhaseBoundaries()
    {
        var value = await TrustedArtifactAsync();

        var plan = CiRunnerExecutionPlanner.Create(value.Accepted, value.Runner, value.Isolation);

        await Assert.That(plan.Build.Target).IsEqualTo("ci-candidate");
        await Assert.That(plan.Build.Architectures).IsEquivalentTo([
            RepositoryCiArchitecture.LinuxX64,
            RepositoryCiArchitecture.LinuxArm64]);
        await Assert.That(plan.Build.Output).IsEqualTo(CiRunnerExecutionOutputKind.CandidateArtifacts);
        await Assert.That(plan.Build.Network).IsEqualTo(CiRunnerNetworkScope.ArtifactServicesOnly);
        await Assert.That(plan.Build.Credentials)
            .IsEqualTo(CiRunnerCredentialProfile.CandidatePublishAndSign);
        await Assert.That(plan.Build.Cache).IsEqualTo(CiRunnerCacheScope.TrustedVerified);
        await Assert.That(plan.Build.CacheNamespace).StartsWith("trusted-");
        await Assert.That(plan.Build.Timeout).IsEqualTo(TimeSpan.FromHours(1));
        await Assert.That(value.Accepted.Command.Architectures)
            .IsEquivalentTo(value.Pipeline.Jobs.Single().Plan.Node.Architectures);
    }

    [Test]
    public async Task WrongRunnerChangedIsolationAndInventedAcceptanceFailClosed()
    {
        var accepted = await RepositoryCiJobInboxTests.AcceptedAsync();
        var runner = Runner(accepted.Command);
        var isolation = Isolation(accepted.Command);

        await Assert.That(() => CiRunnerExecutionPlanner.Create(
                accepted,
                new(new("runner-other"), runner.Zone, runner.Sequence, true, runner.Capabilities),
                isolation))
            .Throws<InvalidDataException>();
        await Assert.That(() => CiRunnerExecutionPlanner.Create(
                accepted,
                runner,
                isolation with { MemoryBytes = isolation.MemoryBytes + 1 }))
            .Throws<InvalidDataException>();
        await Assert.That(() => CiRunnerExecutionPlanner.Create(
                accepted with { PayloadDigest = new string('f', 64) },
                runner,
                isolation))
            .Throws<InvalidDataException>();
    }

    [Test]
    public async Task PlanDigestIsCultureInvariant()
    {
        var accepted = await RepositoryCiJobInboxTests.AcceptedAsync();
        var runner = Runner(accepted.Command);
        var isolation = Isolation(accepted.Command);
        var original = System.Globalization.CultureInfo.CurrentCulture;
        try
        {
            System.Globalization.CultureInfo.CurrentCulture = new("ar-SA");
            var arabic = CiRunnerExecutionPlanner.Create(accepted, runner, isolation);
            System.Globalization.CultureInfo.CurrentCulture = new("fr-FR");
            var french = CiRunnerExecutionPlanner.Create(accepted, runner, isolation);

            await Assert.That(arabic.Digest).IsEqualTo(french.Digest);
        }
        finally
        {
            System.Globalization.CultureInfo.CurrentCulture = original;
        }
    }

    private static RunnerEvidence Runner(RepositoryCiJobWireDocument command) => new(
        new(command.Runner),
        command.AllowedZones.Single(),
        command.RunnerSequence,
        true,
        command.RequiredCapabilities);

    private static CiRunnerIsolationEvidence Isolation(RepositoryCiJobWireDocument command)
    {
        var zone = command.AllowedZones.Single();
        var signing = command.RequiredCapabilities.Contains(RunnerCapability.Sign);
        return new(
            new(command.Job),
            new(command.Runner),
            command.RunnerSequence,
            zone,
            zone == TrustZone.UntrustedProduct
                ? CiRunnerNodeClass.UntrustedProduct
                : CiRunnerNodeClass.TrustedBuild,
            zone == TrustZone.UntrustedProduct
                ? CiRunnerNetworkScope.PublicDependenciesOnly
                : CiRunnerNetworkScope.ArtifactServicesOnly,
            signing ? CiRunnerCredentialProfile.CandidatePublishAndSign : CiRunnerCredentialProfile.None,
            zone == TrustZone.UntrustedProduct
                ? CiRunnerCacheScope.UntrustedIsolated
                : CiRunnerCacheScope.TrustedVerified,
            Ephemeral: true,
            Disposable: true,
            ReadOnlyRootFilesystem: true,
            RootlessBuildKit: true,
            HostDockerSocketMounted: false,
            NoNewPrivileges: true,
            UserNamespace: true,
            Seccomp: true,
            CgroupV2: true,
            MetadataServiceReachable: false,
            ProductionNetworkReachable: false,
            ControlNatsReachable: false,
            DatabaseReachable: false,
            WorkloadIdentityBound: true,
            CredentialsShortLived: true,
            CredentialsPhaseScoped: true,
            LogsRedacted: true,
            LogSecretScanPassed: true,
            CpuMilliCores: 1_000,
            MemoryBytes: 512L * 1024 * 1024,
            EphemeralDiskBytes: 1024L * 1024 * 1024,
            Pids: 128,
            MaximumLogBytes: 16L * 1024 * 1024);
    }

    private static async Task<TrustedArtifact> TrustedArtifactAsync()
    {
        var pipeline = ReleasePipeline();
        var job = pipeline.Jobs.Single();
        var runner = new RunnerEvidence(
            new("runner-candidate"),
            TrustZone.TrustedBuild,
            20,
            true,
            job.Request.RequiredCapabilities);
        var isolation = Isolation(job, runner);
        var journal = new RepositoryCiJobJournal(
            new ForgejoWebhookJournalTests.TestLedger(),
            new FixedTimeProvider(Now));
        await journal.InitializeAsync(pipeline, 5, 9, static () => true);
        var prepared = await journal.PrepareDispatchAsync(
            pipeline,
            job.Request.Job,
            RepositoryCiJobJournalTests.SourceBundle(job),
            runner,
            isolation,
            "gru-controller-1",
            5,
            "dispatch-native-candidate",
            static () => true);
        var wire = RepositoryCiJobWireCodec.Encode(pipeline, prepared.Job!, new TestSigner([71]));
        var decoded = RepositoryCiJobWireCodec.Decode(wire.Payload, wire.Headers);
        var accepted = await new RepositoryCiJobAcceptanceJournal(
            new ForgejoWebhookJournalTests.TestLedger(),
            new TestPayloadStore()).AcceptAsync(
                decoded,
                runner.Runner.Value,
                201,
                Now,
                TimeSpan.Zero,
                new TestVerifier([71]));
        return new(pipeline, accepted.Acceptance!, runner, isolation);
    }

    private static RepositoryCiPipelinePlan ReleasePipeline()
    {
        var descriptor = RepositoryCiDescriptor.Parse(Encoding.UTF8.GetBytes($$"""
            {
              "apiVersion":"terrascale.ci/v2",
              "repository":"{{Repository}}",
              "candidateRetentionDays":7,
              "promotion":"NativeRolling",
              "repositoryDependencies":[],
              "nodes":[
                {"id":"candidate","kind":"Artifact","resourceWeight":"Heavy","profiles":["Release"],"paths":["src/"]}
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
            new string('d', 40),
            "bffeb74224043ba2feb48d137756c8a9331c449a",
            "develop",
            "main",
            42,
            false,
            new string('a', 64));
        return RepositoryCiPipelinePlanner.Plan(
            ForgejoCiTriggerPlanner.Plan(envelope),
            impact,
            [new ForgejoResolvedRevision(
                Repository,
                "bffeb74224043ba2feb48d137756c8a9331c449a",
                "117eb74224043ba2feb48d137756c8a9331c44ff",
                true)],
            7,
            10,
            100);
    }

    private static CiRunnerIsolationEvidence Isolation(
        RepositoryCiPipelineJob job,
        RunnerEvidence runner) => new(
        job.Request.Job,
        runner.Runner,
        runner.Sequence,
        runner.Zone,
        CiRunnerNodeClass.TrustedBuild,
        CiRunnerNetworkScope.ArtifactServicesOnly,
        CiRunnerCredentialProfile.CandidatePublishAndSign,
        CiRunnerCacheScope.TrustedVerified,
        true,
        true,
        true,
        true,
        false,
        true,
        true,
        true,
        true,
        false,
        false,
        false,
        false,
        true,
        true,
        true,
        true,
        true,
        1_000,
        512L * 1024 * 1024,
        1024L * 1024 * 1024,
        128,
        16L * 1024 * 1024);

    private sealed class TestSigner(byte[] signature) : IRepositoryCiJobSigner
    {
        public OpaqueSignature Sign(CommandSignedMaterial material)
        {
            OpaqueSignature.TryCopyFrom(signature, out var value);
            return value!;
        }
    }

    private sealed class TestVerifier(byte[] expected) : ICommandSignatureVerifier
    {
        public VerificationOutcome Verify(CommandSignedMaterial signedMaterial, OpaqueSignature signature) =>
            signature.Bytes.SequenceEqual(expected) ? VerificationOutcome.Valid : VerificationOutcome.Invalid;
    }

    private sealed class TestPayloadStore : IDeliveryObjectStore
    {
        private readonly ConcurrentDictionary<string, byte[]> values = new(StringComparer.Ordinal);

        public Task PutAsync(string name, ReadOnlyMemory<byte> content, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            values[name] = content.ToArray();
            return Task.CompletedTask;
        }

        public Task<byte[]> GetAsync(string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(values.TryGetValue(name, out var content)
                ? content.ToArray()
                : throw new IOException("Missing runner plan test payload."));
        }
    }

    private sealed class FixedTimeProvider(DateTimeOffset value) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => value;
    }

    private sealed record TrustedArtifact(
        RepositoryCiPipelinePlan Pipeline,
        RepositoryCiAcceptedJob Accepted,
        RunnerEvidence Runner,
        CiRunnerIsolationEvidence Isolation);
}
