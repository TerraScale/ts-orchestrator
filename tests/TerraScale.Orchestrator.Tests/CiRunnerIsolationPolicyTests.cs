using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

public sealed class CiRunnerIsolationPolicyTests
{
    [Test]
    public async Task ExactIsolationProfilesAdmitAllFourClosedTrustZones()
    {
        var cases = new[]
        {
            Case(JobKind.ProductValidation, TrustZone.UntrustedProduct,
                [RunnerCapability.Compile, RunnerCapability.Test]),
            Case(JobKind.TrustedBuild, TrustZone.TrustedBuild,
                [RunnerCapability.Compile, RunnerCapability.Test, RunnerCapability.Sign]),
            Case(JobKind.Promotion, TrustZone.ProductionRelease,
                [RunnerCapability.Promote, RunnerCapability.ProductionDeploy]),
            Case(JobKind.ControlRecovery, TrustZone.ControlRecovery,
                [RunnerCapability.ControlRecover]),
        };

        foreach (var value in cases)
        {
            var admission = CiRunnerIsolationPolicy.Evaluate(value.Job, value.Runner, value.Evidence);
            await Assert.That(admission.Accepted).IsTrue();
            await Assert.That(admission.Reason).IsEqualTo(CiRunnerAdmissionReason.Admitted);
        }
    }

    [Test]
    public async Task UntrustedJobsRejectProbedMetadataReachabilityAndHostEscape()
    {
        var value = Case(JobKind.ProductValidation, TrustZone.UntrustedProduct,
            [RunnerCapability.Compile, RunnerCapability.Test]);
        var cases = new[]
        {
            // The one reachability fact evidence may carry: the runner's TCP probe of the
            // metadata service on the build's NAT egress path.
            value.Evidence with { MetadataServiceReachable = true },
            value.Evidence with { HostDockerSocketMounted = true },
            value.Evidence with { RootlessBuildKit = false },
            value.Evidence with { NetworkScope = CiRunnerNetworkScope.DeploymentServicesOnly },
            value.Evidence with { NodeClass = CiRunnerNodeClass.TrustedBuild },
        };

        foreach (var evidence in cases)
            await Assert.That(CiRunnerIsolationPolicy.Evaluate(value.Job, value.Runner, evidence).Accepted).IsFalse();
    }

    [Test]
    public async Task TrustedSigningCredentialsAndVerifiedCachesArePhaseExact()
    {
        var signed = Case(JobKind.TrustedBuild, TrustZone.TrustedBuild,
            [RunnerCapability.Compile, RunnerCapability.Sign]);
        await Assert.That(CiRunnerIsolationPolicy.Evaluate(
                signed.Job,
                signed.Runner,
                signed.Evidence with { CredentialProfile = CiRunnerCredentialProfile.None }).Reason)
            .IsEqualTo(CiRunnerAdmissionReason.CredentialBoundaryViolated);
        await Assert.That(CiRunnerIsolationPolicy.Evaluate(
                signed.Job,
                signed.Runner,
                signed.Evidence with { CacheScope = CiRunnerCacheScope.UntrustedIsolated }).Reason)
            .IsEqualTo(CiRunnerAdmissionReason.CacheBoundaryViolated);

        var compileOnly = Case(JobKind.TrustedBuild, TrustZone.TrustedBuild, [RunnerCapability.Compile]);
        await Assert.That(compileOnly.Evidence.CredentialProfile).IsEqualTo(CiRunnerCredentialProfile.None);
        await Assert.That(CiRunnerIsolationPolicy.Evaluate(
                compileOnly.Job, compileOnly.Runner, compileOnly.Evidence).Accepted)
            .IsTrue();
    }

    [Test]
    public async Task IdentityOutputAndResourceEvidenceFailClosed()
    {
        var value = Case(JobKind.TrustedBuild, TrustZone.TrustedBuild,
            [RunnerCapability.Compile, RunnerCapability.Sign]);
        var cases = new[]
        {
            value.Evidence with { Sequence = value.Evidence.Sequence + 1 },
            value.Evidence with { LogsRedacted = false },
            value.Evidence with { LogSecretScanPassed = false },
            value.Evidence with { MaximumLogBytes = 513L * 1024 * 1024 },
            value.Evidence with { MemoryBytes = 9L * 1024 * 1024 * 1024 },
            value.Evidence with { Pids = 4_097 },
            value.Evidence with { UserNamespace = false },
        };

        foreach (var evidence in cases)
            await Assert.That(CiRunnerIsolationPolicy.Evaluate(value.Job, value.Runner, evidence).Accepted).IsFalse();
    }

    [Test]
    public async Task ProductionAndRecoveryCredentialsCannotCrossZones()
    {
        var production = Case(JobKind.Promotion, TrustZone.ProductionRelease,
            [RunnerCapability.Promote, RunnerCapability.ProductionDeploy]);
        var recovery = Case(JobKind.ControlRecovery, TrustZone.ControlRecovery,
            [RunnerCapability.ControlRecover]);

        await Assert.That(CiRunnerIsolationPolicy.Evaluate(
                production.Job,
                production.Runner,
                production.Evidence with
                {
                    CredentialProfile = CiRunnerCredentialProfile.ControlRecovery,
                    NetworkScope = CiRunnerNetworkScope.ControlRecoveryOnly,
                }).Accepted)
            .IsFalse();
        await Assert.That(CiRunnerIsolationPolicy.Evaluate(
                recovery.Job,
                recovery.Runner,
                recovery.Evidence with { CredentialProfile = CiRunnerCredentialProfile.ProductionPromotion }).Accepted)
            .IsFalse();
    }

    private static RunnerCase Case(JobKind kind, TrustZone zone, RunnerCapability[] capabilities)
    {
        var job = new JobRequest(
            new("pipeline"),
            new("job"),
            kind,
            new(new string('a', 40)),
            1,
            1,
            3,
            new("idempotency"),
            [zone],
            capabilities,
            10,
            100,
            false);
        var runner = new RunnerEvidence(new("runner"), zone, 20, true, capabilities);
        var sign = capabilities.Contains(RunnerCapability.Sign);
        var evidence = new CiRunnerIsolationEvidence(
            job.Job,
            runner.Runner,
            runner.Sequence,
            zone,
            NodeClass(zone),
            Network(zone),
            zone switch
            {
                TrustZone.TrustedBuild when sign => CiRunnerCredentialProfile.CandidatePublishAndSign,
                TrustZone.ProductionRelease => CiRunnerCredentialProfile.ProductionPromotion,
                TrustZone.ControlRecovery => CiRunnerCredentialProfile.ControlRecovery,
                _ => CiRunnerCredentialProfile.None,
            },
            zone switch
            {
                TrustZone.UntrustedProduct => CiRunnerCacheScope.UntrustedIsolated,
                TrustZone.TrustedBuild => CiRunnerCacheScope.TrustedVerified,
                _ => CiRunnerCacheScope.None,
            },
            Ephemeral: true,
            Disposable: true,
            ReadOnlyRootFilesystem: true,
            RootlessBuildKit: capabilities.Contains(RunnerCapability.Compile),
            HostDockerSocketMounted: false,
            NoNewPrivileges: true,
            UserNamespace: true,
            Seccomp: true,
            CgroupV2: true,
            MetadataServiceReachable: false,
            WorkloadIdentityBound: true,
            CredentialsShortLived: true,
            CredentialsPhaseScoped: true,
            LogsRedacted: true,
            LogSecretScanPassed: true,
            CpuMilliCores: 2_000,
            MemoryBytes: 2L * 1024 * 1024 * 1024,
            EphemeralDiskBytes: 20L * 1024 * 1024 * 1024,
            Pids: 512,
            MaximumLogBytes: 64L * 1024 * 1024);
        return new(job, runner, evidence);
    }

    private static CiRunnerNodeClass NodeClass(TrustZone zone) => zone switch
    {
        TrustZone.UntrustedProduct => CiRunnerNodeClass.UntrustedProduct,
        TrustZone.TrustedBuild => CiRunnerNodeClass.TrustedBuild,
        TrustZone.ProductionRelease => CiRunnerNodeClass.ProductionRelease,
        TrustZone.ControlRecovery => CiRunnerNodeClass.ControlRecovery,
        _ => throw new ArgumentOutOfRangeException(nameof(zone)),
    };

    private static CiRunnerNetworkScope Network(TrustZone zone) => zone switch
    {
        TrustZone.UntrustedProduct => CiRunnerNetworkScope.PublicDependenciesOnly,
        TrustZone.TrustedBuild => CiRunnerNetworkScope.ArtifactServicesOnly,
        TrustZone.ProductionRelease => CiRunnerNetworkScope.DeploymentServicesOnly,
        TrustZone.ControlRecovery => CiRunnerNetworkScope.ControlRecoveryOnly,
        _ => throw new ArgumentOutOfRangeException(nameof(zone)),
    };

    private sealed record RunnerCase(
        JobRequest Job,
        RunnerEvidence Runner,
        CiRunnerIsolationEvidence Evidence);
}

