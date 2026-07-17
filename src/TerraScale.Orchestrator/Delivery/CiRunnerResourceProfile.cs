using TerraScale.Orchestrator.ControlPlane.Delivery;

namespace TerraScale.Orchestrator.Delivery;

internal static class CiRunnerResourceProfile
{
    internal const int CpuMilliCores = 4_000;
    internal const long MemoryBytes = 8L * 1024 * 1024 * 1024;
    internal const long EphemeralDiskBytes = 50L * 1024 * 1024 * 1024;
    internal const int Pids = 4_096;
    internal const long MaximumLogBytes = 64L * 1024 * 1024;

    internal static CiRunnerIsolationEvidence Isolation(JobRequest job, RunnerEvidence runner)
    {
        ArgumentNullException.ThrowIfNull(job);
        ArgumentNullException.ThrowIfNull(runner);
        var signing = job.RequiredCapabilities.Contains(RunnerCapability.Sign);
        return new(
            job.Job,
            runner.Runner,
            runner.Sequence,
            runner.Zone,
            runner.Zone == TrustZone.UntrustedProduct
                ? CiRunnerNodeClass.UntrustedProduct
                : CiRunnerNodeClass.TrustedBuild,
            runner.Zone == TrustZone.UntrustedProduct
                ? CiRunnerNetworkScope.PublicDependenciesOnly
                : CiRunnerNetworkScope.ArtifactServicesOnly,
            runner.Zone == TrustZone.TrustedBuild && signing
                ? CiRunnerCredentialProfile.CandidatePublishAndSign
                : CiRunnerCredentialProfile.None,
            runner.Zone == TrustZone.UntrustedProduct
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
            CpuMilliCores,
            MemoryBytes,
            EphemeralDiskBytes,
            Pids,
            MaximumLogBytes);
    }
}
