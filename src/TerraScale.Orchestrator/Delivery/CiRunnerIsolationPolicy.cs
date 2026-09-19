using TerraScale.Orchestrator.ControlPlane.Delivery;

namespace TerraScale.Orchestrator.Delivery;

public enum CiRunnerNodeClass
{
    Unspecified,
    UntrustedProduct,
    TrustedBuild,
    ProductionRelease,
    ControlRecovery,
}

public enum CiRunnerNetworkScope
{
    Unspecified,
    PublicDependenciesOnly,
    ArtifactServicesOnly,
    DeploymentServicesOnly,
    ControlRecoveryOnly,
}

public enum CiRunnerCredentialProfile
{
    Unspecified,
    None,
    CandidatePublishAndSign,
    ProductionPromotion,
    ControlRecovery,
}

public enum CiRunnerCacheScope
{
    Unspecified,
    None,
    UntrustedIsolated,
    TrustedVerified,
}

public enum CiRunnerAdmissionReason
{
    Unspecified,
    Admitted,
    RunnerPolicyDenied,
    IdentityMismatch,
    IsolationMissing,
    HostEscapeRisk,
    NetworkBoundaryViolated,
    CredentialBoundaryViolated,
    CacheBoundaryViolated,
    OutputBoundaryViolated,
    ResourceBoundaryViolated,
}

public sealed record CiRunnerIsolationEvidence(
    JobId Job,
    RunnerId Runner,
    long Sequence,
    TrustZone Zone,
    CiRunnerNodeClass NodeClass,
    CiRunnerNetworkScope NetworkScope,
    CiRunnerCredentialProfile CredentialProfile,
    CiRunnerCacheScope CacheScope,
    bool Ephemeral,
    bool Disposable,
    bool ReadOnlyRootFilesystem,
    bool RootlessBuildKit,
    bool HostDockerSocketMounted,
    bool NoNewPrivileges,
    bool UserNamespace,
    bool Seccomp,
    bool CgroupV2,
    bool MetadataServiceReachable,
    bool WorkloadIdentityBound,
    bool CredentialsShortLived,
    bool CredentialsPhaseScoped,
    bool LogsRedacted,
    bool LogSecretScanPassed,
    int CpuMilliCores,
    long MemoryBytes,
    long EphemeralDiskBytes,
    int Pids,
    long MaximumLogBytes);

public sealed class CiRunnerAdmission
{
    internal CiRunnerAdmission(bool accepted, CiRunnerAdmissionReason reason)
    {
        Accepted = accepted;
        Reason = reason;
    }

    public bool Accepted { get; }
    public CiRunnerAdmissionReason Reason { get; }
}

/// <summary>Admits a selected runner only with exact trust-zone isolation evidence.</summary>
public static class CiRunnerIsolationPolicy
{
    private const long Mebibyte = 1024 * 1024;
    private const long Gibibyte = 1024 * Mebibyte;

    public static CiRunnerAdmission Evaluate(
        JobRequest job,
        RunnerEvidence runner,
        CiRunnerIsolationEvidence evidence)
    {
        ArgumentNullException.ThrowIfNull(job);
        ArgumentNullException.ThrowIfNull(runner);
        ArgumentNullException.ThrowIfNull(evidence);
        var runnerDecision = DeliveryEngine.DecideJob(job, [runner], 256);
        if (runnerDecision.Errors.Count != 0)
            return Deny(CiRunnerAdmissionReason.RunnerPolicyDenied);
        if (evidence.Job != job.Job || evidence.Runner != runner.Runner ||
            evidence.Sequence != runner.Sequence || evidence.Zone != runner.Zone)
            return Deny(CiRunnerAdmissionReason.IdentityMismatch);
        if (evidence.NodeClass != NodeClass(runner.Zone) || !evidence.Ephemeral ||
            !evidence.Disposable || !evidence.ReadOnlyRootFilesystem ||
            !evidence.NoNewPrivileges || !evidence.UserNamespace || !evidence.Seccomp || !evidence.CgroupV2)
            return Deny(CiRunnerAdmissionReason.IsolationMissing);
        if (evidence.HostDockerSocketMounted ||
            job.RequiredCapabilities.Contains(RunnerCapability.Compile) && !evidence.RootlessBuildKit)
            return Deny(CiRunnerAdmissionReason.HostEscapeRisk);
        // The only reachability claim the evidence may carry is the one the runner actually
        // probes (the OCI metadata service, via a TCP probe of the build's NAT egress path).
        // Scope labels below state the required boundary; they are never treated as proof that
        // an unprobed network path is unreachable.
        if (evidence.MetadataServiceReachable ||
            evidence.NetworkScope != Network(runner.Zone))
            return Deny(CiRunnerAdmissionReason.NetworkBoundaryViolated);
        if (!evidence.WorkloadIdentityBound || !evidence.CredentialsShortLived ||
            !evidence.CredentialsPhaseScoped || evidence.CredentialProfile != Credentials(job, runner.Zone))
            return Deny(CiRunnerAdmissionReason.CredentialBoundaryViolated);
        if (evidence.CacheScope != Cache(runner.Zone))
            return Deny(CiRunnerAdmissionReason.CacheBoundaryViolated);
        if (!evidence.LogsRedacted || !evidence.LogSecretScanPassed ||
            evidence.MaximumLogBytes is < Mebibyte or > 512 * Mebibyte)
            return Deny(CiRunnerAdmissionReason.OutputBoundaryViolated);
        if (evidence.CpuMilliCores is < 100 or > 8_000 ||
            evidence.MemoryBytes is < 256 * Mebibyte or > 8 * Gibibyte ||
            evidence.EphemeralDiskBytes is < Gibibyte or > 200 * Gibibyte ||
            evidence.Pids is < 64 or > 4_096)
            return Deny(CiRunnerAdmissionReason.ResourceBoundaryViolated);
        return new(true, CiRunnerAdmissionReason.Admitted);
    }

    private static CiRunnerNodeClass NodeClass(TrustZone zone) => zone switch
    {
        TrustZone.UntrustedProduct => CiRunnerNodeClass.UntrustedProduct,
        TrustZone.TrustedBuild => CiRunnerNodeClass.TrustedBuild,
        TrustZone.ProductionRelease => CiRunnerNodeClass.ProductionRelease,
        TrustZone.ControlRecovery => CiRunnerNodeClass.ControlRecovery,
        _ => CiRunnerNodeClass.Unspecified,
    };

    private static CiRunnerNetworkScope Network(TrustZone zone) => zone switch
    {
        TrustZone.UntrustedProduct => CiRunnerNetworkScope.PublicDependenciesOnly,
        TrustZone.TrustedBuild => CiRunnerNetworkScope.ArtifactServicesOnly,
        TrustZone.ProductionRelease => CiRunnerNetworkScope.DeploymentServicesOnly,
        TrustZone.ControlRecovery => CiRunnerNetworkScope.ControlRecoveryOnly,
        _ => CiRunnerNetworkScope.Unspecified,
    };

    private static CiRunnerCredentialProfile Credentials(JobRequest job, TrustZone zone) => zone switch
    {
        TrustZone.UntrustedProduct => CiRunnerCredentialProfile.None,
        TrustZone.TrustedBuild when job.RequiredCapabilities.Contains(RunnerCapability.Sign) =>
            CiRunnerCredentialProfile.CandidatePublishAndSign,
        TrustZone.TrustedBuild => CiRunnerCredentialProfile.None,
        TrustZone.ProductionRelease => CiRunnerCredentialProfile.ProductionPromotion,
        TrustZone.ControlRecovery => CiRunnerCredentialProfile.ControlRecovery,
        _ => CiRunnerCredentialProfile.Unspecified,
    };

    private static CiRunnerCacheScope Cache(TrustZone zone) => zone switch
    {
        TrustZone.UntrustedProduct => CiRunnerCacheScope.UntrustedIsolated,
        TrustZone.TrustedBuild => CiRunnerCacheScope.TrustedVerified,
        TrustZone.ProductionRelease or TrustZone.ControlRecovery => CiRunnerCacheScope.None,
        _ => CiRunnerCacheScope.Unspecified,
    };

    private static CiRunnerAdmission Deny(CiRunnerAdmissionReason reason) => new(false, reason);
}

