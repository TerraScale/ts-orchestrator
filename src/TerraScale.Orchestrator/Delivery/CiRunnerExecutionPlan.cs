using System.Collections.ObjectModel;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.ControlPlane.Delivery;

namespace TerraScale.Orchestrator.Delivery;

internal enum CiRunnerExecutionOutputKind
{
    Unspecified,
    Evidence,
    CandidateArtifacts,
}

internal sealed record CiRunnerSourcePlan(
    string Repository,
    string Commit,
    string Tree,
    string DescriptorPath,
    string RecipePath);

internal sealed class CiRunnerBuildKitPlan
{
    internal CiRunnerBuildKitPlan(
        string frontend,
        string target,
        IEnumerable<RepositoryCiArchitecture> architectures,
        CiRunnerExecutionOutputKind output,
        CiRunnerNetworkScope network,
        CiRunnerCredentialProfile credentials,
        CiRunnerCacheScope cache,
        string cacheNamespace,
        int cpuMilliCores,
        long memoryBytes,
        long ephemeralDiskBytes,
        int pids,
        long maximumLogBytes,
        TimeSpan timeout)
    {
        Frontend = frontend;
        Target = target;
        Architectures = Array.AsReadOnly(architectures.ToArray());
        Output = output;
        Network = network;
        Credentials = credentials;
        Cache = cache;
        CacheNamespace = cacheNamespace;
        CpuMilliCores = cpuMilliCores;
        MemoryBytes = memoryBytes;
        EphemeralDiskBytes = ephemeralDiskBytes;
        Pids = pids;
        MaximumLogBytes = maximumLogBytes;
        Timeout = timeout;
    }

    internal string Frontend { get; }
    internal string Target { get; }
    internal ReadOnlyCollection<RepositoryCiArchitecture> Architectures { get; }
    internal CiRunnerExecutionOutputKind Output { get; }
    internal CiRunnerNetworkScope Network { get; }
    internal CiRunnerCredentialProfile Credentials { get; }
    internal CiRunnerCacheScope Cache { get; }
    internal string CacheNamespace { get; }
    internal int CpuMilliCores { get; }
    internal long MemoryBytes { get; }
    internal long EphemeralDiskBytes { get; }
    internal int Pids { get; }
    internal long MaximumLogBytes { get; }
    internal TimeSpan Timeout { get; }
}

internal sealed class CiRunnerExecutionPlan
{
    internal CiRunnerExecutionPlan(
        string pipelineDigest,
        string job,
        string jobDigest,
        string executionIdentityDigest,
        int attempt,
        CiRunnerSourcePlan source,
        CiRunnerBuildKitPlan build)
    {
        SchemaVersion = 1;
        PipelineDigest = pipelineDigest;
        Job = job;
        JobDigest = jobDigest;
        ExecutionIdentityDigest = executionIdentityDigest;
        Attempt = attempt;
        Source = source;
        Build = build;
        Digest = CiRunnerExecutionPlanner.Digest(this);
    }

    internal int SchemaVersion { get; }
    internal string PipelineDigest { get; }
    internal string Job { get; }
    internal string JobDigest { get; }
    internal string ExecutionIdentityDigest { get; }
    internal int Attempt { get; }
    internal CiRunnerSourcePlan Source { get; }
    internal CiRunnerBuildKitPlan Build { get; }
    internal string Digest { get; }
}

/// <summary>
/// Compiles one accepted repository node into a fixed rootless-BuildKit recipe target. Repository
/// policy can select only the node ID; it cannot supply an executable, argument, host path, or
/// BuildKit endpoint to the runner process.
/// </summary>
internal static class CiRunnerExecutionPlanner
{
    internal const string Frontend = "dockerfile.v0";
    internal const string RecipePath = ".terrascale/ci.Dockerfile";

    internal static CiRunnerExecutionPlan Create(
        RepositoryCiAcceptedJob accepted,
        RunnerEvidence runner,
        CiRunnerIsolationEvidence isolation)
    {
        RepositoryCiJobExecutionJournal.ValidateAccepted(accepted);
        ArgumentNullException.ThrowIfNull(runner);
        ArgumentNullException.ThrowIfNull(isolation);
        var command = accepted.Command;
        if (runner.Runner.Value != command.Runner || runner.Sequence != command.RunnerSequence ||
            RepositoryCiJobJournal.IsolationDigest(isolation) != command.IsolationDigest)
            throw new InvalidDataException("The CI runner execution inputs do not match the accepted command.");

        var job = new JobRequest(
            new(command.Pipeline),
            new(command.Job),
            command.Kind,
            new(command.Tree),
            command.Generation,
            command.Attempt,
            command.MaximumAttempts,
            new(command.Idempotency),
            command.AllowedZones,
            command.RequiredCapabilities,
            command.MinimumRunnerSequence,
            command.MaximumRunnerSequence,
            command.RetryAuthorized);
        var admission = CiRunnerIsolationPolicy.Evaluate(job, runner, isolation);
        if (!admission.Accepted || !isolation.RootlessBuildKit || isolation.HostDockerSocketMounted)
            throw new InvalidDataException("The accepted CI job does not have executable runner isolation.");

        var output = command.NodeKind == RepositoryCiNodeKind.Artifact
            ? CiRunnerExecutionOutputKind.CandidateArtifacts
            : CiRunnerExecutionOutputKind.Evidence;
        var build = new CiRunnerBuildKitPlan(
            Frontend,
            $"ci-{command.NodeId}",
            command.Architectures,
            output,
            isolation.NetworkScope,
            isolation.CredentialProfile,
            isolation.CacheScope,
            CacheNamespace(command, isolation.CacheScope),
            isolation.CpuMilliCores,
            isolation.MemoryBytes,
            isolation.EphemeralDiskBytes,
            isolation.Pids,
            isolation.MaximumLogBytes,
            Timeout(command.ResourceWeight));
        return new(
            command.PipelineDigest,
            command.Job,
            command.JobDigest,
            accepted.ExecutionIdentityDigest,
            command.Attempt,
            new(
                command.Repository,
                command.SourceCommit,
                command.SourceTree,
                RepositoryCiImpactPlanner.DescriptorPath,
                RecipePath),
            build);
    }

    internal static string Digest(CiRunnerExecutionPlan plan)
    {
        var build = plan.Build;
        var value = new StringBuilder()
            .Append(plan.SchemaVersion.ToString(CultureInfo.InvariantCulture)).Append('\n')
            .Append(plan.PipelineDigest).Append(':').Append(plan.Job).Append(':')
            .Append(plan.JobDigest).Append(':').Append(plan.ExecutionIdentityDigest).Append(':')
            .Append(plan.Attempt.ToString(CultureInfo.InvariantCulture)).Append('\n')
            .Append(plan.Source.Repository).Append(':').Append(plan.Source.Commit).Append(':')
            .Append(plan.Source.Tree).Append(':').Append(plan.Source.DescriptorPath).Append(':')
            .Append(plan.Source.RecipePath).Append('\n')
            .Append(build.Frontend).Append(':').Append(build.Target).Append(':').Append(build.Output).Append('\n')
            .AppendJoin(',', build.Architectures).Append('\n')
            .Append(build.Network).Append(':').Append(build.Credentials).Append(':')
            .Append(build.Cache).Append(':').Append(build.CacheNamespace).Append('\n')
            .Append(build.CpuMilliCores.ToString(CultureInfo.InvariantCulture)).Append(':')
            .Append(build.MemoryBytes.ToString(CultureInfo.InvariantCulture)).Append(':')
            .Append(build.EphemeralDiskBytes.ToString(CultureInfo.InvariantCulture)).Append(':')
            .Append(build.Pids.ToString(CultureInfo.InvariantCulture)).Append(':')
            .Append(build.MaximumLogBytes.ToString(CultureInfo.InvariantCulture)).Append(':')
            .Append(((long)build.Timeout.TotalSeconds).ToString(CultureInfo.InvariantCulture))
            .ToString();
        return Hash(value);
    }

    private static string CacheNamespace(
        RepositoryCiJobWireDocument command,
        CiRunnerCacheScope cache) => cache switch
    {
        CiRunnerCacheScope.UntrustedIsolated => $"untrusted-{command.JobDigest}",
        CiRunnerCacheScope.TrustedVerified => $"trusted-{Hash($"{command.Repository}\n{command.SourceTree}")}",
        CiRunnerCacheScope.None => "none",
        _ => throw new InvalidDataException("The CI runner cache scope has no execution namespace."),
    };

    private static TimeSpan Timeout(RepositoryCiResourceWeight weight) => weight switch
    {
        RepositoryCiResourceWeight.Light => TimeSpan.FromMinutes(15),
        RepositoryCiResourceWeight.Medium => TimeSpan.FromMinutes(30),
        RepositoryCiResourceWeight.Heavy => TimeSpan.FromHours(1),
        _ => throw new InvalidDataException("The CI runner resource weight has no execution timeout."),
    };

    private static string Hash(string value) => Convert.ToHexStringLower(
        SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}
