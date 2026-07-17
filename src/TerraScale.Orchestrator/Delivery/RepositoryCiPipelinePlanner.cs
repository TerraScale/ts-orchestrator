using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.ControlPlane.Delivery;

namespace TerraScale.Orchestrator.Delivery;

public sealed record RepositoryCiPipelineJob
{
    internal RepositoryCiPipelineJob(
        RepositoryCiPlannedJob plan,
        ForgejoResolvedRevision source,
        JobRequest request,
        IReadOnlyList<JobId> dependsOn,
        bool mayPublishCandidateArtifact)
    {
        Plan = plan;
        Source = source;
        Request = request;
        DependsOn = dependsOn;
        MayPublishCandidateArtifact = mayPublishCandidateArtifact;
    }

    public RepositoryCiPlannedJob Plan { get; }
    public ForgejoResolvedRevision Source { get; }
    public JobRequest Request { get; }
    public IReadOnlyList<JobId> DependsOn { get; }
    public bool MayPublishCandidateArtifact { get; }
}

public sealed class RepositoryCiPipelinePlan
{
    internal RepositoryCiPipelinePlan(
        PipelineId pipeline,
        string digest,
        string impactDigest,
        int candidateRetentionDays,
        RepositoryCiProfile profile,
        IReadOnlyList<RepositoryCiPipelineJob> jobs)
    {
        Pipeline = pipeline;
        Digest = digest;
        ImpactDigest = impactDigest;
        CandidateRetentionDays = candidateRetentionDays;
        Profile = profile;
        Jobs = jobs;
    }

    public PipelineId Pipeline { get; }
    public string Digest { get; }
    public string ImpactDigest { get; }
    public int CandidateRetentionDays { get; }
    public RepositoryCiProfile Profile { get; }
    public IReadOnlyList<RepositoryCiPipelineJob> Jobs { get; }
}

/// <summary>Binds an affected DAG to immutable Git objects and least-privilege runner work.</summary>
public static class RepositoryCiPipelinePlanner
{
    private const int MaximumAttempts = 3;
    private const int MaximumJobs = 16_384;

    public static RepositoryCiPipelinePlan Plan(
        ForgejoCiTriggerPlan trigger,
        RepositoryCiImpactPlan impact,
        IEnumerable<ForgejoResolvedRevision> sources,
        long generation,
        long minimumRunnerSequence,
        long maximumRunnerSequence)
    {
        ArgumentNullException.ThrowIfNull(trigger);
        ArgumentNullException.ThrowIfNull(impact);
        ArgumentNullException.ThrowIfNull(sources);
        if (trigger.Disposition != ForgejoCiTriggerDisposition.Dispatch || trigger.RequiresQualifiedCandidate)
            throw new InvalidOperationException("Only validation or candidate triggers can create a CI pipeline.");
        var expectedProfile = trigger.JobKind switch
        {
            JobKind.ProductValidation => RepositoryCiProfile.Feature,
            JobKind.TrustedBuild => RepositoryCiProfile.Release,
            _ => throw new InvalidOperationException("The Forgejo trigger cannot create repository CI work."),
        };
        if (impact.Profile != expectedProfile || !IsDigest(impact.Digest) ||
            impact.CandidateRetentionDays is < 1 or > 30 ||
            impact.Jobs is not { Count: > 0 and <= MaximumJobs })
            throw new ArgumentException("The CI impact plan does not match the trigger policy.", nameof(impact));
        if (generation <= 0 || minimumRunnerSequence <= 0 || maximumRunnerSequence < minimumRunnerSequence)
            throw new ArgumentOutOfRangeException(nameof(generation));

        ValidateImpact(impact);
        var sourceArray = sources.Take(65).ToArray();
        if (sourceArray.Length is < 1 or > 64 || sourceArray.Any(static source => source is null))
            throw new ArgumentException("The CI source set must be bounded and non-empty.", nameof(sources));
        foreach (var source in sourceArray) ValidateSource(source);
        var sourceByRepository = sourceArray.ToDictionary(static source => source.Repository, StringComparer.Ordinal);
        var repositories = impact.Jobs.Select(static job => job.Repository).Distinct(StringComparer.Ordinal).ToArray();
        if (!repositories.ToHashSet(StringComparer.Ordinal).SetEquals(sourceByRepository.Keys))
            throw new ArgumentException("The CI source set must exactly cover the affected repositories.", nameof(sources));
        if (!sourceByRepository.TryGetValue(trigger.Envelope.Repository, out var triggeringSource) ||
            !StringComparer.OrdinalIgnoreCase.Equals(triggeringSource.Commit, trigger.Envelope.Revision))
            throw new ArgumentException("The signed Forgejo revision is not the exact triggering source.", nameof(sources));
        if (expectedProfile == RepositoryCiProfile.Release && sourceArray.Any(static source => !source.SignatureVerified))
            throw new InvalidOperationException("Every release pipeline source requires a verified commit signature.");

        var digest = PipelineDigest(
            trigger,
            impact,
            sourceArray,
            generation,
            minimumRunnerSequence,
            maximumRunnerSequence);
        var pipeline = new PipelineId($"ci-{digest[..24]}");
        var jobIds = impact.Jobs.ToDictionary(
            static job => job.Id,
            job => new JobId($"ci-{Hash($"{digest}\n{job.Id}\n{sourceByRepository[job.Repository].Tree}")[..32]}"),
            StringComparer.Ordinal);
        var jobs = new List<RepositoryCiPipelineJob>(impact.Jobs.Count);
        foreach (var planned in impact.Jobs)
        {
            var source = sourceByRepository[planned.Repository];
            var capabilities = Capabilities(planned.Node.Kind);
            if (capabilities.Any(capability => !trigger.Capabilities.Contains(capability)))
                throw new InvalidDataException("A CI node requests capability outside the trigger trust policy.");
            var jobId = jobIds[planned.Id];
            var request = new JobRequest(
                pipeline,
                jobId,
                trigger.JobKind,
                new TreeId(source.Tree.ToLowerInvariant()),
                generation,
                1,
                MaximumAttempts,
                new IdempotencyId($"ci-{Hash($"{digest}\n{planned.Id}")}"),
                [trigger.TrustZone],
                capabilities,
                minimumRunnerSequence,
                maximumRunnerSequence,
                retryAuthorized: false);
            jobs.Add(new(
                planned,
                source,
                request,
                ReadOnly(planned.DependsOn.Select(dependency => jobIds[dependency]).ToArray()),
                planned.Node.Kind == RepositoryCiNodeKind.Artifact && trigger.MayPublishArtifacts));
        }
        return new(
            pipeline,
            digest,
            impact.Digest,
            impact.CandidateRetentionDays,
            expectedProfile,
            ReadOnly(jobs));
    }

    private static void ValidateImpact(RepositoryCiImpactPlan impact)
    {
        var positions = new Dictionary<string, int>(StringComparer.Ordinal);
        for (var index = 0; index < impact.Jobs.Count; index++)
        {
            var job = impact.Jobs[index];
            if (job is null || job.Node is null || job.DependsOn is null || job.Reasons is null ||
                !ForgejoWebhookVerifier.IsRepository(job.Repository) ||
                job.Id != $"{job.Repository}:{job.Node.Id}" || !IsNodeId(job.Node.Id) ||
                job.Node.Profiles is null || !job.Node.Profiles.Contains(impact.Profile) ||
                job.Reasons is not { Count: > 0 and <= 128 } ||
                job.Reasons.Any(static reason => reason is not { Length: >= 1 and <= 1_024 } || reason.Any(char.IsControl)) ||
                job.DependsOn.Count > 256 ||
                job.DependsOn.Distinct(StringComparer.Ordinal).Count() != job.DependsOn.Count ||
                !positions.TryAdd(job.Id, index))
                throw new InvalidDataException("The CI impact plan contains an invalid job.");
            foreach (var dependency in job.DependsOn)
                if (!positions.ContainsKey(dependency))
                    throw new InvalidDataException("The CI impact plan is not in dependency order.");
            _ = Capabilities(job.Node.Kind);
        }
    }

    private static void ValidateSource(ForgejoResolvedRevision source)
    {
        if (!ForgejoWebhookVerifier.IsRepository(source.Repository) || !IsObjectId(source.Commit) ||
            source.Commit.All(static value => value == '0') || !IsObjectId(source.Tree) ||
            source.Tree.All(static value => value == '0'))
            throw new ArgumentException("A CI source contains an invalid Git object identity.", nameof(source));
    }

    private static RunnerCapability[] Capabilities(RepositoryCiNodeKind kind) => kind switch
    {
        RepositoryCiNodeKind.Static or RepositoryCiNodeKind.Build => [RunnerCapability.Compile],
        RepositoryCiNodeKind.Test => [RunnerCapability.Test],
        RepositoryCiNodeKind.Artifact => [RunnerCapability.Compile, RunnerCapability.Sign],
        _ => throw new InvalidDataException("The CI node kind has no admitted runner capability."),
    };

    private static string PipelineDigest(
        ForgejoCiTriggerPlan trigger,
        RepositoryCiImpactPlan impact,
        IReadOnlyList<ForgejoResolvedRevision> sources,
        long generation,
        long minimumRunnerSequence,
        long maximumRunnerSequence)
    {
        var value = new StringBuilder()
            .Append(trigger.Envelope.DedupeKey).Append('\n')
            .Append(trigger.JobKind).Append(':').Append(trigger.TrustZone).Append(':')
            .Append(trigger.MayPublishArtifacts ? '1' : '0').Append('\n')
            .AppendJoin(',', trigger.Capabilities).Append('\n')
            .Append(impact.Digest).Append('\n')
            .Append(impact.CandidateRetentionDays).Append('\n')
            .Append(generation).Append(':').Append(minimumRunnerSequence).Append(':')
            .Append(maximumRunnerSequence).Append('\n');
        foreach (var source in sources.OrderBy(static source => source.Repository, StringComparer.Ordinal))
            value.Append(source.Repository).Append(':')
                .Append(source.Commit.ToLowerInvariant()).Append(':')
                .Append(source.Tree.ToLowerInvariant()).Append(':')
                .Append(source.SignatureVerified ? '1' : '0').Append('\n');
        return Hash(value.ToString());
    }

    private static bool IsNodeId(string value) => value is { Length: >= 1 and <= 64 } &&
        value[0] is >= 'a' and <= 'z' &&
        value.All(static character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-');

    private static bool IsObjectId(string? value) => value is { Length: 40 or 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F');

    private static bool IsDigest(string? value) => value is { Length: 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static string Hash(string value) => Convert.ToHexStringLower(
        SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static IReadOnlyList<T> ReadOnly<T>(T[] values) => new ReadOnlyCollection<T>(values);
    private static IReadOnlyList<T> ReadOnly<T>(List<T> values) => new ReadOnlyCollection<T>(values.ToArray());
}
