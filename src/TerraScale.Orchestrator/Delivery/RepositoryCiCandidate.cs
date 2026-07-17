using System.Buffers;
using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text.Json;
using TerraScale.Orchestrator.ControlPlane.Delivery;

namespace TerraScale.Orchestrator.Delivery;

public sealed record RepositoryCiJobResult(
    JobId Job,
    int Attempt,
    bool Succeeded,
    int RequiredTestSkips,
    string EvidenceDigest);

public sealed record RepositoryCiArtifactResult(
    JobId Job,
    ArtifactId Artifact,
    RepositoryCiArchitecture Architecture,
    DigestId Digest,
    SigningIdentityId SigningIdentity,
    SignatureId Signature,
    bool SignatureVerified,
    DigestId? ObservedRuntimeDigest);

public sealed record RepositoryCiCandidateSource(
    string Repository,
    string Commit,
    string Tree,
    bool SignatureVerified);

public sealed class RepositoryCiCandidate
{
    internal RepositoryCiCandidate(
        string id,
        string digest,
        PipelineId pipeline,
        string pipelineDigest,
        string impactDigest,
        IReadOnlyList<RepositoryCiCandidateSource> sources,
        IReadOnlyList<RepositoryCiJobResult> jobs,
        IReadOnlyList<RepositoryCiArtifactResult> artifacts)
    {
        Id = id;
        Digest = digest;
        Pipeline = pipeline;
        PipelineDigest = pipelineDigest;
        ImpactDigest = impactDigest;
        Sources = sources;
        Jobs = jobs;
        Artifacts = artifacts;
    }

    public string Id { get; }
    public string Digest { get; }
    public PipelineId Pipeline { get; }
    public string PipelineDigest { get; }
    public string ImpactDigest { get; }
    public IReadOnlyList<RepositoryCiCandidateSource> Sources { get; }
    public IReadOnlyList<RepositoryCiJobResult> Jobs { get; }
    public IReadOnlyList<RepositoryCiArtifactResult> Artifacts { get; }
}

/// <summary>Qualifies build-once candidate metadata without granting production publication authority.</summary>
public static class RepositoryCiCandidateAssembler
{
    private const int MaximumJobs = 16_384;
    private const int MaximumArtifacts = MaximumJobs * 2;

    public static RepositoryCiCandidate Assemble(
        RepositoryCiPipelinePlan pipeline,
        IEnumerable<RepositoryCiJobResult> results,
        IEnumerable<RepositoryCiArtifactResult> artifacts)
    {
        ArgumentNullException.ThrowIfNull(pipeline);
        ArgumentNullException.ThrowIfNull(results);
        ArgumentNullException.ThrowIfNull(artifacts);
        if (pipeline.Profile != RepositoryCiProfile.Release || !IsDigest(pipeline.Digest) ||
            !IsDigest(pipeline.ImpactDigest) || pipeline.Jobs is not { Count: > 0 and <= MaximumJobs } ||
            pipeline.Jobs.Any(static job => job.Request.Kind != JobKind.TrustedBuild ||
                job.Request.AllowedZones.Count != 1 || job.Request.AllowedZones[0] != TrustZone.TrustedBuild ||
                job.Request.RequiredCapabilities.Any(static capability => capability is not (
                    RunnerCapability.Compile or RunnerCapability.Test or RunnerCapability.Sign))))
            throw new InvalidOperationException("Only a closed trusted release pipeline can produce a candidate.");

        var resultArray = results.Take(MaximumJobs + 1).ToArray();
        if (resultArray.Length != pipeline.Jobs.Count || resultArray.Any(static result => result is null))
            throw new InvalidDataException("Candidate job evidence must exactly cover the release pipeline.");
        var resultByJob = UniqueResults(resultArray);
        if (!pipeline.Jobs.Select(static job => job.Request.Job.Value).ToHashSet(StringComparer.Ordinal)
            .SetEquals(resultByJob.Keys))
            throw new InvalidDataException("Candidate job evidence does not match the release pipeline.");
        foreach (var job in pipeline.Jobs)
        {
            var result = resultByJob[job.Request.Job.Value];
            if (result.Attempt != job.Request.Attempt || result.Attempt != 1 || !result.Succeeded ||
                result.RequiredTestSkips != 0 || !IsDigest(result.EvidenceDigest))
                throw new InvalidDataException("A required candidate job did not produce clean first-attempt evidence.");
        }

        var artifactArray = artifacts.Take(MaximumArtifacts + 1).ToArray();
        if (artifactArray.Length > MaximumArtifacts || artifactArray.Any(static artifact => artifact is null))
            throw new InvalidDataException("Candidate artifact evidence exceeds its technical bound.");
        var expectedArtifacts = pipeline.Jobs
            .Where(static job => job.Plan.Node.Kind == RepositoryCiNodeKind.Artifact)
            .SelectMany(job => job.Plan.Node.Architectures.Select(architecture =>
                (Job: job.Request.Job.Value, Architecture: architecture)))
            .ToHashSet();
        if (expectedArtifacts.Count == 0)
            throw new InvalidDataException("A release candidate requires at least one declared artifact.");
        var artifactByIdentity = UniqueArtifacts(artifactArray);
        if (!expectedArtifacts.SetEquals(artifactByIdentity.Keys))
            throw new InvalidDataException("Candidate artifacts do not exactly cover the declared architectures.");
        foreach (var job in pipeline.Jobs.Where(static job => job.Plan.Node.Kind == RepositoryCiNodeKind.Artifact))
        foreach (var architecture in job.Plan.Node.Architectures)
        {
            if (!job.MayPublishCandidateArtifact)
                throw new InvalidOperationException("An artifact job lacks candidate publication authority.");
            var artifact = artifactByIdentity[(job.Request.Job.Value, architecture)];
            ValidateArtifact(artifact);
            if (architecture == RepositoryCiArchitecture.Any && artifact.ObservedRuntimeDigest is not null ||
                architecture != RepositoryCiArchitecture.Any && artifact.ObservedRuntimeDigest != artifact.Digest)
                throw new InvalidDataException("Candidate runtime evidence does not match the exact native artifact digest.");
        }

        var orderedResults = pipeline.Jobs.Select(job => resultByJob[job.Request.Job.Value]).ToArray();
        var orderedArtifacts = artifactArray
            .OrderBy(static artifact => artifact.Job.Value, StringComparer.Ordinal)
            .ThenBy(static artifact => artifact.Architecture)
            .ToArray();
        var sources = pipeline.Jobs
            .Select(static job => job.Source)
            .GroupBy(static source => source.Repository, StringComparer.Ordinal)
            .Select(static group => group.First())
            .OrderBy(static source => source.Repository, StringComparer.Ordinal)
            .Select(static source => new RepositoryCiCandidateSource(
                source.Repository,
                source.Commit.ToLowerInvariant(),
                source.Tree.ToLowerInvariant(),
                source.SignatureVerified))
            .ToArray();
        var digest = Digest(
            pipeline.Pipeline,
            pipeline.Digest,
            pipeline.ImpactDigest,
            sources,
            orderedResults,
            orderedArtifacts);
        return new(
            $"candidate-{digest}",
            digest,
            pipeline.Pipeline,
            pipeline.Digest,
            pipeline.ImpactDigest,
            ReadOnly(sources),
            ReadOnly(orderedResults),
            ReadOnly(orderedArtifacts));
    }

    internal static RepositoryCiCandidate Restore(
        string expectedDigest,
        string pipelineId,
        string pipelineDigest,
        string impactDigest,
        IEnumerable<RepositoryCiCandidateSource> sources,
        IEnumerable<RepositoryCiJobResult> jobs,
        IEnumerable<RepositoryCiArtifactResult> artifacts)
    {
        ArgumentNullException.ThrowIfNull(sources);
        ArgumentNullException.ThrowIfNull(jobs);
        ArgumentNullException.ThrowIfNull(artifacts);
        if (!IsDigest(expectedDigest) || !IsIdentity(pipelineId) ||
            !IsDigest(pipelineDigest) || !IsDigest(impactDigest))
            throw new InvalidDataException("Persisted candidate identity is invalid.");

        var sourceArray = sources.Take(65).ToArray();
        var jobArray = jobs.Take(MaximumJobs + 1).ToArray();
        var artifactArray = artifacts.Take(MaximumArtifacts + 1).ToArray();
        if (sourceArray.Length is < 1 or > 64 || jobArray.Length is < 1 or > MaximumJobs ||
            artifactArray.Length is < 1 or > MaximumArtifacts ||
            sourceArray.Any(static source => source is null) || jobArray.Any(static job => job is null) ||
            artifactArray.Any(static artifact => artifact is null))
            throw new InvalidDataException("Persisted candidate inputs exceed their technical bounds.");
        if (sourceArray.Select(static source => source.Repository).Distinct(StringComparer.Ordinal).Count() != sourceArray.Length ||
            !sourceArray.SequenceEqual(sourceArray.OrderBy(static source => source.Repository, StringComparer.Ordinal)) ||
            sourceArray.Any(static source => !source.SignatureVerified ||
                !ForgejoWebhookVerifier.IsRepository(source.Repository) || !IsObjectId(source.Commit) ||
                !IsObjectId(source.Tree)))
            throw new InvalidDataException("Persisted candidate sources are invalid.");

        var jobById = UniqueResults(jobArray);
        if (jobArray.Any(static job => job.Attempt != 1 || !job.Succeeded || job.RequiredTestSkips != 0 ||
                !IsDigest(job.EvidenceDigest)))
            throw new InvalidDataException("Persisted candidate jobs are invalid.");
        var artifactByIdentity = UniqueArtifacts(artifactArray);
        if (artifactByIdentity.Count != artifactArray.Length ||
            artifactArray.Any(artifact => !jobById.ContainsKey(artifact.Job.Value)))
            throw new InvalidDataException("Persisted candidate artifacts do not match its jobs.");
        foreach (var artifact in artifactArray)
        {
            ValidateArtifact(artifact);
            if (artifact.Architecture == RepositoryCiArchitecture.Any && artifact.ObservedRuntimeDigest is not null ||
                artifact.Architecture != RepositoryCiArchitecture.Any && artifact.ObservedRuntimeDigest != artifact.Digest)
                throw new InvalidDataException("Persisted candidate runtime evidence is invalid.");
        }
        if (!artifactArray.SequenceEqual(artifactArray
                .OrderBy(static artifact => artifact.Job.Value, StringComparer.Ordinal)
                .ThenBy(static artifact => artifact.Architecture)))
            throw new InvalidDataException("Persisted candidate artifacts are not canonical.");

        var pipeline = new PipelineId(pipelineId);
        var digest = Digest(pipeline, pipelineDigest, impactDigest, sourceArray, jobArray, artifactArray);
        if (digest != expectedDigest)
            throw new InvalidDataException("Persisted candidate content does not match its digest.");
        return new(
            $"candidate-{digest}",
            digest,
            pipeline,
            pipelineDigest,
            impactDigest,
            ReadOnly(sourceArray),
            ReadOnly(jobArray),
            ReadOnly(artifactArray));
    }

    private static Dictionary<string, RepositoryCiJobResult> UniqueResults(
        IEnumerable<RepositoryCiJobResult> results)
    {
        var values = new Dictionary<string, RepositoryCiJobResult>(StringComparer.Ordinal);
        foreach (var result in results)
        {
            if (result.Job?.Value is not { Length: > 0 } id || !values.TryAdd(id, result))
                throw new InvalidDataException("Candidate job evidence contains a duplicate or invalid job identity.");
        }
        return values;
    }

    private static Dictionary<(string Job, RepositoryCiArchitecture Architecture), RepositoryCiArtifactResult>
        UniqueArtifacts(IEnumerable<RepositoryCiArtifactResult> artifacts)
    {
        var values = new Dictionary<(string, RepositoryCiArchitecture), RepositoryCiArtifactResult>();
        foreach (var artifact in artifacts)
        {
            if (artifact.Job?.Value is not { Length: > 0 } id || !Enum.IsDefined(artifact.Architecture) ||
                artifact.Architecture == RepositoryCiArchitecture.Unspecified ||
                !values.TryAdd((id, artifact.Architecture), artifact))
                throw new InvalidDataException("Candidate artifact evidence contains a duplicate or invalid identity.");
        }
        return values;
    }

    private static void ValidateArtifact(RepositoryCiArtifactResult artifact)
    {
        if (!IsArtifactId(artifact.Artifact?.Value) || !IsDigest(artifact.Digest?.Value) ||
            !IsIdentity(artifact.SigningIdentity?.Value) || !IsIdentity(artifact.Signature?.Value) ||
            !artifact.SignatureVerified || artifact.ObservedRuntimeDigest is not null &&
            !IsDigest(artifact.ObservedRuntimeDigest.Value))
            throw new InvalidDataException("Candidate artifact evidence is incomplete or invalid.");
    }

    private static string Digest(
        PipelineId pipeline,
        string pipelineDigest,
        string impactDigest,
        IReadOnlyList<RepositoryCiCandidateSource> sources,
        IReadOnlyList<RepositoryCiJobResult> results,
        IReadOnlyList<RepositoryCiArtifactResult> artifacts)
    {
        var bytes = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(bytes))
        {
            writer.WriteStartObject();
            writer.WriteString("pipeline", pipeline.Value);
            writer.WriteString("pipelineDigest", pipelineDigest);
            writer.WriteString("impactDigest", impactDigest);
            writer.WriteStartArray("sources");
            foreach (var source in sources)
            {
                writer.WriteStartObject();
                writer.WriteString("repository", source.Repository);
                writer.WriteString("commit", source.Commit);
                writer.WriteString("tree", source.Tree);
                writer.WriteBoolean("signatureVerified", source.SignatureVerified);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteStartArray("jobs");
            foreach (var result in results)
            {
                writer.WriteStartObject();
                writer.WriteString("job", result.Job.Value);
                writer.WriteNumber("attempt", result.Attempt);
                writer.WriteString("evidenceDigest", result.EvidenceDigest);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteStartArray("artifacts");
            foreach (var artifact in artifacts)
            {
                writer.WriteStartObject();
                writer.WriteString("job", artifact.Job.Value);
                writer.WriteString("artifact", artifact.Artifact.Value);
                writer.WriteString("architecture", artifact.Architecture.ToString());
                writer.WriteString("digest", artifact.Digest.Value);
                writer.WriteString("signingIdentity", artifact.SigningIdentity.Value);
                writer.WriteString("signature", artifact.Signature.Value);
                if (artifact.ObservedRuntimeDigest is not null)
                    writer.WriteString("observedRuntimeDigest", artifact.ObservedRuntimeDigest.Value);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteEndObject();
        }
        return Convert.ToHexStringLower(SHA256.HashData(bytes.WrittenSpan));
    }

    private static bool IsArtifactId(string? value) => value is { Length: >= 1 and <= 256 } &&
        value[0] != '/' && !value.Contains("//", StringComparison.Ordinal) &&
        value.All(static character => character is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or
            >= '0' and <= '9' or '.' or '_' or '-' or '/') &&
        value.Split('/').All(static segment => segment is not ("" or "." or ".."));

    private static bool IsIdentity(string? value) => value is { Length: >= 1 and <= 512 } &&
        !value.Any(static character => char.IsWhiteSpace(character) || char.IsControl(character));

    private static bool IsObjectId(string? value) => value is { Length: 40 or 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f') &&
        value.Any(static character => character != '0');

    private static bool IsDigest(string? value) => value is { Length: 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static IReadOnlyList<T> ReadOnly<T>(T[] values) => new ReadOnlyCollection<T>(values);
}
