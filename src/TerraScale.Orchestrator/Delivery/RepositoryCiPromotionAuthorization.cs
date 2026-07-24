using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using Cysharp.Text;

namespace TerraScale.Orchestrator.Delivery;

public sealed record RepositoryCiDeploymentEvidence(
    string QualifiedDigest,
    string CandidateDigest,
    string TestsDigest,
    string EvidenceDigest,
    string DependencyLockDigest,
    string GeneratedSchemasDigest,
    string ToolchainDigest,
    SigningIdentityId SigningIdentity,
    SignatureId Signature,
    ApprovalId Approval,
    CompatibilityProof Compatibility,
    bool TestsVerified,
    bool EvidenceVerified,
    bool SignatureVerified,
    bool ApprovalVerified);

public sealed class RepositoryCiPromotionAuthorization
{
    internal RepositoryCiPromotionAuthorization(
        string id,
        string digest,
        RepositoryCiQualifiedCandidate qualified,
        RepositoryCiDeploymentEvidence evidence,
        JobRequest job)
    {
        Id = id;
        Digest = digest;
        Qualified = qualified;
        Evidence = evidence;
        Job = job;
    }

    public string Id { get; }
    public string Digest { get; }
    public RepositoryCiQualifiedCandidate Qualified { get; }
    public RepositoryCiDeploymentEvidence Evidence { get; }
    public JobRequest Job { get; }
}

/// <summary>Creates production runner work only from exact qualified and verified evidence.</summary>
public static class RepositoryCiPromotionAuthorizer
{
    private const int MaximumAttempts = 3;

    public static RepositoryCiPromotionAuthorization Authorize(
        RepositoryCiQualifiedCandidate qualified,
        RepositoryCiDeploymentEvidence evidence,
        long generation,
        long minimumRunnerSequence,
        long maximumRunnerSequence)
    {
        ArgumentNullException.ThrowIfNull(qualified);
        ArgumentNullException.ThrowIfNull(evidence);
        if (!IsDigest(qualified.Digest) || qualified.Id != $"qualified-{qualified.Digest}" ||
            evidence.QualifiedDigest != qualified.Digest ||
            evidence.CandidateDigest != qualified.Candidate.Digest ||
            !IsDigest(evidence.TestsDigest) || !IsDigest(evidence.EvidenceDigest) ||
            !IsDigest(evidence.DependencyLockDigest) || !IsDigest(evidence.GeneratedSchemasDigest) ||
            !IsDigest(evidence.ToolchainDigest) || !IsIdentity(evidence.SigningIdentity?.Value) ||
            !IsIdentity(evidence.Signature?.Value) || !IsIdentity(evidence.Approval?.Value) ||
            !ValidCompatibility(evidence.Compatibility) || !evidence.TestsVerified ||
            !evidence.EvidenceVerified || !evidence.SignatureVerified || !evidence.ApprovalVerified)
            throw new InvalidDataException("Deployment evidence is incomplete, invalid, or bound to another candidate.");
        if (qualified.Sources is not { Count: > 0 } || qualified.Candidate.Artifacts is not { Count: > 0 } ||
            qualified.Candidate.Artifacts.Any(static artifact => !artifact.SignatureVerified) ||
            qualified.Sources.Any(static source => !IsObjectId(source.Tree)))
            throw new InvalidDataException("The qualified candidate is missing exact signed source or artifact evidence.");
        if (generation <= 0 || minimumRunnerSequence <= 0 || maximumRunnerSequence < minimumRunnerSequence)
            throw new ArgumentOutOfRangeException(nameof(generation));

        var digest = Digest(qualified, evidence, generation, minimumRunnerSequence, maximumRunnerSequence);
        var pipeline = new PipelineId($"promotion-{digest[..24]}");
        var job = new JobRequest(
            pipeline,
            new JobId($"promotion-{digest[..32]}"),
            JobKind.Promotion,
            new TreeId(qualified.Sources[0].Tree),
            generation,
            1,
            MaximumAttempts,
            new IdempotencyId($"promotion-{digest}"),
            [TrustZone.ProductionRelease],
            [RunnerCapability.Promote, RunnerCapability.ProductionDeploy],
            minimumRunnerSequence,
            maximumRunnerSequence,
            retryAuthorized: false);
        return new($"promotion-{digest}", digest, qualified, evidence, job);
    }

    private static bool ValidCompatibility(CompatibilityProof? value) => value is not null &&
        IsDigest(value.CurrentToCurrent?.Value) && IsDigest(value.CurrentToPrevious?.Value) &&
        IsDigest(value.PreviousToCurrent?.Value) && value.CurrentToCurrentCompatible &&
        value.CurrentToPreviousCompatible && value.PreviousToCurrentCompatible;

    private static string Digest(
        RepositoryCiQualifiedCandidate qualified,
        RepositoryCiDeploymentEvidence evidence,
        long generation,
        long minimumRunnerSequence,
        long maximumRunnerSequence)
    {
        using var value = ZString.CreateStringBuilder();
        value.Append(qualified.Digest);
        value.Append('\n');
        value.Append(evidence.CandidateDigest);
        value.Append('\n');
        value.Append(evidence.TestsDigest);
        value.Append('\n');
        value.Append(evidence.EvidenceDigest);
        value.Append('\n');
        value.Append(evidence.DependencyLockDigest);
        value.Append('\n');
        value.Append(evidence.GeneratedSchemasDigest);
        value.Append('\n');
        value.Append(evidence.ToolchainDigest);
        value.Append('\n');
        value.Append(evidence.SigningIdentity.Value);
        value.Append('\n');
        value.Append(evidence.Signature.Value);
        value.Append('\n');
        value.Append(evidence.Approval.Value);
        value.Append('\n');
        value.Append(evidence.Compatibility.CurrentToCurrent.Value);
        value.Append('\n');
        value.Append(evidence.Compatibility.CurrentToPrevious.Value);
        value.Append('\n');
        value.Append(evidence.Compatibility.PreviousToCurrent.Value);
        value.Append('\n');
        value.Append(generation);
        value.Append(':');
        value.Append(minimumRunnerSequence);
        value.Append(':');
        value.Append(maximumRunnerSequence);
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value.ToString())));
    }

    private static bool IsObjectId(string? value) => value is { Length: 40 or 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f') &&
        value.Any(static character => character != '0');

    private static bool IsDigest(string? value) => value is { Length: 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool IsIdentity(string? value) => value is { Length: >= 1 and <= 512 } &&
        !value.Any(static character => char.IsWhiteSpace(character) || char.IsControl(character));
}
