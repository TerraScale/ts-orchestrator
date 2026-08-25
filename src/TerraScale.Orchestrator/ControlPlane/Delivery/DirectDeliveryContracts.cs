using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

/// <summary>Version one of the direct product delivery request.</summary>
public sealed record DeliveryRequest(
    [property: JsonPropertyName("schemaVersion")] int SchemaVersion,
    [property: JsonPropertyName("operationId")] string? OperationId,
    [property: JsonPropertyName("source")] DeliverySource? Source,
    [property: JsonPropertyName("artifact")] DeliveryArtifact? Artifact,
    [property: JsonPropertyName("target")] DeliveryTarget? Target,
    [property: JsonPropertyName("configurationRevision")] string? ConfigurationRevision,
    [property: JsonPropertyName("migrationRevision")] string? MigrationRevision,
    [property: JsonPropertyName("requestedBy")] string? RequestedBy,
    [property: JsonPropertyName("reason")] string? Reason,
    [property: JsonPropertyName("authorityGeneration")] long AuthorityGeneration = 1,
    [property: JsonPropertyName("writerEpoch")] long WriterEpoch = 1,
    [property: JsonPropertyName("attempt")] int Attempt = 1)
{
    public const int CurrentSchemaVersion = 1;
}

public sealed record DeliverySource(
    [property: JsonPropertyName("repository")] string? Repository,
    [property: JsonPropertyName("commit")] string? Commit,
    [property: JsonPropertyName("treeDigest")] string? TreeDigest);

public sealed record DeliveryArtifact(
    [property: JsonPropertyName("digest")] string? Digest,
    [property: JsonPropertyName("manifestDigest")] string? ManifestDigest,
    [property: JsonPropertyName("kind")] string? Kind);

public sealed record DeliveryTarget(
    [property: JsonPropertyName("service")] string? Service,
    [property: JsonPropertyName("environment")] string? Environment,
    [property: JsonPropertyName("regions")] IReadOnlyList<string>? Regions);

public static class DeliveryReceiptStatus
{
    public const string Succeeded = "succeeded";
    public const string Failed = "failed";
    public const string RolledBack = "rolled_back";
}

public static class DeliveryHealthStatus
{
    public const string Passed = "passed";
    public const string Failed = "failed";
}

public static class DeliveryRollbackStatus
{
    public const string NotRequired = "not_required";
    public const string Succeeded = "succeeded";
    public const string Failed = "failed";
}

public static class DeliveryJournalState
{
    public const string Accepted = "accepted";
    public const string Applying = "applying";
    public const string RollingBack = "rolling_back";
    public const string Failed = "failed";
    public const string RolledBack = "rolled_back";
    public const string Succeeded = "succeeded";
}

/// <summary>Stable, redacted failure codes at the direct delivery seam.</summary>
public static class DirectDeliveryErrorCode
{
    public const string InvalidInput = "invalid_input";
    public const string UnsupportedSchema = "unsupported_schema";
    public const string MissingSourceAndArtifact = "missing_source_and_artifact";
    public const string InvalidDigest = "invalid_digest";
    public const string StaleDigest = "stale_digest";
    public const string UnknownTarget = "unknown_target";
    public const string UnauthorizedActor = "unauthorized_actor";
    public const string UnboundedText = "unbounded_text";
    public const string ProvenanceFailed = "provenance_failed";
    public const string HealthFailed = "health_failed";
    public const string ConvergenceFailed = "convergence_failed";
    public const string RollbackFailed = "rollback_failed";
    public const string JournalUnavailable = "journal_unavailable";
    public const string OperationConflict = "operation_conflict";
    public const string Cancelled = "cancelled";
    public const string MutationFailed = "mutation_failed";
    public const string AuthorityFenced = "authority_fenced";
    /// <summary>Transient: the authorization boundary could not be reached (distinct from a denial).</summary>
    public const string AuthorizationUnavailable = "authorization_unavailable";
    /// <summary>Transient: the provenance evidence source could not be reached (distinct from failed verification).</summary>
    public const string ProvenanceUnavailable = "provenance_unavailable";
}

public sealed record DeliveryErrorInfo(
    [property: JsonPropertyName("code")] string? Code,
    [property: JsonPropertyName("message")] string? Message,
    [property: JsonPropertyName("remediation")] string? Remediation);

public sealed record DeliveryProvenance(
    [property: JsonPropertyName("verified")] bool Verified,
    [property: JsonPropertyName("configurationRevision")] string? ConfigurationRevision,
    [property: JsonPropertyName("migrationRevision")] string? MigrationRevision);

public sealed record DeliveryHealthCheck(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("status")] string Status);

public sealed record DeliveryHealth(
    [property: JsonPropertyName("checks")] IReadOnlyList<DeliveryHealthCheck> Checks,
    [property: JsonPropertyName("converged")] bool Converged);

public sealed record DeliveryRollback(
    [property: JsonPropertyName("attempted")] bool Attempted,
    [property: JsonPropertyName("targetArtifactDigest")] string? TargetArtifactDigest,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("targetManifestDigest")] string? TargetManifestDigest = null);

/// <summary>The redacted, durable authority returned by direct delivery.</summary>
public sealed record DeliveryReceipt(
    [property: JsonPropertyName("schemaVersion")] int SchemaVersion,
    [property: JsonPropertyName("operationId")] string OperationId,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("source")] DeliverySource? Source,
    [property: JsonPropertyName("artifactDigest")] string? ArtifactDigest,
    [property: JsonPropertyName("target")] DeliveryTarget? Target,
    [property: JsonPropertyName("provenance")] DeliveryProvenance Provenance,
    [property: JsonPropertyName("health")] DeliveryHealth Health,
    [property: JsonPropertyName("rollback")] DeliveryRollback Rollback,
    [property: JsonPropertyName("auditId")] string AuditId,
    [property: JsonPropertyName("error")] DeliveryErrorInfo Error);

public sealed record DeliveryAuthorizationResult(bool Authorized);

public sealed record DeliveryProvenanceResult(
    bool Verified,
    bool Stale,
    string? ConfigurationRevision = null,
    string? MigrationRevision = null);

public sealed record DeliveryMutationResult(
    bool Succeeded,
    bool Mutated,
    string? PreviousArtifactDigest,
    string? FailureCode = null,
    string? PreviousManifestDigest = null);

public sealed record DeliveryHealthResult(
    bool Passed,
    IReadOnlyList<DeliveryHealthCheck>? Checks = null);

public sealed record DeliveryConvergenceResult(bool Converged);

public sealed record DeliveryRollbackResult(
    bool Succeeded,
    string? TargetArtifactDigest = null,
    DeliveryArtifact? Artifact = null);

public sealed record DeliveryRegionProgress(
    string Region,
    string State,
    string? PreviousArtifactDigest = null,
    string? ErrorCode = null,
    string? PreviousManifestDigest = null);

/// <summary>Authorization is evaluated by the owning authenticated control-plane seam.</summary>
public interface IDeliveryAuthorizer
{
    ValueTask<DeliveryAuthorizationResult> AuthorizeAsync(DeliveryRequest request, CancellationToken cancellationToken);
}

/// <summary>Verifies source, artifact, configuration, and migration provenance.</summary>
public interface IDeliveryProvenanceVerifier
{
    ValueTask<DeliveryProvenanceResult> VerifyAsync(
        DeliveryRequest request,
        DeliveryArtifact artifact,
        CancellationToken cancellationToken);
}

/// <summary>Builds an exact artifact only when the caller intentionally omitted one.</summary>
public interface IDeliveryArtifactBuilder
{
    ValueTask<DeliveryArtifact?> BuildAsync(DeliveryRequest request, DeliverySource source, CancellationToken cancellationToken);
}

/// <summary>Resolves an admitted target; unknown targets must return <see langword="null"/>.</summary>
public interface IDeliveryTargetResolver
{
    ValueTask<IDeliveryTarget?> ResolveAsync(DeliveryTarget target, CancellationToken cancellationToken);
}

/// <summary>Provider/runtime adapter for ordered mutation, health, convergence, and exact rollback.</summary>
public interface IDeliveryTarget
{
    /// <summary>
    /// Reads the region's currently deployed artifact digest before any mutation. The
    /// coordinator persists it in its write-ahead <c>applying</c> record so a crash between the
    /// mutation and the <c>applied</c> persist keeps the exact rollback target recoverable.
    /// Returns null when the region has no deployed digest yet.
    /// </summary>
    ValueTask<string?> ObserveCurrentDigestAsync(
        DeliveryRequest request,
        string region,
        CancellationToken cancellationToken);

    /// <summary>Reads the exact currently deployed artifact, including its manifest identity.</summary>
    /// <remarks>A digest-only adapter cannot prove rollback provenance and therefore returns null.</remarks>
    async ValueTask<DeliveryArtifact?> ObserveCurrentArtifactAsync(
        DeliveryRequest request,
        string region,
        CancellationToken cancellationToken)
    {
        await Task.Yield();
        return null;
    }

    ValueTask<DeliveryMutationResult> ApplyAsync(
        DeliveryRequest request,
        DeliveryArtifact artifact,
        string region,
        CancellationToken cancellationToken);

    ValueTask<DeliveryHealthResult> CheckHealthAsync(
        DeliveryRequest request,
        DeliveryArtifact artifact,
        string region,
        CancellationToken cancellationToken);

    ValueTask<DeliveryConvergenceResult> CheckConvergenceAsync(
        DeliveryRequest request,
        DeliveryArtifact artifact,
        IReadOnlyList<string> orderedRegions,
        CancellationToken cancellationToken);

    /// <summary>Rolls back with the exact prior artifact and manifest identities.</summary>
    async ValueTask<DeliveryRollbackResult> RollbackAsync(
        DeliveryRequest request,
        string region,
        string targetArtifactDigest,
        string? targetManifestDigest,
        CancellationToken cancellationToken)
    {
        await Task.Yield();
        return new DeliveryRollbackResult(false, targetArtifactDigest);
    }
}

public sealed record DeliveryJournalRecord(
    string OperationId,
    string RequestFingerprint,
    string State,
    DeliveryReceipt? Receipt,
    string? ArtifactDigest = null,
    IReadOnlyList<DeliveryRegionProgress>? Regions = null,
    long AuthorityGeneration = 1,
    long WriterEpoch = 1,
    int Attempt = 1);

/// <summary>Durable append-only journal used for idempotency and crash resumability.</summary>
public interface IDeliveryJournal
{
    ValueTask<DeliveryJournalRecord?> ReadAsync(string operationId, CancellationToken cancellationToken);
    ValueTask AppendAsync(DeliveryJournalRecord record, CancellationToken cancellationToken);
}

public static class DeliveryWireCodec
{
    public static JsonSerializerOptions JsonOptions { get; } = CreateOptions();

    public static string SerializeRequest(DeliveryRequest request) =>
        JsonSerializer.Serialize(request ?? throw new ArgumentNullException(nameof(request)), JsonOptions);

    public static string SerializeReceipt(DeliveryReceipt receipt) =>
        JsonSerializer.Serialize(receipt ?? throw new ArgumentNullException(nameof(receipt)), JsonOptions);

    public static DeliveryRequest DeserializeRequest(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
            throw new JsonException("The delivery request document is empty.");

        return JsonSerializer.Deserialize<DeliveryRequest>(json, JsonOptions)
            ?? throw new JsonException("The delivery request document is null.");
    }

    private static JsonSerializerOptions CreateOptions() => new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };
}
