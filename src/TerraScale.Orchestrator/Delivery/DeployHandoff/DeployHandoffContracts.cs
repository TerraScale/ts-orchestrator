using System.Text.Json.Serialization;

namespace TerraScale.Orchestrator.Delivery.DeployHandoff;

/// <summary>Schema identity of the bounded Deploy-side handoff manifest accepted by mapping v1.</summary>
public static class DeployHandoffManifestSchema
{
    public const int CurrentVersion = 1;
    public const int MinimumSupportedVersion = 1;
}

/// <summary>Version of the typed Deploy-to-Orchestrator mapping contract itself.</summary>
public static class DeployHandoffMapping
{
    public const int CurrentVersion = 1;
}

/// <summary>Technical input bounds for the handoff manifest; mirrors the direct-delivery seam.</summary>
public static class DeployHandoffInputLimits
{
    public const int MaximumDocumentCharacters = 1_048_576;
    public const int MaximumDocumentDepth = 8;
    public const int MaximumOperationIdLength = 128;
    public const int MaximumTextLength = 256;
    public const int MaximumReasonLength = 1_024;
    public const int MaximumNotesLength = 1_024;
    public const int MaximumRegionCount = 32;
    public const int MaximumChannelCount = 8;
}

/// <summary>Stable, redacted failure codes at the Deploy-to-Orchestrator handoff seam.</summary>
public static class DeployHandoffErrorCode
{
    public const string DocumentInvalid = "handoff_document_invalid";
    public const string AmbiguousContent = "handoff_ambiguous_content";
    public const string FieldUnknown = "handoff_field_unknown";
    public const string FieldMissing = "handoff_field_missing";
    public const string SchemaUnsupported = "handoff_schema_unsupported";
    public const string UnboundedText = "handoff_unbounded_text";
    public const string SecretRejected = "handoff_secret_rejected";
    public const string DigestInvalid = "handoff_digest_invalid";
    public const string ArtifactInvalid = "handoff_artifact_invalid";
    public const string TargetInvalid = "handoff_target_invalid";
    public const string RollbackIncompatible = "handoff_rollback_incompatible";
    public const string DigestStale = "handoff_digest_stale";
    public const string SourceMismatch = "handoff_source_mismatch";
    public const string TargetMismatch = "handoff_target_mismatch";
}

/// <summary>
/// The typed, bounded input DTO shaped after the TerraScale.Deploy public manifest conventions:
/// exact source identity, published artifact identity with architecture, exact rollback artifact
/// identity, target identity, configuration and migration revisions, the requesting actor, and
/// informational-only metadata that is never executed.
/// </summary>
public sealed record DeployHandoffManifest(
    [property: JsonPropertyName("schemaVersion")] int? SchemaVersion,
    [property: JsonPropertyName("operationId")] string? OperationId,
    [property: JsonPropertyName("source")] DeployHandoffSource? Source,
    [property: JsonPropertyName("artifact")] DeployHandoffArtifact? Artifact,
    [property: JsonPropertyName("rollback")] DeployHandoffRollback? Rollback,
    [property: JsonPropertyName("target")] DeployHandoffTarget? Target,
    [property: JsonPropertyName("configurationRevision")] string? ConfigurationRevision,
    [property: JsonPropertyName("migrationRevision")] string? MigrationRevision,
    [property: JsonPropertyName("requestedBy")] string? RequestedBy,
    [property: JsonPropertyName("reason")] string? Reason,
    [property: JsonPropertyName("informational")] DeployHandoffInformational? Informational);

public sealed record DeployHandoffSource(
    [property: JsonPropertyName("repository")] string? Repository,
    [property: JsonPropertyName("commit")] string? Commit,
    [property: JsonPropertyName("treeDigest")] string? TreeDigest);

public sealed record DeployHandoffArtifact(
    [property: JsonPropertyName("digest")] string? Digest,
    [property: JsonPropertyName("manifestDigest")] string? ManifestDigest,
    [property: JsonPropertyName("kind")] string? Kind,
    [property: JsonPropertyName("architecture")] string? Architecture);

public sealed record DeployHandoffRollback(
    [property: JsonPropertyName("artifactDigest")] string? ArtifactDigest,
    [property: JsonPropertyName("manifestDigest")] string? ManifestDigest,
    [property: JsonPropertyName("kind")] string? Kind,
    [property: JsonPropertyName("architecture")] string? Architecture);

public sealed record DeployHandoffTarget(
    [property: JsonPropertyName("service")] string? Service,
    [property: JsonPropertyName("environment")] string? Environment,
    [property: JsonPropertyName("regions")] IReadOnlyList<string>? Regions);

public sealed record DeployHandoffInformational(
    [property: JsonPropertyName("notes")] string? Notes,
    [property: JsonPropertyName("notificationChannels")] IReadOnlyList<string>? NotificationChannels);

/// <summary>
/// The admitted operation identity the mapper compares the manifest against. Every expected
/// value is optional: when present, the manifest must agree exactly or the mapping is rejected
/// before any request data exists. The schema bounds are negotiated explicitly.
/// </summary>
public sealed record DeployHandoffAdmissionContext(
    int MinimumManifestSchemaVersion = DeployHandoffManifestSchema.MinimumSupportedVersion,
    int MaximumManifestSchemaVersion = DeployHandoffManifestSchema.CurrentVersion,
    string? ExpectedRepository = null,
    string? ExpectedCommit = null,
    string? ExpectedTreeDigest = null,
    string? ExpectedService = null,
    string? ExpectedEnvironment = null,
    IReadOnlyList<string>? ExpectedRegions = null)
{
    public static DeployHandoffAdmissionContext Default { get; } = new();
}

/// <summary>The exact rollback artifact identity carried through the handoff.</summary>
public sealed record DeployHandoffRollbackArtifact(
    string ArtifactDigest,
    string ManifestDigest,
    string Kind,
    string Architecture);

/// <summary>
/// The typed bounded request data consumed by the direct-delivery runtime (#3): the canonical
/// executable <see cref="ControlPlane.Delivery.DeliveryRequest"/> plus the fields the version-1
/// request cannot carry — the preserved artifact architecture and the exact rollback artifact.
/// </summary>
public sealed record DeployHandoffRequest(
    TerraScale.Orchestrator.ControlPlane.Delivery.DeliveryRequest Delivery,
    string Architecture,
    DeployHandoffRollbackArtifact? RollbackArtifact);

public enum DeployHandoffMappingDecision
{
    Admitted = 0,
    Rejected = 1,
}

/// <summary>Stable, redacted failure detail at the handoff seam.</summary>
public sealed record DeployHandoffError(string Code, string Message, string Remediation);

/// <summary>
/// The bounded typed result of a mapping or dry-run evaluation. A rejected manifest never
/// carries request data, so a rejection can never reach the target-mutation path.
/// </summary>
public sealed record DeployHandoffMappingResult(
    DeployHandoffMappingDecision Decision,
    DeployHandoffRequest? Request,
    DeployHandoffError? Error)
{
    /// <summary>
    /// True only for an admitted mapping. The decision is made entirely inside this pure
    /// translation, before any authorization, provenance, journal, or target interaction.
    /// </summary>
    public bool IsAdmittedForTargetMutation => Decision == DeployHandoffMappingDecision.Admitted;

    internal static DeployHandoffMappingResult Reject(string code, string message, string remediation) =>
        new(DeployHandoffMappingDecision.Rejected, null, new DeployHandoffError(code, message, remediation));
}
