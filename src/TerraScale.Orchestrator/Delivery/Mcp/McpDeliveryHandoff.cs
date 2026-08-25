using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery.DeployHandoff;
using TerraScale.Orchestrator.Runtime.Mcp;

namespace TerraScale.Orchestrator.Delivery.Mcp;

/// <summary>
/// The typed MCP direct-delivery target. The MCP workload deploys through the existing
/// direct-delivery controls — signed command envelope, durable evidence-provenance, admitted
/// targets, health gating, and exact rollback — with no MCP-specific mutation path. This type
/// only pins the identity of the target the composition admits for MCP deliveries.
/// </summary>
public static class McpDeliveryTarget
{
    /// <summary>The direct-delivery service name of the MCP workload.</summary>
    public const string ServiceName = "mcp";

    /// <summary>The source repository that owns the qualified MCP HTTP artifact.</summary>
    public const string SourceRepository = "TerraScale/TerraScale.MCP";

    /// <summary>The artifact kind of the qualified MCP HTTP executable.</summary>
    public const string ExpectedArtifactKind = "service";

    /// <summary>
    /// The handoff admission context for an MCP delivery: the manifest must come from the MCP
    /// repository and target the MCP service, or the mapping is rejected before any request
    /// data exists. Commit and tree digests may be pinned to the admitted operation.
    /// </summary>
    public static DeployHandoffAdmissionContext AdmissionContext(
        string environment,
        IReadOnlyList<string> regions,
        string? expectedCommit = null,
        string? expectedTreeDigest = null) =>
        new(
            ExpectedRepository: SourceRepository,
            ExpectedCommit: expectedCommit,
            ExpectedTreeDigest: expectedTreeDigest,
            ExpectedService: ServiceName,
            ExpectedEnvironment: environment,
            ExpectedRegions: regions);
}

/// <summary>Stable, redacted release-preparation codes for the MCP workload.</summary>
public enum McpReleasePreparationCode
{
    Admitted = 0,
    SourceRepositoryRejected = 1,
    ProvenanceIdentityIncomplete = 2,
    ArchitectureNotQualified = 3,
    ArtifactNotQualified = 4,
    ConfigurationSchemaMissing = 5,
    RollbackArtifactRequired = 6,
    RollbackArtifactRejected = 7,
    /// <summary>The source revision does not match the pinned expected revision.</summary>
    SourceRevisionMismatch = 8,
    /// <summary>The configuration revision does not match the admitted configuration-schema revision.</summary>
    ConfigurationRevisionMismatch = 9,
    /// <summary>The artifact kind is not the expected qualified HTTP executable kind.</summary>
    ArtifactKindRejected = 10,
}

/// <summary>The bounded typed result of MCP release preparation.</summary>
public sealed record McpReleasePreparationDecision(McpReleasePreparationCode Code, string Detail)
{
    public bool IsAdmitted => Code == McpReleasePreparationCode.Admitted;

    /// <summary>The bounded note vocabulary an admitted decision may carry; never free-form adapter text.</summary>
    public const int MaximumDetailLength = 256;
}

/// <summary>
/// The pinned identities release preparation can compare against. Every value is optional: a
/// present value is compared exactly, and an absent one is reported as not pinned in the
/// admitted decision instead of being silently treated as verified.
/// </summary>
public sealed record McpReleasePreparationPins(
    string? ExpectedCommit = null,
    string? ExpectedTreeDigest = null,
    string? AdmittedConfigurationRevision = null);

/// <summary>
/// MCP release preparation (issue #9): verifies the exact source revision, artifact digest,
/// architecture, provenance identity, configuration schema revision, and rollback artifact
/// BEFORE the workload is activated. Pure decision over the typed handoff request the
/// Deploy-to-Orchestrator mapping (#26 machinery) already produced; signature verification of
/// the durable artifact evidence happens in the production provenance seam the delivery
/// coordinator already calls, so a delivery that reaches a target has provenance enforced
/// independently of this check.
/// </summary>
public static class McpReleasePreparation
{
    public static McpReleasePreparationDecision Verify(
        DeployHandoffRequest request,
        McpHttpArtifactQualification qualification,
        string? currentlyDeployedDigest,
        McpReleasePreparationPins? pins = null)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(qualification);
        pins ??= new McpReleasePreparationPins();

        var delivery = request.Delivery;
        if (delivery.Source is not { } source)
            return Reject(McpReleasePreparationCode.ProvenanceIdentityIncomplete,
                "The delivery carries no source identity for provenance binding.");
        if (!string.Equals(source.Repository, McpDeliveryTarget.SourceRepository, StringComparison.Ordinal))
            return Reject(McpReleasePreparationCode.SourceRepositoryRejected,
                $"The MCP artifact must come from {McpDeliveryTarget.SourceRepository}.");
        if (string.IsNullOrWhiteSpace(source.Commit) || string.IsNullOrWhiteSpace(source.TreeDigest))
            return Reject(McpReleasePreparationCode.ProvenanceIdentityIncomplete,
                "The exact source revision requires both the commit and the tree digest.");
        if (delivery.Artifact is not { } artifact || string.IsNullOrWhiteSpace(artifact.Digest))
            return Reject(McpReleasePreparationCode.ArtifactNotQualified,
                "The delivery carries no artifact digest.");
        if (!string.Equals(artifact.Kind, McpDeliveryTarget.ExpectedArtifactKind, StringComparison.Ordinal))
            return Reject(McpReleasePreparationCode.ArtifactKindRejected,
                $"The MCP artifact kind must be '{McpDeliveryTarget.ExpectedArtifactKind}' (the qualified self-contained HTTP executable).");

        if (!McpWorkloadAdmission.TryParseArchitecture(request.Architecture, out var architecture) ||
            !qualification.AdmitsArchitecture(architecture))
            return Reject(McpReleasePreparationCode.ArchitectureNotQualified,
                "The artifact architecture must be exactly linux/arm64 or linux/amd64 and qualified for MCP.");

        if (!qualification.Admits(BareDigest(artifact.Digest), architecture))
            return Reject(McpReleasePreparationCode.ArtifactNotQualified,
                "The artifact digest is not the qualified MCP digest for this architecture.");

        if (string.IsNullOrWhiteSpace(delivery.ConfigurationRevision))
            return Reject(McpReleasePreparationCode.ConfigurationSchemaMissing,
                "The configuration schema revision is required before the workload is activated.");

        // Pinned-identity checks (R4): a pin that is present must match exactly; a pin that is
        // absent is reported as not pinned in the admitted note, never treated as verified.
        if (pins.ExpectedCommit is { Length: > 0 } expectedCommit &&
            !string.Equals(source.Commit, expectedCommit, StringComparison.Ordinal))
            return Reject(McpReleasePreparationCode.SourceRevisionMismatch,
                "source.commit does not match the pinned expected source revision.");
        if (pins.ExpectedTreeDigest is { Length: > 0 } expectedTreeDigest &&
            !string.Equals(BareDigest(source.TreeDigest), BareDigest(expectedTreeDigest), StringComparison.OrdinalIgnoreCase))
            return Reject(McpReleasePreparationCode.SourceRevisionMismatch,
                "source.treeDigest does not match the pinned expected source tree.");
        if (pins.AdmittedConfigurationRevision is { Length: > 0 } admittedConfigurationRevision &&
            !string.Equals(BareDigest(delivery.ConfigurationRevision), BareDigest(admittedConfigurationRevision), StringComparison.OrdinalIgnoreCase))
            return Reject(McpReleasePreparationCode.ConfigurationRevisionMismatch,
                "configurationRevision does not match the admitted configuration-schema revision.");

        var rollbackNote = string.Empty;
        if (!string.IsNullOrWhiteSpace(currentlyDeployedDigest))
        {
            // The workload is live: the ONLY valid rollback anchor is the exact artifact that is
            // currently deployed. Any other digest — however qualified — is a wrong anchor, and
            // a missing anchor leaves a failed activation unrestorable (ADR 0032).
            if (request.RollbackArtifact is not { } rollback)
                return Reject(McpReleasePreparationCode.RollbackArtifactRequired,
                    "A deployment over a live artifact must carry the exact rollback artifact identity.");
            if (!string.Equals(
                    BareDigest(rollback.ArtifactDigest),
                    BareDigest(currentlyDeployedDigest),
                    StringComparison.OrdinalIgnoreCase))
                return Reject(McpReleasePreparationCode.RollbackArtifactRejected,
                    "The rollback artifact must be the exact currently deployed artifact; record the live digest as the rollback anchor.");
            if (string.Equals(BareDigest(rollback.ArtifactDigest), BareDigest(artifact.Digest), StringComparison.OrdinalIgnoreCase))
                return Reject(McpReleasePreparationCode.RollbackArtifactRejected,
                    "The rollback artifact equals the artifact being deployed, so no exact prior artifact exists.");
            if (!McpWorkloadAdmission.TryParseArchitecture(rollback.Architecture, out var rollbackArchitecture) ||
                rollbackArchitecture != architecture)
                return Reject(McpReleasePreparationCode.RollbackArtifactRejected,
                    "The rollback artifact must run on the same architecture as the deployment target.");
            if (!qualification.Admits(BareDigest(rollback.ArtifactDigest), architecture))
                return Reject(McpReleasePreparationCode.RollbackArtifactRejected,
                    "The rollback artifact is not a qualified MCP artifact.");
            rollbackNote = "rollback anchor verified against the live artifact";
        }
        else if (request.RollbackArtifact is { } bootstrapRollback)
        {
            // First deployment: nothing is live to roll back to (the delivery coordinator's
            // pristine-region bootstrap expectation), but a declared anchor must still be a
            // distinct qualified prior artifact, exactly like the #26 handoff mapper requires.
            if (string.Equals(BareDigest(bootstrapRollback.ArtifactDigest), BareDigest(artifact.Digest), StringComparison.OrdinalIgnoreCase))
                return Reject(McpReleasePreparationCode.RollbackArtifactRejected,
                    "The rollback artifact equals the artifact being deployed, so no exact prior artifact exists.");
            if (!McpWorkloadAdmission.TryParseArchitecture(bootstrapRollback.Architecture, out var rollbackArchitecture) ||
                rollbackArchitecture != architecture)
                return Reject(McpReleasePreparationCode.RollbackArtifactRejected,
                    "The rollback artifact must run on the same architecture as the deployment target.");
            if (!qualification.Admits(BareDigest(bootstrapRollback.ArtifactDigest), architecture))
                return Reject(McpReleasePreparationCode.RollbackArtifactRejected,
                    "The rollback artifact is not a qualified MCP artifact.");
            rollbackNote = "first deployment with a declared bootstrap rollback anchor";
        }
        else
        {
            rollbackNote = "first deployment: no prior artifact exists to roll back to";
        }

        return new(
            McpReleasePreparationCode.Admitted,
            Note(rollbackNote, pins));
    }

    /// <summary>
    /// The bounded admitted note: the rollback disposition plus an honest list of identity
    /// checks that were NOT pinned for this verification. Fixed vocabulary only.
    /// </summary>
    private static string Note(string rollbackNote, McpReleasePreparationPins pins)
    {
        var notPinned = new List<string>();
        if (pins.ExpectedCommit is not { Length: > 0 })
            notPinned.Add("source commit");
        if (pins.ExpectedTreeDigest is not { Length: > 0 })
            notPinned.Add("source tree digest");
        if (pins.AdmittedConfigurationRevision is not { Length: > 0 })
            notPinned.Add("configuration revision");
        var note = notPinned.Count == 0
            ? rollbackNote
            : $"{rollbackNote}; not pinned: {string.Join(", ", notPinned)}";
        return note.Length <= McpReleasePreparationDecision.MaximumDetailLength
            ? note
            : note[..McpReleasePreparationDecision.MaximumDetailLength];
    }

    /// <summary>Strips the optional sha256: prefix so catalog digests and wire digests compare equal.</summary>
    private static string BareDigest(string value) =>
        value.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase)
            ? value["sha256:".Length..]
            : value;

    private static McpReleasePreparationDecision Reject(McpReleasePreparationCode code, string detail) =>
        new(code, detail);
}
