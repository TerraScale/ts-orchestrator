using System.Collections.Frozen;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using TerraScale.Orchestrator.ControlPlane.Delivery;

namespace TerraScale.Orchestrator.Delivery.DeployHandoff;

/// <summary>
/// The typed Deploy-to-Orchestrator handoff translation (mapping v1). This is a pure decision:
/// it reads one bounded Deploy-shaped manifest and returns either the typed bounded request data
/// consumed by the direct-delivery runtime (#3) or a bounded actionable rejection. It performs no
/// I/O and no mutation of any kind, so every rejection happens strictly before a target could be
/// touched. Loading the manifest document is the caller's (adapter or test) responsibility.
/// </summary>
public static partial class DeployHandoffMapper
{
    internal static readonly JsonSerializerOptions ManifestJsonOptions = CreateManifestOptions();

    private static readonly FrozenSet<string> GenericManifestKeys = new[]
    {
        "manifests", "layers", "config", "configDigest", "blobs", "descriptors", "mediaType",
        "artifactType", "subject", "annotations", "history", "fsLayers", "env", "entrypoint",
        "cmd", "command", "files", "url", "urls", "inline", "payload", "template",
    }.ToFrozenSet(StringComparer.Ordinal);

    private static readonly FrozenDictionary<string, FrozenSet<string>> AllowedChildProperties =
        CreateAllowedChildProperties();

    private static FrozenDictionary<string, FrozenSet<string>> CreateAllowedChildProperties()
    {
        var dictionary = new Dictionary<string, FrozenSet<string>>(StringComparer.Ordinal)
        {
            [""] = new[]
            {
                "schemaVersion", "operationId", "source", "artifact", "rollback", "target",
                "configurationRevision", "migrationRevision", "requestedBy", "reason", "informational",
            }.ToFrozenSet(StringComparer.Ordinal),
            ["source"] = new[] { "repository", "commit", "treeDigest" }.ToFrozenSet(StringComparer.Ordinal),
            ["artifact"] = new[] { "digest", "manifestDigest", "kind", "architecture" }.ToFrozenSet(StringComparer.Ordinal),
            ["rollback"] = new[] { "artifactDigest", "manifestDigest", "kind", "architecture" }.ToFrozenSet(StringComparer.Ordinal),
            ["target"] = new[] { "service", "environment", "regions" }.ToFrozenSet(StringComparer.Ordinal),
            ["informational"] = new[] { "notes", "notificationChannels" }.ToFrozenSet(StringComparer.Ordinal),
        };
        return dictionary.ToFrozenDictionary(StringComparer.Ordinal);
    }

    /// <summary>Evaluates a manifest document without producing executable divergence from <see cref="Map(string,DeployHandoffAdmissionContext?)"/>.</summary>
    public static DeployHandoffMappingResult DryRun(string json, DeployHandoffAdmissionContext? context = null) =>
        Map(json, context);

    /// <summary>Evaluates an already-typed manifest without producing executable divergence from <see cref="Map(TerraScale.Orchestrator.Delivery.DeployHandoff.DeployHandoffManifest,DeployHandoffAdmissionContext?)"/>.</summary>
    public static DeployHandoffMappingResult DryRun(
        DeployHandoffManifest manifest, DeployHandoffAdmissionContext? context = null) =>
        Map(manifest, context);

    /// <summary>Maps one bounded Deploy-shaped manifest document into typed bounded request data, or rejects it before any request exists.</summary>
    public static DeployHandoffMappingResult Map(string json, DeployHandoffAdmissionContext? context = null)
    {
        if (string.IsNullOrWhiteSpace(json) || json.Length > DeployHandoffInputLimits.MaximumDocumentCharacters)
            return RejectDocument("The handoff manifest is empty or exceeds the document bound.");

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(json, new JsonDocumentOptions
            {
                MaxDepth = DeployHandoffInputLimits.MaximumDocumentDepth,
            });
        }
        catch (JsonException)
        {
            return RejectDocument("The handoff manifest is not valid JSON.");
        }

        using (document)
        {
            if (document.RootElement.ValueKind is not JsonValueKind.Object)
                return RejectDocument("The handoff manifest must be a single JSON object.");

            // Generic manifest content and unknown fields fail closed before any typed parsing:
            // no generic descriptor is ever admitted through this seam.
            var violation = ScanElement(document.RootElement, "", 0);
            if (violation is not null)
                return violation;

            DeployHandoffManifest? manifest;
            try
            {
                manifest = JsonSerializer.Deserialize<DeployHandoffManifest>(json, ManifestJsonOptions);
                if (manifest is null)
                    return RejectDocument("The handoff manifest document is null.");
            }
            catch (JsonException exception)
            {
                var location = string.IsNullOrEmpty(exception.Path) ? "document" : $"field '{Echo(exception.Path)}'";
                return RejectDocument($"The handoff manifest has an unexpected value type at {location}.");
            }

            return Map(manifest, context);
        }
    }

    /// <summary>Maps an already-typed manifest into typed bounded request data, or rejects it before any request exists.</summary>
    public static DeployHandoffMappingResult Map(
        DeployHandoffManifest manifest, DeployHandoffAdmissionContext? context = null)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        var admission = Normalize(context);

        var schemaError = NegotiateSchema(manifest.SchemaVersion, admission);
        if (schemaError is not null)
            return schemaError;

        var presenceError = CheckRequiredPresence(manifest);
        if (presenceError is not null)
            return presenceError;

        var boundsError = CheckBounds(manifest);
        if (boundsError is not null)
            return boundsError;

        var formatError = CheckFormats(manifest);
        if (formatError is not null)
            return formatError;

        var rollbackError = CheckRollbackCompatibility(manifest);
        if (rollbackError is not null)
            return rollbackError;

        var identityError = CheckAdmissionIdentity(manifest, admission);
        if (identityError is not null)
            return identityError;

        var source = manifest.Source!;
        var artifact = manifest.Artifact!;
        var target = manifest.Target!;
        var rollback = manifest.Rollback;
        return new DeployHandoffMappingResult(
            DeployHandoffMappingDecision.Admitted,
            new DeployHandoffRequest(
                new DeliveryRequest(
                    SchemaVersion: DeliveryRequest.CurrentSchemaVersion,
                    OperationId: manifest.OperationId,
                    Source: new DeliverySource(source.Repository, source.Commit, source.TreeDigest),
                    Artifact: new DeliveryArtifact(artifact.Digest, artifact.ManifestDigest, artifact.Kind),
                    Target: new DeliveryTarget(target.Service, target.Environment, target.Regions!.ToArray()),
                    ConfigurationRevision: manifest.ConfigurationRevision,
                    MigrationRevision: manifest.MigrationRevision,
                    RequestedBy: manifest.RequestedBy,
                    Reason: manifest.Reason),
                artifact.Architecture!,
                rollback is null
                    ? null
                    : new DeployHandoffRollbackArtifact(
                        rollback.ArtifactDigest!, rollback.ManifestDigest!, rollback.Kind!, rollback.Architecture!)),
            null);
    }

    /// <summary>Serializes a manifest with the contract codec; used by the contract-drift test to enumerate input fields.</summary>
    public static string SerializeManifest(DeployHandoffManifest manifest) =>
        JsonSerializer.Serialize(manifest ?? throw new ArgumentNullException(nameof(manifest)), ManifestJsonOptions);

    private static DeployHandoffAdmissionContext Normalize(DeployHandoffAdmissionContext? context)
    {
        var effective = context ?? DeployHandoffAdmissionContext.Default;
        // Mapping v1 never widens: a context may narrow the negotiated schema range within the
        // contract bounds, but may not admit manifest schema versions this mapping does not define.
        if (effective.MinimumManifestSchemaVersion < DeployHandoffManifestSchema.MinimumSupportedVersion ||
            effective.MaximumManifestSchemaVersion > DeployHandoffManifestSchema.CurrentVersion ||
            effective.MaximumManifestSchemaVersion < effective.MinimumManifestSchemaVersion)
            throw new ArgumentException(
                $"The admission context must declare a manifest schema range within " +
                $"{DeployHandoffManifestSchema.MinimumSupportedVersion}.." +
                $"{DeployHandoffManifestSchema.CurrentVersion}.", nameof(context));
        return effective;
    }

    private static DeployHandoffMappingResult? NegotiateSchema(int? version, DeployHandoffAdmissionContext admission)
    {
        if (version is null)
            return DeployHandoffMappingResult.Reject(
                DeployHandoffErrorCode.FieldMissing,
                "Required field 'schemaVersion' is absent.",
                "Set schemaVersion to the handoff manifest schema version produced by TerraScale.Deploy.");
        if (version < admission.MinimumManifestSchemaVersion || version > admission.MaximumManifestSchemaVersion)
            return DeployHandoffMappingResult.Reject(
                DeployHandoffErrorCode.SchemaUnsupported,
                $"schemaVersion {version} is outside the admitted range " +
                $"{admission.MinimumManifestSchemaVersion}..{admission.MaximumManifestSchemaVersion}.",
                "Regenerate the manifest with an admitted schema version, or negotiate a wider mapping version.");
        return null;
    }

    private static DeployHandoffMappingResult? ScanElement(JsonElement element, string path, int depth)
    {
        if (depth > DeployHandoffInputLimits.MaximumDocumentDepth)
            return RejectDocument("The handoff manifest nesting exceeds the document depth bound.");

        if (element.ValueKind is JsonValueKind.Object)
        {
            var allowed = AllowedChildProperties.TryGetValue(path, out var children)
                ? children
                : FrozenSet<string>.Empty;
            var seenPropertyNames = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                var propertyPath = path.Length == 0 ? property.Name : path + "." + property.Name;
                // A duplicated property name is ambiguous content by construction (last-wins
                // parsing would silently drop the first value), so it fails closed.
                if (!seenPropertyNames.Add(property.Name))
                    return RejectDocument($"Property '{Echo(propertyPath)}' appears more than once.");
                if (GenericManifestKeys.Contains(property.Name))
                    return DeployHandoffMappingResult.Reject(
                        DeployHandoffErrorCode.AmbiguousContent,
                        $"Generic manifest content at '{Echo(propertyPath)}' is not admitted.",
                        "Send the typed handoff manifest; generic OCI image-index or descriptor content must be translated by TerraScale.Deploy first.");
                if (!allowed.Contains(property.Name))
                    return DeployHandoffMappingResult.Reject(
                        DeployHandoffErrorCode.FieldUnknown,
                        $"Unknown field '{Echo(propertyPath)}' is not mapped by handoff mapping v{DeployHandoffMapping.CurrentVersion}.",
                        $"Remove the field, or add it to the mapping table in docs/contracts/deploy-orchestrator-handoff.md with the next mapping version.");
                var nested = ScanElement(property.Value, propertyPath, depth + 1);
                if (nested is not null)
                    return nested;
            }
        }
        else if (element.ValueKind is JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                var nested = ScanElement(item, path, depth + 1);
                if (nested is not null)
                    return nested;
            }
        }

        return null;
    }

    private static DeployHandoffMappingResult? CheckRequiredPresence(DeployHandoffManifest manifest)
    {
        if (string.IsNullOrEmpty(manifest.OperationId))
            return Missing("operationId");
        if (manifest.Source is null)
            return Missing("source");
        if (string.IsNullOrEmpty(manifest.Source.Repository))
            return Missing("source.repository");
        if (string.IsNullOrEmpty(manifest.Source.Commit))
            return Missing("source.commit");
        if (string.IsNullOrEmpty(manifest.Source.TreeDigest))
            return Missing("source.treeDigest");
        if (manifest.Artifact is null)
            return Missing("artifact");
        if (string.IsNullOrEmpty(manifest.Artifact.Digest))
            return Missing("artifact.digest");
        if (string.IsNullOrEmpty(manifest.Artifact.ManifestDigest))
            return Missing("artifact.manifestDigest");
        if (string.IsNullOrEmpty(manifest.Artifact.Kind))
            return Missing("artifact.kind");
        if (string.IsNullOrEmpty(manifest.Artifact.Architecture))
            return Missing("artifact.architecture");
        if (manifest.Target is null)
            return Missing("target");
        if (string.IsNullOrEmpty(manifest.Target.Service))
            return Missing("target.service");
        if (string.IsNullOrEmpty(manifest.Target.Environment))
            return Missing("target.environment");
        if (manifest.Target.Regions is null || manifest.Target.Regions.Count == 0)
            return Missing("target.regions");
        if (string.IsNullOrEmpty(manifest.ConfigurationRevision))
            return Missing("configurationRevision");
        if (string.IsNullOrEmpty(manifest.RequestedBy))
            return Missing("requestedBy");
        if (string.IsNullOrEmpty(manifest.Reason))
            return Missing("reason");
        return null;
    }

    private static DeployHandoffMappingResult? CheckBounds(DeployHandoffManifest manifest)
    {
        if (!IsBoundedText(manifest.OperationId, DeployHandoffInputLimits.MaximumOperationIdLength))
            return Unbounded("operationId");
        if (!IsBoundedText(manifest.Source!.Repository, DeployHandoffInputLimits.MaximumTextLength))
            return Unbounded("source.repository");
        if (!IsBoundedText(manifest.Reason, DeployHandoffInputLimits.MaximumReasonLength))
            return Unbounded("reason");
        if (!IsBoundedText(manifest.RequestedBy, DeployHandoffInputLimits.MaximumTextLength))
            return Unbounded("requestedBy");
        if (!IsBoundedText(manifest.Target!.Service, DeployHandoffInputLimits.MaximumTextLength))
            return Unbounded("target.service");
        if (!IsBoundedText(manifest.Target.Environment, DeployHandoffInputLimits.MaximumTextLength))
            return Unbounded("target.environment");

        var seenRegions = new HashSet<string>(StringComparer.Ordinal);
        if (manifest.Target.Regions!.Count > DeployHandoffInputLimits.MaximumRegionCount)
            return Unbounded("target.regions");
        foreach (var region in manifest.Target.Regions)
        {
            if (!IsBoundedText(region, DeployHandoffInputLimits.MaximumTextLength) || !seenRegions.Add(region))
                return Unbounded("target.regions");
        }

        if (manifest.Informational is { } informational)
        {
            if (informational.Notes is not null &&
                !IsBoundedText(informational.Notes, DeployHandoffInputLimits.MaximumNotesLength))
                return Unbounded("informational.notes");
            if (informational.NotificationChannels is { } channels)
            {
                if (channels.Count > DeployHandoffInputLimits.MaximumChannelCount)
                    return Unbounded("informational.notificationChannels");
                foreach (var channel in channels)
                {
                    if (!IsBoundedText(channel, DeployHandoffInputLimits.MaximumTextLength))
                        return Unbounded("informational.notificationChannels");
                }
            }
        }

        if (SecretBearing(manifest))
            return DeployHandoffMappingResult.Reject(
                DeployHandoffErrorCode.SecretRejected,
                $"Field '{SecretBearingField(manifest)}' appears to contain secret material.",
                "Remove credentials from the manifest; secrets come from the secret store and never travel in handoff data.");
        return null;
    }

    /// <summary>
    /// Every admitted free-text field is scanned, so no plaintext secret can reach the journal
    /// through a less-obvious field than the reason.
    /// </summary>
    private static bool SecretBearing(DeployHandoffManifest manifest) => SecretBearingField(manifest) is not null;

    private static string? SecretBearingField(DeployHandoffManifest manifest)
    {
        if (SecretBearingText(manifest.OperationId)) return "operationId";
        if (SecretBearingText(manifest.Source!.Repository)) return "source.repository";
        if (SecretBearingText(manifest.RequestedBy)) return "requestedBy";
        if (SecretBearingText(manifest.Reason)) return "reason";
        if (SecretBearingText(manifest.Target!.Service)) return "target.service";
        if (SecretBearingText(manifest.Target.Environment)) return "target.environment";
        if (manifest.Target.Regions!.Any(SecretBearingText)) return "target.regions";
        if (SecretBearingText(manifest.Informational?.Notes)) return "informational.notes";
        if (manifest.Informational?.NotificationChannels?.Any(SecretBearingText) == true)
            return "informational.notificationChannels";
        return null;
    }

    private static bool SecretBearingText(string? value) =>
        value is not null && SecretPattern().IsMatch(value);

    private static DeployHandoffMappingResult? CheckFormats(DeployHandoffManifest manifest)
    {
        if (!IsCommit(manifest.Source!.Commit))
            return InvalidDigest("source.commit", "a 40-character Git commit");
        if (!IsDigest(manifest.Source.TreeDigest))
            return InvalidDigest("source.treeDigest", "a sha256 digest");
        if (!IsDigest(manifest.Artifact!.Digest))
            return InvalidDigest("artifact.digest", "a sha256 digest");
        if (!IsDigest(manifest.Artifact.ManifestDigest))
            return InvalidDigest("artifact.manifestDigest", "a sha256 digest");
        if (!IsDigest(manifest.ConfigurationRevision))
            return InvalidDigest("configurationRevision", "a sha256 digest");
        if (manifest.MigrationRevision is not null && !IsDigest(manifest.MigrationRevision))
            return InvalidDigest("migrationRevision", "a sha256 digest");
        if (manifest.Rollback is { } rollback)
        {
            // Null/empty rollback fields are completeness failures handled by
            // CheckRollbackCompatibility (handoff_rollback_incompatible); here only a present
            // but malformed identity is a digest-format failure.
            if (!string.IsNullOrEmpty(rollback.ArtifactDigest) && !IsDigest(rollback.ArtifactDigest))
                return InvalidDigest("rollback.artifactDigest", "a sha256 digest");
            if (!string.IsNullOrEmpty(rollback.ManifestDigest) && !IsDigest(rollback.ManifestDigest))
                return InvalidDigest("rollback.manifestDigest", "a sha256 digest");
        }

        if (manifest.Artifact.Kind is not ("service" or "package" or "site"))
            return DeployHandoffMappingResult.Reject(
                DeployHandoffErrorCode.ArtifactInvalid,
                $"artifact.kind '{Echo(manifest.Artifact.Kind)}' is not supported.",
                "Use one of service, package, or site.");
        if (manifest.Artifact.Architecture is not ("linux/amd64" or "linux/arm64" or "multi"))
            return DeployHandoffMappingResult.Reject(
                DeployHandoffErrorCode.ArtifactInvalid,
                $"artifact.architecture '{Echo(manifest.Artifact.Architecture)}' is not supported.",
                "Use linux/amd64, linux/arm64, or multi, matching the artifact TerraScale.Deploy published.");
        if (manifest.Target!.Environment is not ("local" or "development" or "production"))
            return DeployHandoffMappingResult.Reject(
                DeployHandoffErrorCode.TargetInvalid,
                $"target.environment '{Echo(manifest.Target.Environment)}' is not supported.",
                "Use local, development, or production, matching the admitted delivery target.");
        if (manifest.Rollback is { } rollbackShape &&
            !string.IsNullOrEmpty(rollbackShape.Kind) &&
            rollbackShape.Kind is not ("service" or "package" or "site"))
            return DeployHandoffMappingResult.Reject(
                DeployHandoffErrorCode.RollbackIncompatible,
                $"rollback.kind '{Echo(rollbackShape.Kind)}' is not supported.",
                "Use the same kind as the deployed artifact.");
        return null;
    }

    private static DeployHandoffMappingResult? CheckRollbackCompatibility(DeployHandoffManifest manifest)
    {
        if (manifest.Rollback is not { } rollback)
            return null;

        if (string.IsNullOrEmpty(rollback.ArtifactDigest))
            return RollbackRejected("rollback.artifactDigest", "is required when rollback is declared");
        if (string.IsNullOrEmpty(rollback.ManifestDigest))
            return RollbackRejected("rollback.manifestDigest", "is required when rollback is declared");
        if (string.IsNullOrEmpty(rollback.Kind))
            return RollbackRejected("rollback.kind", "is required when rollback is declared");
        if (string.IsNullOrEmpty(rollback.Architecture))
            return RollbackRejected("rollback.architecture", "is required when rollback is declared");
        if (rollback.Architecture is not ("linux/amd64" or "linux/arm64" or "multi"))
            return RollbackRejected("rollback.architecture", "is not a supported platform");

        var artifact = manifest.Artifact!;
        if (string.Equals(rollback.ArtifactDigest, artifact.Digest, StringComparison.OrdinalIgnoreCase))
            return RollbackRejected(
                "rollback.artifactDigest",
                "equals the artifact being deployed, so no exact prior artifact exists");
        if (!string.Equals(rollback.Kind, artifact.Kind, StringComparison.Ordinal))
            return RollbackRejected("rollback.kind", "does not match the deployed artifact kind");
        if (!string.Equals(rollback.Architecture, artifact.Architecture, StringComparison.Ordinal))
            return RollbackRejected(
                "rollback.architecture",
                "does not match the deployed artifact architecture and cannot run on the target");
        return null;
    }

    private static DeployHandoffMappingResult? CheckAdmissionIdentity(
        DeployHandoffManifest manifest, DeployHandoffAdmissionContext admission)
    {
        var source = manifest.Source!;
        var target = manifest.Target!;
        if (admission.ExpectedRepository is not null &&
            !string.Equals(source.Repository, admission.ExpectedRepository, StringComparison.Ordinal))
            return DeployHandoffMappingResult.Reject(
                DeployHandoffErrorCode.SourceMismatch,
                "source.repository does not match the admitted operation repository.",
                "Send the manifest produced from the admitted repository, or admit that repository for this operation.");
        if (admission.ExpectedCommit is not null &&
            !string.Equals(source.Commit, admission.ExpectedCommit, StringComparison.Ordinal))
            return DeployHandoffMappingResult.Reject(
                DeployHandoffErrorCode.DigestStale,
                "source.commit is stale: it does not match the admitted operation source.",
                "Regenerate the manifest from the admitted commit before handing it to Orchestrator.");
        if (admission.ExpectedTreeDigest is not null &&
            !string.Equals(source.TreeDigest, admission.ExpectedTreeDigest, StringComparison.OrdinalIgnoreCase))
            return DeployHandoffMappingResult.Reject(
                DeployHandoffErrorCode.DigestStale,
                "source.treeDigest is stale: it does not match the admitted operation tree.",
                "Regenerate the manifest from the admitted tree before handing it to Orchestrator.");
        if (admission.ExpectedService is not null &&
            !string.Equals(target.Service, admission.ExpectedService, StringComparison.Ordinal))
            return DeployHandoffMappingResult.Reject(
                DeployHandoffErrorCode.TargetMismatch,
                "target.service does not match the admitted operation target.",
                "Send the manifest built for the admitted service, or admit this target for the operation.");
        if (admission.ExpectedEnvironment is not null &&
            !string.Equals(target.Environment, admission.ExpectedEnvironment, StringComparison.Ordinal))
            return DeployHandoffMappingResult.Reject(
                DeployHandoffErrorCode.TargetMismatch,
                "target.environment does not match the admitted operation target.",
                "Send the manifest built for the admitted environment, or admit this target for the operation.");
        if (admission.ExpectedRegions is { } expectedRegions &&
            !target.Regions!.SequenceEqual(expectedRegions, StringComparer.Ordinal))
            return DeployHandoffMappingResult.Reject(
                DeployHandoffErrorCode.TargetMismatch,
                "target.regions do not match the admitted operation regions in identity or order.",
                "Send the manifest built for the admitted regions, or admit these regions for the operation.");
        return null;
    }

    private static DeployHandoffMappingResult Missing(string field) => DeployHandoffMappingResult.Reject(
        DeployHandoffErrorCode.FieldMissing,
        $"Required field '{field}' is absent.",
        $"Provide {field} in the handoff manifest; see docs/contracts/deploy-orchestrator-handoff.md.");

    private static DeployHandoffMappingResult Unbounded(string field) => DeployHandoffMappingResult.Reject(
        DeployHandoffErrorCode.UnboundedText,
        $"Field '{field}' is empty, too long, duplicated, or contains control characters.",
        "Provide a bounded value within the limits in docs/contracts/deploy-orchestrator-handoff.md.");

    private static DeployHandoffMappingResult InvalidDigest(string field, string shape) => DeployHandoffMappingResult.Reject(
        DeployHandoffErrorCode.DigestInvalid,
        $"Field '{field}' must be {shape}.",
        "Copy the exact identity TerraScale.Deploy produced; never reformat a digest by hand.");

    private static DeployHandoffMappingResult RollbackRejected(string field, string problem) => DeployHandoffMappingResult.Reject(
        DeployHandoffErrorCode.RollbackIncompatible,
        $"{field} {problem}; the rollback handoff must be an exact, deployable prior artifact.",
        "Record the currently deployed artifact and manifest digests, or omit rollback for a first deployment.");

    private static DeployHandoffMappingResult RejectDocument(string message) => DeployHandoffMappingResult.Reject(
        DeployHandoffErrorCode.DocumentInvalid,
        message,
        "Send a bounded single-object JSON document shaped by docs/contracts/deploy-orchestrator-handoff.md.");

    private static bool IsBoundedText(string? value, int maximum) =>
        value is not null && value.Length > 0 && value.Length <= maximum &&
        !value.Any(char.IsControl);

    private static bool IsCommit(string? value) =>
        value is not null && value.Length == 40 && value.All(IsHex);

    private static bool IsDigest(string? value) =>
        value is not null && value.Length == 71 &&
        value.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase) &&
        value[7..].All(IsHex);

    private static bool IsHex(char value) => value is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F';

    private static string Echo(string? value) =>
        string.IsNullOrEmpty(value) ? "(absent)" : value.Length <= 128 ? value : value[..128];

    [GeneratedRegex("(?i)(bearer\\s+|(?:token|password|secret|private[_ -]?key|authorization)\\s*[:=])", RegexOptions.CultureInvariant)]
    private static partial Regex SecretPattern();

    private static JsonSerializerOptions CreateManifestOptions() => new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };
}
