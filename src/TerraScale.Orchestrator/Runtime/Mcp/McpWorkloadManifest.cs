using System.Collections.Frozen;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace TerraScale.Orchestrator.Runtime.Mcp;

/// <summary>
/// The typed desired-state manifest of the MCP workload. Every field is closed: one qualified
/// digest/architecture pair, the single admitted listener port, approved configuration keys
/// only, secret references only, and the admitted probe paths. Arbitrary images, executable
/// paths, mounts, capabilities, environment injection, and free-form ingress are not
/// expressible in this type and are rejected at the document seam below.
/// </summary>
public sealed record McpWorkloadManifest(
    string ArtifactDigest,
    HostArchitecture Architecture,
    int HttpListenerPort,
    IReadOnlyDictionary<string, string> Configuration,
    IReadOnlyList<McpSecretReference> SecretReferences,
    IReadOnlyList<string> ProbePaths);

/// <summary>Stable, redacted admission codes for the MCP workload manifest.</summary>
public enum McpAdmissionCode
{
    Admitted = 0,
    DocumentInvalid = 1,
    FieldUnknown = 2,
    AmbiguousContent = 3,
    FieldMissing = 4,
    ArtifactNotQualified = 5,
    ArchitectureNotQualified = 6,
    PortNotAdmitted = 7,
    ConfigurationKeyNotAdmitted = 8,
    ConfigurationValueRejected = 9,
    SecretReferenceNotAdmitted = 10,
    ProbePathNotAdmitted = 11,
}

/// <summary>The bounded typed result of admitting one MCP workload manifest.</summary>
public sealed record McpAdmissionDecision(McpAdmissionCode Code, string Field, string Detail)
{
    public bool IsAdmitted => Code == McpAdmissionCode.Admitted;

    public static McpAdmissionDecision Admitted() =>
        new(McpAdmissionCode.Admitted, string.Empty, string.Empty);

    internal static McpAdmissionDecision Reject(McpAdmissionCode code, string field, string detail) =>
        new(code, field, detail);
}

/// <summary>
/// The strict wire shape of one MCP workload manifest document. Parsing is closed: unknown or
/// generic workload fields fail closed before any typed value exists.
/// </summary>
public sealed record McpWorkloadManifestDocument(
    [property: JsonPropertyName("schemaVersion")] int? SchemaVersion,
    [property: JsonPropertyName("artifact")] McpArtifactDocument? Artifact,
    [property: JsonPropertyName("httpListenerPort")] int? HttpListenerPort,
    [property: JsonPropertyName("configuration")] IReadOnlyDictionary<string, string?>? Configuration,
    [property: JsonPropertyName("secretReferences")] IReadOnlyList<string?>? SecretReferences,
    [property: JsonPropertyName("probes")] IReadOnlyList<string?>? Probes);

public sealed record McpArtifactDocument(
    [property: JsonPropertyName("digest")] string? Digest,
    [property: JsonPropertyName("architecture")] string? Architecture);

/// <summary>
/// Admission of the MCP workload manifest against the closed catalog (ADR 0032). A pure
/// decision: no I/O, no mutation, no environment, no clock. The qualified artifact set arrives
/// as an explicit typed input so nothing is admitted before qualification evidence exists.
/// </summary>
public static partial class McpWorkloadAdmission
{
    public const int CurrentSchemaVersion = 1;
    public const int MaximumDocumentCharacters = 65_536;
    public const int MaximumConfigurationKeys = 16;
    public const int MaximumConfigurationValueLength = 256;
    public const int MaximumSecretReferences = 4;

    private static readonly FrozenSet<string> AllowedRootFields = new[]
    {
        "schemaVersion", "artifact", "httpListenerPort", "configuration", "secretReferences", "probes",
    }.ToFrozenSet(StringComparer.Ordinal);

    private static readonly FrozenSet<string> AllowedArtifactFields = new[]
    {
        "digest", "architecture",
    }.ToFrozenSet(StringComparer.Ordinal);

    /// <summary>
    /// Generic workload-descriptor keys that must never be admitted through the typed MCP
    /// manifest seam. A document carrying any of them is rejected as ambiguous content before
    /// its typed values exist: the MCP workload runs the exact qualified artifact, not an
    /// operator-supplied image, executable, mount, capability, or environment payload.
    /// </summary>
    private static readonly FrozenSet<string> GenericWorkloadFields = new[]
    {
        "image", "images", "executable", "exec", "entrypoint", "command", "cmd", "args", "arguments",
        "mounts", "volumes", "devices", "hostPaths", "capabilities", "caps", "privileged",
        "environment", "env", "environmentFile", "user", "group", "workingDirectory", "shell",
        "ingress", "ingressHost", "dns", "hosts", "ports", "tlsCertificate", "certificate",
        "credentials", "secret", "secrets", "token", "apiKey",
    }.ToFrozenSet(StringComparer.Ordinal);

    private static readonly JsonSerializerOptions DocumentOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    /// <summary>Admits a manifest document (the persisted/wire shape). Fails closed on any unknown field.</summary>
    public static McpAdmissionDecision AdmitDocument(string json, McpHttpArtifactQualification qualification)
    {
        ArgumentNullException.ThrowIfNull(qualification);
        if (string.IsNullOrWhiteSpace(json) || json.Length > MaximumDocumentCharacters)
            return Reject(McpAdmissionCode.DocumentInvalid, "document", "The manifest document is empty or exceeds the document bound.");
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(json);
        }
        catch (JsonException)
        {
            return Reject(McpAdmissionCode.DocumentInvalid, "document", "The manifest document is not valid JSON.");
        }
        using (document)
        {
            if (document.RootElement.ValueKind is not JsonValueKind.Object)
                return Reject(McpAdmissionCode.DocumentInvalid, "document", "The manifest document must be a single JSON object.");
            var violation = ScanElement(document.RootElement, string.Empty, string.Empty);
            if (violation is not null)
                return violation;
        }

        McpWorkloadManifestDocument parsed;
        try
        {
            parsed = JsonSerializer.Deserialize<McpWorkloadManifestDocument>(json, DocumentOptions)
                ?? throw new JsonException();
        }
        catch (JsonException)
        {
            return Reject(McpAdmissionCode.DocumentInvalid, "document", "The manifest document has an unexpected value type.");
        }

        if (parsed.SchemaVersion is not CurrentSchemaVersion)
            return Reject(McpAdmissionCode.DocumentInvalid, "schemaVersion",
                $"The manifest schema version must be {CurrentSchemaVersion}.");
        if (parsed.Artifact is not { } artifact)
            return Reject(McpAdmissionCode.FieldMissing, "artifact", "The qualified artifact is required.");
        if (string.IsNullOrEmpty(artifact.Digest))
            return Reject(McpAdmissionCode.FieldMissing, "artifact.digest", "The artifact digest is required.");
        if (artifact.Architecture is not { } architectureText || !TryParseArchitecture(architectureText, out var architecture))
            return Reject(McpAdmissionCode.DocumentInvalid, "artifact.architecture",
                "The artifact architecture must be 'linux/arm64' or 'linux/amd64'.");
        if (parsed.HttpListenerPort is not int port)
            return Reject(McpAdmissionCode.FieldMissing, "httpListenerPort", "The fixed HTTP listener port is required.");
        if (parsed.SecretReferences is null)
            return Reject(McpAdmissionCode.FieldMissing, "secretReferences", "The secret reference list is required.");
        if (parsed.SecretReferences.Count is 0)
            return Reject(McpAdmissionCode.FieldMissing, "secretReferences", "The OAuth client secret reference is required by reference.");
        if (parsed.Probes is null)
            return Reject(McpAdmissionCode.FieldMissing, "probes", "The admitted probe paths are required.");

        var configuration = new Dictionary<string, string>(StringComparer.Ordinal);
        if (parsed.Configuration is { } values)
        {
            foreach (var (key, value) in values)
            {
                if (value is null)
                    return Reject(McpAdmissionCode.ConfigurationValueRejected, $"configuration.{key}", "A configuration value is null.");
                configuration[key] = value;
            }
        }

        var secretReferences = new List<McpSecretReference>(parsed.SecretReferences.Count);
        foreach (var value in parsed.SecretReferences)
        {
            if (value is null)
                return Reject(McpAdmissionCode.DocumentInvalid, "secretReferences", "A secret reference is null.");
            if (!McpSecretReferenceToken().IsMatch(value))
                return Reject(McpAdmissionCode.SecretReferenceNotAdmitted, "secretReferences",
                    "A secret reference must be a bounded 'vault:terrascale/mcp/<name>' token; secret bytes are never admitted.");
            try
            {
                secretReferences.Add(new McpSecretReference(value));
            }
            catch (ArgumentException)
            {
                return Reject(McpAdmissionCode.SecretReferenceNotAdmitted, "secretReferences",
                    $"The secret reference is not admitted; only '{McpSecretReferenceNames.OAuthClientSecret}' may be referenced.");
            }
        }

        var probes = parsed.Probes.Where(value => value is not null).Cast<string>().ToArray();
        if (probes.Length != parsed.Probes.Count)
            return Reject(McpAdmissionCode.DocumentInvalid, "probes", "A probe path is null.");

        return AdmitManifest(new McpWorkloadManifest(
            artifact.Digest!,
            architecture,
            port,
            configuration,
            secretReferences,
            probes), qualification);
    }

    /// <summary>Admits an already-typed manifest against the closed catalog and the qualification.</summary>
    public static McpAdmissionDecision AdmitManifest(McpWorkloadManifest manifest, McpHttpArtifactQualification qualification)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(qualification);

        if (manifest.ArtifactDigest is not { Length: McpQualifiedHttpArtifact.DigestLength } digest ||
            digest.Any(static character => character is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
            return Reject(McpAdmissionCode.ArtifactNotQualified, "artifact.digest",
                "The artifact digest must be lowercase SHA-256 hex bound to a qualified artifact.");
        if (!Enum.IsDefined(manifest.Architecture))
            return Reject(McpAdmissionCode.DocumentInvalid, "artifact.architecture", "The artifact architecture is not admitted.");
        if (!qualification.AdmitsArchitecture(manifest.Architecture))
            return Reject(McpAdmissionCode.ArchitectureNotQualified, "artifact.architecture",
                "No qualified MCP HTTP artifact exists for this architecture.");
        if (!qualification.Admits(digest, manifest.Architecture))
            return Reject(McpAdmissionCode.ArtifactNotQualified, "artifact.digest",
                "The artifact digest is not the qualified digest for this architecture; arbitrary images and executables are not admitted.");

        if (manifest.HttpListenerPort != McpWorkloadPorts.HttpListenerPort)
            return Reject(McpAdmissionCode.PortNotAdmitted, "httpListenerPort",
                $"The MCP workload listens on exactly port {McpWorkloadPorts.HttpListenerPort}; no other port is admitted.");

        // A typed manifest with a null collection is a malformed document, not an exception:
        // reject it with the same bounded vocabulary the document seam uses (R8).
        if (manifest.Configuration is null)
            return Reject(McpAdmissionCode.FieldMissing, "configuration",
                "The configuration map is required (it may be empty).");
        if (manifest.SecretReferences is null)
            return Reject(McpAdmissionCode.FieldMissing, "secretReferences",
                "The secret reference list is required.");
        if (manifest.ProbePaths is null)
            return Reject(McpAdmissionCode.FieldMissing, "probes",
                "The probe path list is required.");

        if (manifest.Configuration.Count > MaximumConfigurationKeys)
            return Reject(McpAdmissionCode.ConfigurationValueRejected, "configuration",
                $"The manifest carries more than {MaximumConfigurationKeys} configuration keys.");
        foreach (var (key, value) in manifest.Configuration)
        {
            if (!McpConfigurationKeys.All.Contains(key))
                return Reject(McpAdmissionCode.ConfigurationKeyNotAdmitted, $"configuration.{key}",
                    "The configuration key is not in the approved MCP configuration set.");
            if (string.IsNullOrEmpty(value) || value.Length > MaximumConfigurationValueLength ||
                value.Any(char.IsControl))
                return Reject(McpAdmissionCode.ConfigurationValueRejected, $"configuration.{key}",
                    "The configuration value is empty, unbounded, or carries control characters.");
            if (SecretBearingText(value))
                return Reject(McpAdmissionCode.ConfigurationValueRejected, $"configuration.{key}",
                    "The configuration value appears to contain secret material; secrets travel by reference only.");
            if (McpConfigurationKeys.HttpsUrlKeys.Contains(key) &&
                (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != "https" || uri.Host.Length == 0))
                return Reject(McpAdmissionCode.ConfigurationValueRejected, $"configuration.{key}",
                    "The URL-valued configuration must be an absolute HTTPS URL.");
        }

        if (manifest.SecretReferences.Count is 0 or > MaximumSecretReferences)
            return Reject(McpAdmissionCode.SecretReferenceNotAdmitted, "secretReferences",
                "The manifest must carry at least the OAuth client secret reference and no more than the admitted references.");
        foreach (var reference in manifest.SecretReferences)
        {
            if (reference.Name != McpSecretReferenceNames.OAuthClientSecret)
                return Reject(McpAdmissionCode.SecretReferenceNotAdmitted, "secretReferences",
                    $"Only the '{McpSecretReferenceNames.OAuthClientSecret}' reference is admitted.");
        }
        if (!manifest.SecretReferences.Any(reference =>
                reference.Name == McpSecretReferenceNames.OAuthClientSecret))
            return Reject(McpAdmissionCode.FieldMissing, "secretReferences",
                "The OAuth client secret reference is required by reference.");

        if (!manifest.ProbePaths.SequenceEqual(McpRouteContract.AdmittedProbePaths, StringComparer.Ordinal))
            return Reject(McpAdmissionCode.ProbePathNotAdmitted, "probes",
                $"The admitted probe paths are exactly {string.Join(", ", McpRouteContract.AdmittedProbePaths)}.");

        return McpAdmissionDecision.Admitted();
    }

    private static McpAdmissionDecision? ScanElement(JsonElement element, string path, string parentField)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                // Only the document root and the artifact object have closed field sets; the
                // configuration object's keys are admitted later against the approved
                // configuration set, and generic workload fields are rejected everywhere.
                FrozenSet<string>? allowed = parentField.Length == 0 ? AllowedRootFields
                    : parentField == "artifact" ? AllowedArtifactFields
                    : null;
                var seen = new HashSet<string>(StringComparer.Ordinal);
                foreach (var property in element.EnumerateObject())
                {
                    var propertyPath = path.Length == 0 ? property.Name : $"{path}.{property.Name}";
                    if (!seen.Add(property.Name))
                        return Reject(McpAdmissionCode.AmbiguousContent, propertyPath,
                            "The property appears more than once.");
                    if (GenericWorkloadFields.Contains(property.Name))
                        return Reject(McpAdmissionCode.AmbiguousContent, propertyPath,
                            "Generic workload descriptor content is not admitted; the MCP workload runs the exact qualified artifact only.");
                    if (allowed is not null && !allowed.Contains(property.Name))
                        return Reject(McpAdmissionCode.FieldUnknown, propertyPath,
                            "The field is not mapped by the MCP workload manifest contract.");
                    var nested = ScanElement(property.Value, propertyPath, property.Name);
                    if (nested is not null)
                        return nested;
                }
                break;
            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray())
                {
                    var nested = ScanElement(item, path, parentField);
                    if (nested is not null)
                        return nested;
                }
                break;
        }
        return null;
    }

    /// <summary>
    /// Maps the deployment-platform architecture string carried by delivery handoffs onto the
    /// host architecture the catalog admits. 'multi' is deliberately not admitted: the MCP
    /// artifact must be architecture-exact.
    /// </summary>
    public static bool TryParseArchitecture(string value, out HostArchitecture architecture)
    {
        switch (value)
        {
            case "linux/arm64":
                architecture = HostArchitecture.Arm64;
                return true;
            case "linux/amd64":
                architecture = HostArchitecture.X64;
                return true;
            default:
                architecture = default;
                return false;
        }
    }

    internal static bool SecretBearingText(string? value) =>
        value is not null && SecretPattern().IsMatch(value);

    [GeneratedRegex("(?i)(bearer\\s+|(?:token|password|secret|private[_ -]?key|authorization)\\s*[:=]|-----BEGIN)", RegexOptions.CultureInvariant)]
    private static partial Regex SecretPattern();

    [GeneratedRegex("^vault:terrascale/mcp/[a-z0-9][a-z0-9-]{0,62}$", RegexOptions.CultureInvariant)]
    private static partial Regex McpSecretReferenceToken();

    private static McpAdmissionDecision Reject(McpAdmissionCode code, string field, string detail) =>
        McpAdmissionDecision.Reject(code, field, detail);
}
