using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace TerraScale.Orchestrator.Runtime.Mcp;

/// <summary>
/// Canonical public route and host-owned application paths of the MCP product workload
/// (ADR 0032). These are string constants recorded in the typed manifest; they are not live
/// DNS or ingress bindings, and no live ingress activation is implied by declaring them.
/// </summary>
public static class McpPublicRoutes
{
    /// <summary>
    /// Canonical public host. TLS terminates at the shared product edge and forwarding
    /// preserves the host's HTTPS requirement; the workload never serves plain HTTP publicly.
    /// </summary>
    public const string CanonicalHost = "mcp.terrascale.tech";

    /// <summary>The canonical MCP application path owned by the workload host.</summary>
    public const string McpPath = "/mcp";

    /// <summary>The canonical public MCP endpoint: https://mcp.terrascale.tech/mcp.</summary>
    public const string CanonicalRoute = "https://" + CanonicalHost + McpPath;

    /// <summary>OAuth 2.0 protected-resource metadata path owned by the workload host.</summary>
    public const string ProtectedResourceMetadataPath = "/.well-known/oauth-protected-resource/mcp";

    /// <summary>Host-owned liveness path. It reports process health only.</summary>
    public const string LivenessPath = "/health/live";

    /// <summary>Host-owned readiness path. It reports dependency readiness only.</summary>
    public const string ReadinessPath = "/health/ready";
}

/// <summary>The route kinds the MCP host owns. Closed set; no other route may be declared.</summary>
public enum McpRouteKind
{
    McpEndpoint = 0,
    ProtectedResourceMetadata = 1,
    Liveness = 2,
    Readiness = 3,
}

/// <summary>
/// The redacted public projection of one MCP route. Redacted by construction: it carries only
/// the route kind, host, path, transport requirement, and routability. Project identifiers,
/// caller identity, credentials, and internal diagnostics have no field to live in, so no
/// mapping produced from this record can expose them.
/// </summary>
public sealed record McpPublicRouteView(
    [property: JsonPropertyName("kind")] McpRouteKind Kind,
    [property: JsonPropertyName("host")] string Host,
    [property: JsonPropertyName("path")] string Path,
    [property: JsonPropertyName("httpsRequired")] bool HttpsRequired,
    [property: JsonPropertyName("publiclyRoutable")] bool PubliclyRoutable);

/// <summary>The closed MCP route mapping: exactly the canonical endpoint, the protected-resource
/// metadata route, and the two health routes, all on the canonical HTTPS host.</summary>
public static class McpRouteContract
{
    /// <summary>True only for routes a public client may traverse once ingress is open.</summary>
    private static bool IsPubliclyRoutable(McpRouteKind kind) =>
        kind is McpRouteKind.McpEndpoint or McpRouteKind.ProtectedResourceMetadata;

    public static McpPublicRouteView McpEndpoint { get; } = new(
        McpRouteKind.McpEndpoint,
        McpPublicRoutes.CanonicalHost,
        McpPublicRoutes.McpPath,
        HttpsRequired: true,
        PubliclyRoutable: IsPubliclyRoutable(McpRouteKind.McpEndpoint));

    public static McpPublicRouteView ProtectedResourceMetadata { get; } = new(
        McpRouteKind.ProtectedResourceMetadata,
        McpPublicRoutes.CanonicalHost,
        McpPublicRoutes.ProtectedResourceMetadataPath,
        HttpsRequired: true,
        PubliclyRoutable: IsPubliclyRoutable(McpRouteKind.ProtectedResourceMetadata));

    public static McpPublicRouteView Liveness { get; } = new(
        McpRouteKind.Liveness,
        McpPublicRoutes.CanonicalHost,
        McpPublicRoutes.LivenessPath,
        HttpsRequired: true,
        PubliclyRoutable: IsPubliclyRoutable(McpRouteKind.Liveness));

    public static McpPublicRouteView Readiness { get; } = new(
        McpRouteKind.Readiness,
        McpPublicRoutes.CanonicalHost,
        McpPublicRoutes.ReadinessPath,
        HttpsRequired: true,
        PubliclyRoutable: IsPubliclyRoutable(McpRouteKind.Readiness));

    /// <summary>Every MCP route mapping, in canonical order. No other mapping exists.</summary>
    public static IReadOnlyList<McpPublicRouteView> All { get; } =
        [McpEndpoint, ProtectedResourceMetadata, Liveness, Readiness];

    /// <summary>The admitted health-probe paths. A manifest may declare no others.</summary>
    public static IReadOnlyList<string> AdmittedProbePaths { get; } =
        [McpPublicRoutes.LivenessPath, McpPublicRoutes.ReadinessPath];
}

/// <summary>
/// The Orchestrator-owned listener reservation for the MCP workload. The workload binds one
/// fixed host-local HTTP port recorded in the typed manifest.
/// </summary>
public static class McpWorkloadPorts
{
    /// <summary>
    /// The single admitted host-local HTTP listener port. A distinct port may be assigned only
    /// through an ADR-0032 catalog change after deployment qualification.
    /// </summary>
    public const int HttpListenerPort = 18675;
}

/// <summary>
/// The closed set of approved MCP configuration keys. Values are bounded, non-secret
/// configuration only; the Internals MCP access and token-exchange contract keys join this set
/// only when that contract lands (cross-repository dependency recorded in ADR 0032).
/// </summary>
public static class McpConfigurationKeys
{
    public const string PublicBaseUrl = "public-base-url";
    public const string AuthenticationIssuerUrl = "authentication-issuer-url";
    public const string DashboardApiBaseUrl = "dashboard-api-base-url";
    public const string MinimumLogLevel = "minimum-log-level";

    public static IReadOnlyList<string> All { get; } =
        [PublicBaseUrl, AuthenticationIssuerUrl, DashboardApiBaseUrl, MinimumLogLevel];

    /// <summary>Keys whose values must be absolute HTTPS URLs.</summary>
    public static IReadOnlyList<string> HttpsUrlKeys { get; } =
        [PublicBaseUrl, AuthenticationIssuerUrl, DashboardApiBaseUrl];
}

/// <summary>
/// One secret reference for the MCP workload: a bounded vault path token. It names WHERE the
/// confidential material lives; the bytes are delivered by the runtime credential mechanism at
/// execution time and never appear in desired state, manifests, journals, logs, or evidence.
/// </summary>
public sealed partial record McpSecretReference
{
    public const string Scheme = "vault";
    public const string AdmittedPathPrefix = "terrascale/mcp/";
    public const int MaximumLength = 128;

    public McpSecretReference(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length > MaximumLength || !TokenPattern().IsMatch(value))
        {
            throw new ArgumentException(
                "A MCP secret reference must be a bounded 'vault:terrascale/mcp/<name>' token.", nameof(value));
        }
        Value = value;
        if (!ReferenceNames.Contains(Name))
        {
            throw new ArgumentException(
                $"The MCP secret reference '{value}' is not admitted; only " +
                $"'{string.Join("', '", ReferenceNames)}' may be referenced.", nameof(value));
        }
    }

    public string Value { get; }

    /// <summary>The reference name after the admitted path prefix.</summary>
    public string Name => Value[(Scheme.Length + 1 + AdmittedPathPrefix.Length)..];

    private static readonly IReadOnlyList<string> ReferenceNames =
    [
        McpSecretReferenceNames.OAuthClientSecret,
    ];

    [GeneratedRegex("^vault:terrascale/mcp/[a-z0-9][a-z0-9-]{0,62}$", RegexOptions.CultureInvariant)]
    private static partial Regex TokenPattern();
}

/// <summary>The admitted secret reference names for the MCP workload.</summary>
public static class McpSecretReferenceNames
{
    /// <summary>
    /// The confidential OAuth client secret. Admitted BY REFERENCE only: no manifest, desired
    /// state, journal, receipt, or evidence document may carry its bytes.
    /// </summary>
    public const string OAuthClientSecret = "oauth-client-secret";
}

/// <summary>The closed set of secret references the MCP workload may declare.</summary>
public static class McpSecretReferenceContract
{
    /// <summary>The canonical OAuth client secret reference (reference only, never bytes).</summary>
    public static McpSecretReference Default { get; } =
        new($"{McpSecretReference.Scheme}:{McpSecretReference.AdmittedPathPrefix}{McpSecretReferenceNames.OAuthClientSecret}");

    public static IReadOnlyList<McpSecretReference> Admitted { get; } = [Default];
}

/// <summary>One qualified MCP HTTP artifact: an exact digest bound to one host architecture.</summary>
public sealed record McpQualifiedHttpArtifact
{
    public const int DigestLength = 64;

    public McpQualifiedHttpArtifact(string digest, HostArchitecture architecture)
    {
        ArgumentNullException.ThrowIfNull(digest);
        if (digest.Length != DigestLength || digest.Any(static character =>
                character is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
        {
            throw new ArgumentException(
                "A qualified MCP artifact digest must be lowercase SHA-256 hex.", nameof(digest));
        }
        if (!Enum.IsDefined(architecture))
        {
            throw new ArgumentException("The MCP artifact architecture is not admitted.", nameof(architecture));
        }
        Digest = digest;
        Architecture = architecture;
    }

    public string Digest { get; }
    public HostArchitecture Architecture { get; }
}

/// <summary>
/// The qualified MCP HTTP artifact set. Fail-closed by construction: <see cref="None"/> admits
/// no artifact, so nothing is deployable until qualification evidence registers exact digests.
/// The TerraScale.MCP HTTP artifact qualification is a cross-repository dependency tracked by
/// TerraScale.Orchestrator#9; digests enter this set only from accepted qualification evidence,
/// never from a delivery request.
/// </summary>
public sealed class McpHttpArtifactQualification
{
    public static McpHttpArtifactQualification None { get; } = new([]);

    private readonly IReadOnlyDictionary<HostArchitecture, IReadOnlyList<string>> digestsByArchitecture;

    private McpHttpArtifactQualification(IReadOnlyList<McpQualifiedHttpArtifact> artifacts)
    {
        Artifacts = artifacts;
        digestsByArchitecture = artifacts
            .GroupBy(static artifact => artifact.Architecture)
            .ToDictionary(
                static group => group.Key,
                static group => (IReadOnlyList<string>)group.Select(static artifact => artifact.Digest).ToArray(),
                EqualityComparer<HostArchitecture>.Default);
    }

    public IReadOnlyList<McpQualifiedHttpArtifact> Artifacts { get; }

    /// <summary>
    /// Builds a qualification from exact evidence. Multiple digests per architecture are
    /// allowed (the current and prior qualified releases), but digest/architecture pairs must
    /// be distinct.
    /// </summary>
    public static McpHttpArtifactQualification Of(params McpQualifiedHttpArtifact[] artifacts)
    {
        ArgumentNullException.ThrowIfNull(artifacts);
        if (artifacts.Select(static artifact => (artifact.Digest, artifact.Architecture)).Distinct().Count() != artifacts.Length)
            throw new ArgumentException("A digest/architecture pair may appear exactly once in a qualification.");
        return new McpHttpArtifactQualification(artifacts);
    }

    public bool Admits(string digest, HostArchitecture architecture) =>
        digestsByArchitecture.TryGetValue(architecture, out var qualified) &&
        qualified.Contains(digest, StringComparer.Ordinal);

    public bool AdmitsArchitecture(HostArchitecture architecture) =>
        digestsByArchitecture.ContainsKey(architecture);
}

/// <summary>The live evidence an open MCP ingress requires. Absence of any item keeps ingress closed.</summary>
public sealed record McpIngressEvidence(
    bool AuthenticationVerified,
    bool ScopeDenialVerified,
    bool TenantIsolationVerified,
    bool HealthVerified,
    bool RollbackVerified)
{
    public bool IsComplete =>
        AuthenticationVerified && ScopeDenialVerified && TenantIsolationVerified &&
        HealthVerified && RollbackVerified;

    public static McpIngressEvidence None { get; } = new(false, false, false, false, false);
}

public enum McpIngressState
{
    Closed = 0,
    Open = 1,
}

/// <summary>
/// Ingress stays closed until the complete live evidence bundle passes. Live
/// Authentication, scope-denial, isolation, health, and rollback evidence is produced on the
/// live lane; this gate is the typed, fail-closed record of that requirement.
/// </summary>
public static class McpIngressGate
{
    public static McpIngressState Evaluate(McpIngressEvidence? evidence) =>
        evidence is { IsComplete: true } ? McpIngressState.Open : McpIngressState.Closed;
}

/// <summary>The placement contract of the stateless MCP workload.</summary>
public static class McpPlacementContract
{
    /// <summary>Two instances is the admission floor: independent failure domains, independently routed.</summary>
    public const int MinimumInstances = 2;

    /// <summary>
    /// Stateless routing: requests carry no session affinity. Any healthy backend may serve any
    /// request, and consecutive requests may be served by different backends.
    /// </summary>
    public const bool StickySessions = false;
}

/// <summary>One named product route in the operator route table.</summary>
public sealed record McpProductRouteEntry(string Name, bool Open);

/// <summary>The operator view of product routes, including the MCP route.</summary>
public sealed record McpProductRouteTable(IReadOnlyList<McpProductRouteEntry> Routes)
{
    public const string McpRouteName = "mcp";

    public static McpProductRouteTable WithRoutesOpen(IReadOnlyList<string> names) =>
        new(names.Select(name => new McpProductRouteEntry(name, Open: true)).ToArray());

    public bool IsOpen(string name) =>
        Routes.Any(route => route.Name == name && route.Open);

    public IReadOnlyList<string> OpenRouteNames =>
        Routes.Where(static route => route.Open).Select(static route => route.Name).ToArray();
}

/// <summary>
/// The stdio MCP distribution channel: artifacts customers run locally. It is outside this
/// control plane's HTTP route table — withdrawing the MCP HTTP route never touches it.
/// </summary>
public static class McpStdioDistributionChannel
{
    public const string ChannelName = "stdio";
}

/// <summary>The typed result of an emergency MCP route withdrawal.</summary>
public sealed record McpRouteWithdrawal(
    IReadOnlyList<string> ClosedRoutes,
    IReadOnlyList<string> UntouchedRoutes,
    IReadOnlyList<string> UntouchedDistributionChannels,
    McpProductRouteTable RemainingRoutes);

/// <summary>
/// Emergency withdrawal of the MCP route. It closes ONLY the MCP HTTP route: every other
/// product route and the separately distributed stdio artifacts are untouched. Withdrawal is
/// an operator route action, not a workload mutation; instances and artifacts are left alone.
/// </summary>
public static class McpEmergencyRouteControl
{
    public static McpRouteWithdrawal Withdraw(McpProductRouteTable table)
    {
        ArgumentNullException.ThrowIfNull(table);
        var closed = table.Routes
            .Where(route => route.Name == McpProductRouteTable.McpRouteName)
            .Select(static route => route.Name)
            .ToArray();
        return new(
            closed,
            table.Routes.Where(route => route.Name != McpProductRouteTable.McpRouteName)
                .Select(static route => route.Name)
                .ToArray(),
            [McpStdioDistributionChannel.ChannelName],
            new McpProductRouteTable(table.Routes
                .Select(route => route.Name == McpProductRouteTable.McpRouteName
                    ? route with { Open = false }
                    : route)
                .ToArray()));
    }
}
