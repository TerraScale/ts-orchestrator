using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace TerraScale.Orchestrator.ControlPlane.Delivery.EndpointVerification;

/// <summary>Route semantics a verified public endpoint must keep.</summary>
public static class EndpointRouteKind
{
    /// <summary>The global hostname routes each client vantage to the nearest healthy selected region.</summary>
    public const string Global = "global";
    /// <summary>A strict regional hostname always routes to its own region and never silently fails over.</summary>
    public const string StrictRegional = "strict_regional";
}

/// <summary>The probe categories one verification round can emit.</summary>
public static class EndpointProbeKind
{
    public const string RegionHealth = "region_health";
    public const string StrictRoute = "strict_route";
    public const string GlobalRoute = "global_route";
    public const string ContractCheck = "contract_check";
}

/// <summary>Status of one verification observation.</summary>
/// <remarks>
/// <see cref="Deferred"/> marks evidence that is descriptor-only at the current fidelity: it
/// never changes an availability claim and never counts as a pass. Honesty about deferred
/// evidence is part of the contract, not an optional detail. <see cref="Unavailable"/> marks a
/// check that did not execute because its SOURCE failed (executor threw, returned null, or
/// reported a cause): distinct from the authorized deferral so an infrastructure outage can
/// never be rendered identical to an intentional live-lane deferral.
/// </remarks>
public static class EndpointObservationStatus
{
    public const string Passed = "passed";
    public const string Failed = "failed";
    public const string Deferred = "deferred";
    public const string Unavailable = "unavailable";
}

/// <summary>Stable, redacted failure codes for endpoint verification.</summary>
public static class EndpointFailureCode
{
    public const string DnsFailure = "dns_failure";
    public const string ProbeUnreachable = "probe_unreachable";
    public const string Misroute = "misroute";
    public const string StrictAffinityViolation = "strict_affinity_violation";
    public const string NoHealthySelectedRegion = "no_healthy_selected_region";
    public const string StaleHealth = "stale_health";
    public const string UnknownHealth = "unknown_health";
    public const string UnhealthyRegion = "unhealthy_region";
    public const string BindingMismatch = "binding_mismatch";
    public const string ContractCheckFailed = "contract_check_failed";
    public const string TlsRejected = "tls_rejected";
    public const string ResolverUnavailable = "resolver_unavailable";
    public const string SourceUnavailable = "source_unavailable";
    public const string NotRecorded = "not_recorded";
    /// <summary>
    /// Stable fallback for an adapter-reported failure code outside this closed set. Adapter
    /// text is untrusted: an unknown code (for example a raw transport error) is replaced by
    /// this constant at the boundary instead of flowing into observations or claims.
    /// </summary>
    public const string Unclassified = "unclassified";
}

/// <summary>The availability claim for one region. Ranks: outage evidence outranks nothing.</summary>
public enum EndpointRegionAvailability
{
    /// <summary>No round has produced evidence for the region yet; never eligible as healthy.</summary>
    Unknown = 0,
    /// <summary>
    /// The latest round verified the region's strict route and fresh identity-bound health with
    /// no failed executed contract check. This is NOT a promise that contract checks executed:
    /// see <see cref="VerifiedRegion.ContractEvidence"/> for the per-region fidelity of the
    /// contract-check evidence behind this claim.
    /// </summary>
    Available = 1,
    /// <summary>The latest round observed a failure for the region.</summary>
    Outage = 2,
}

/// <summary>The fidelity of the contract-check evidence behind one region's availability.</summary>
public enum EndpointContractEvidence
{
    /// <summary>
    /// No public-contract check executed for the region in the claim's round (all checks were
    /// deferred or their source was unavailable). The claim rests on routing and health
    /// evidence only.
    /// </summary>
    RoutingHealthOnly = 0,
    /// <summary>At least one public-contract check executed for the region in the claim's round.</summary>
    WithContractChecks = 1,
}

/// <summary>A named client vantage with its region preference ordered nearest to farthest.</summary>
public sealed record EndpointVantage(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("regionPreference")] IReadOnlyList<string> RegionPreference);

/// <summary>One public endpoint under verification.</summary>
/// <param name="Region">The pinned region for strict endpoints; <c>global</c> for the global endpoint.</param>
public sealed record EndpointProbeTarget(
    [property: JsonPropertyName("hostname")] string Hostname,
    [property: JsonPropertyName("region")] string Region,
    [property: JsonPropertyName("routeKind")] string RouteKind);

/// <summary>The typed result of resolving one endpoint from one vantage.</summary>
/// <remarks>
/// Redacted by construction: addresses appear only as a count, never as values. TLS acceptance is
/// nullable because the managed lane does not evaluate it; <c>null</c> means "not evaluated at
/// this fidelity", never "accepted".
/// </remarks>
public sealed record EndpointRouteResolution(
    bool Resolved,
    string? ObservedRegion,
    int AddressCount,
    DateTimeOffset ObservedAt,
    string? FailureCode,
    bool? TlsAccepted = null);

/// <summary>
/// Resolves public endpoints to their currently routed region. The managed/recorded adapter
/// serves scripted truth; the live DNS/HTTP adapter is a sketch gated on an authorized live lane.
/// </summary>
public interface IEndpointRouteResolver
{
    /// <param name="vantage">The client vantage for global routing; <see langword="null"/> for strict endpoints.</param>
    ValueTask<EndpointRouteResolution> ResolveAsync(
        EndpointProbeTarget target,
        EndpointVantage? vantage,
        CancellationToken cancellationToken);
}

/// <summary>Fresh health evidence for one region, bound to the artifact it was observed under.</summary>
public sealed record RegionHealthSnapshot(
    [property: JsonPropertyName("region")] string Region,
    [property: JsonPropertyName("healthy")] bool? Healthy,
    [property: JsonPropertyName("observedAt")] DateTimeOffset ObservedAt,
    [property: JsonPropertyName("artifactDigest")] string? ArtifactDigest,
    [property: JsonPropertyName("configurationRevision")] string? ConfigurationRevision);

/// <summary>Observes regional health. Absent snapshots are unknown, never healthy.</summary>
public interface IRegionHealthSource
{
    ValueTask<RegionHealthSnapshot?> ObserveAsync(string region, CancellationToken cancellationToken);
}

/// <summary>The check kinds that must run through public contracts.</summary>
public static class PublicContractCheckKind
{
    public const string TenantIsolation = "tenant_isolation";
    public const string SelectedRegionResidency = "selected_region_residency";
    public const string Metering = "metering";
    public const string Replication = "replication";
    public const string Monitoring = "monitoring";
}

/// <summary>
/// A typed verification descriptor over one public-contract surface. At in-process fidelity these
/// are descriptor definitions evaluated against typed fakes; live evaluation is deferred until the
/// live lane is authorized.
/// </summary>
public sealed record PublicContractCheckDescriptor(
    [property: JsonPropertyName("checkId")] string CheckId,
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("region")] string Region,
    [property: JsonPropertyName("contractSurface")] string ContractSurface,
    [property: JsonPropertyName("expectation")] string Expectation);

/// <summary>The outcome of evaluating one descriptor.</summary>
/// <param name="Executed"><see langword="false"/> means descriptor-only (deferred) evidence.</param>
public sealed record PublicContractCheckResult(
    PublicContractCheckDescriptor Descriptor,
    bool Executed,
    bool? Passed,
    DateTimeOffset ObservedAt,
    string? FailureCode,
    string? Note);

/// <summary>Evaluates public-contract check descriptors through public surfaces.</summary>
public interface IPublicContractCheckExecutor
{
    ValueTask<PublicContractCheckResult> ExecuteAsync(PublicContractCheckDescriptor descriptor, CancellationToken cancellationToken);
}

/// <summary>The standard per-region public-contract check set.</summary>
public static class StandardPublicContractChecks
{
    public const string PublicPlatformSurface = "public-contract:platform/v1";

    public static IReadOnlyList<PublicContractCheckDescriptor> ForRegion(string region) =>
    [
        new($"public-contract:{region}:tenant-isolation", PublicContractCheckKind.TenantIsolation, region,
            PublicPlatformSurface, "no public operation serves another tenant's data"),
        new($"public-contract:{region}:selected-region-residency", PublicContractCheckKind.SelectedRegionResidency, region,
            PublicPlatformSurface, "projects selected into the region are served only from selected regions"),
        new($"public-contract:{region}:metering", PublicContractCheckKind.Metering, region,
            PublicPlatformSurface, "every billable public operation records exactly one metering event"),
        new($"public-contract:{region}:replication", PublicContractCheckKind.Replication, region,
            PublicPlatformSurface, "writes replicate to the region set the public replication contract records"),
        new($"public-contract:{region}:monitoring", PublicContractCheckKind.Monitoring, region,
            PublicPlatformSurface, "public operations expose health and freshness through the public monitoring contract"),
    ];
}

/// <summary>
/// One bound observation (AC-2): service, region, artifact digest, configuration revision, and
/// observation time always travel together. The digest and revision bind what the observation
/// verified; the engine stamps the time from its injected clock.
/// </summary>
public sealed record EndpointObservation(
    [property: JsonPropertyName("service")] string Service,
    [property: JsonPropertyName("region")] string Region,
    [property: JsonPropertyName("artifactDigest")] string? ArtifactDigest,
    [property: JsonPropertyName("configurationRevision")] string? ConfigurationRevision,
    [property: JsonPropertyName("observedAt")] DateTimeOffset ObservedAt,
    [property: JsonPropertyName("probeKind")] string ProbeKind,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("failureCode")] string? FailureCode,
    [property: JsonPropertyName("vantage")] string? Vantage = null,
    [property: JsonPropertyName("expectedRegion")] string? ExpectedRegion = null,
    [property: JsonPropertyName("observedRegion")] string? ObservedRegion = null,
    [property: JsonPropertyName("note")] string? Note = null);

/// <summary>A truthful availability transition observed for one region.</summary>
public sealed record EndpointRegionTransition(
    [property: JsonPropertyName("region")] string Region,
    [property: JsonPropertyName("from")] EndpointRegionAvailability From,
    [property: JsonPropertyName("to")] EndpointRegionAvailability To,
    [property: JsonPropertyName("roundId")] long RoundId,
    [property: JsonPropertyName("observedAt")] DateTimeOffset ObservedAt,
    [property: JsonPropertyName("failureCode")] string? FailureCode);

/// <summary>One region inside the verified region set.</summary>
/// <param name="ContractEvidence">
/// Whether any public-contract check actually executed for this region in the claim's round.
/// <see cref="EndpointRegionAvailability.Available"/> without
/// <see cref="EndpointContractEvidence.WithContractChecks"/> is a routing-and-health-only
/// claim, and consumers must not read it as executed contract-check evidence.
/// </param>
public sealed record VerifiedRegion(
    [property: JsonPropertyName("region")] string Region,
    [property: JsonPropertyName("availability")] EndpointRegionAvailability Availability,
    [property: JsonPropertyName("selectedForGlobalRouting")] bool SelectedForGlobalRouting,
    [property: JsonPropertyName("lastTransitionAt")] DateTimeOffset LastTransitionAt,
    [property: JsonPropertyName("lastFailureCode")] string? LastFailureCode,
    [property: JsonPropertyName("contractEvidence")] EndpointContractEvidence ContractEvidence);

/// <summary>
/// The public verified-region claim (the typed region-set contract other surfaces consume). This
/// is DATA, not policy: it changes only through verified observations and never mutates
/// authorization policy — who may act stays in the authorization seams (for example
/// <see cref="IDeliveryAuthorizer"/>), which verification never calls. Each region carries its
/// own <see cref="VerifiedRegion.ContractEvidence"/> fidelity so an Available claim is never
/// read as executed contract-check evidence when it is not.
/// </summary>
public sealed record VerifiedRegionSet(
    [property: JsonPropertyName("schemaVersion")] int SchemaVersion,
    [property: JsonPropertyName("service")] string Service,
    [property: JsonPropertyName("claimedAt")] DateTimeOffset ClaimedAt,
    [property: JsonPropertyName("artifactDigest")] string? ArtifactDigest,
    [property: JsonPropertyName("configurationRevision")] string? ConfigurationRevision,
    [property: JsonPropertyName("globalRoutingAvailable")] bool GlobalRoutingAvailable,
    [property: JsonPropertyName("regions")] IReadOnlyList<VerifiedRegion> Regions)
{
    public const int CurrentSchemaVersion = 1;
}

/// <summary>
/// One redacted, machine-readable verification round. This record is the operator state (full
/// observations and transitions); <see cref="PublicClaim"/> inside it is the public state.
/// </summary>
public sealed record EndpointVerificationReport(
    [property: JsonPropertyName("schemaVersion")] int SchemaVersion,
    [property: JsonPropertyName("service")] string Service,
    [property: JsonPropertyName("roundId")] long RoundId,
    [property: JsonPropertyName("roundObservedAt")] DateTimeOffset RoundObservedAt,
    [property: JsonPropertyName("artifactDigest")] string? ArtifactDigest,
    [property: JsonPropertyName("configurationRevision")] string? ConfigurationRevision,
    [property: JsonPropertyName("observations")] IReadOnlyList<EndpointObservation> Observations,
    [property: JsonPropertyName("transitions")] IReadOnlyList<EndpointRegionTransition> Transitions,
    [property: JsonPropertyName("publicClaim")] VerifiedRegionSet PublicClaim)
{
    public const int CurrentSchemaVersion = 1;
}

/// <summary>One strict regional endpoint in the verification plan.</summary>
public sealed record StrictRegionalEndpoint(
    [property: JsonPropertyName("region")] string Region,
    [property: JsonPropertyName("hostname")] string Hostname);

/// <summary>
/// The bounded verification plan: what to verify, under which artifact and configuration
/// identity, how fresh health must be, and at what cadence rounds run.
/// </summary>
/// <param name="QualifiedRegions">Regions that may appear in the claim (CONTEXT.md qualified regions).</param>
/// <param name="SelectedRegions">Regions eligible for global routing; strict endpoints never route elsewhere.</param>
public sealed record EndpointVerificationPlan(
    string Service,
    string GlobalHostname,
    IReadOnlyList<string> QualifiedRegions,
    IReadOnlyList<string> SelectedRegions,
    IReadOnlyList<StrictRegionalEndpoint> StrictRegionalEndpoints,
    IReadOnlyList<EndpointVantage> Vantages,
    string? ArtifactDigest,
    string? ConfigurationRevision,
    TimeSpan HealthFreshnessWindow,
    TimeSpan Interval);

/// <summary>Receives every completed round (operator consumption seam).</summary>
public interface IEndpointVerificationSink
{
    ValueTask OnRoundAsync(EndpointVerificationReport report, CancellationToken cancellationToken);
}

/// <summary>Canonical, redacted JSON for verification reports and claims.</summary>
public static class EndpointVerificationWireCodec
{
    public static JsonSerializerOptions JsonOptions { get; } = CreateOptions();

    public static string SerializeReport(EndpointVerificationReport report) =>
        JsonSerializer.Serialize(report ?? throw new ArgumentNullException(nameof(report)), JsonOptions);

    public static EndpointVerificationReport DeserializeReport(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
            throw new JsonException("The endpoint verification report document is empty.");
        var report = JsonSerializer.Deserialize<EndpointVerificationReport>(json, JsonOptions)
            ?? throw new JsonException("The endpoint verification report document is null.");
        EnsureSupportedVersion(report.SchemaVersion, EndpointVerificationReport.CurrentSchemaVersion, "report");
        return report;
    }

    public static string SerializeClaim(VerifiedRegionSet claim) =>
        JsonSerializer.Serialize(claim ?? throw new ArgumentNullException(nameof(claim)), JsonOptions);

    public static VerifiedRegionSet DeserializeClaim(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
            throw new JsonException("The verified region set document is empty.");
        var claim = JsonSerializer.Deserialize<VerifiedRegionSet>(json, JsonOptions)
            ?? throw new JsonException("The verified region set document is null.");
        EnsureSupportedVersion(claim.SchemaVersion, VerifiedRegionSet.CurrentSchemaVersion, "verified region set");
        return claim;
    }

    private static void EnsureSupportedVersion(int observed, int current, string document)
    {
        if (observed != current)
            throw new JsonException(
                $"The endpoint verification {document} schema version {observed} is not supported; expected {current}.");
    }

    private static JsonSerializerOptions CreateOptions() => new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };
}

/// <summary>
/// The adapter-text boundary for endpoint verification. Adapter-authored failure codes and note
/// text are untrusted infrastructure output: an unknown code is replaced by the stable
/// <see cref="EndpointFailureCode.Unclassified"/> fallback, and a note that is not bounded
/// lowercase token text is dropped entirely — never clamped, because a truncated hostile string
/// still leaks. Engine-authored constants are contract text and do not pass through here.
/// </summary>
public static class EndpointVerificationRedaction
{
    public const int MaximumAdapterNoteLength = 256;

    private static readonly HashSet<string> KnownFailureCodes = new(StringComparer.Ordinal)
    {
        EndpointFailureCode.DnsFailure,
        EndpointFailureCode.ProbeUnreachable,
        EndpointFailureCode.Misroute,
        EndpointFailureCode.StrictAffinityViolation,
        EndpointFailureCode.NoHealthySelectedRegion,
        EndpointFailureCode.StaleHealth,
        EndpointFailureCode.UnknownHealth,
        EndpointFailureCode.UnhealthyRegion,
        EndpointFailureCode.BindingMismatch,
        EndpointFailureCode.ContractCheckFailed,
        EndpointFailureCode.TlsRejected,
        EndpointFailureCode.ResolverUnavailable,
        EndpointFailureCode.SourceUnavailable,
        EndpointFailureCode.NotRecorded,
        EndpointFailureCode.Unclassified,
    };

    /// <summary>Maps an adapter failure code onto the closed set; null stays null (no failure).</summary>
    public static string? SanitizeFailureCode(string? code) =>
        code is null ? null : KnownFailureCodes.Contains(code) ? code : EndpointFailureCode.Unclassified;

    /// <summary>
    /// Returns the note only when it is bounded lowercase token text
    /// (<c>a-z 0-9 space . - _</c>, non-empty, at most <see cref="MaximumAdapterNoteLength"/>
    /// characters); anything else — including free-form diagnostics like
    /// <c>dial tcp 203.0.113.9:443</c> — is dropped.
    /// </summary>
    public static string? SanitizeNote(string? note)
    {
        if (note is not { Length: > 0 } || note.Length > MaximumAdapterNoteLength)
            return null;
        foreach (var character in note)
            if (character is (>= 'a' and <= 'z') or (>= '0' and <= '9') or ' ' or '.' or '-' or '_')
                continue;
            else
                return null;
        return note;
    }
}

/// <summary>
/// AC-7 adapter: projects one verification round onto the direct delivery health seam
/// (<see cref="IDeliveryTarget.CheckHealthAsync"/>) shapes, so delivery health verification can
/// consume endpoint verification without a new wire format.
/// </summary>
/// <remarks>
/// The seam exposes only Passed/Failed, so not-executed evidence is carried in the check NAME:
/// a deferred descriptor becomes <c>...:deferred</c> and an unavailable check source becomes
/// <c>...:unavailable</c>, both reporting Passed. Deferred and unavailable are the absence of
/// evidence, not failure evidence, and must not fail a delivery — but the suffix keeps them
/// distinguishable from executed passes. Only <see cref="EndpointObservationStatus.Failed"/>
/// observations map to <see cref="DeliveryHealthStatus.Failed"/>.
/// </remarks>
public static class EndpointVerificationDeliveryHealth
{
    public static DeliveryHealth ToDeliveryHealth(EndpointVerificationReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        var checks = new List<DeliveryHealthCheck>(report.Observations.Count);
        foreach (var observation in report.Observations)
            checks.Add(new DeliveryHealthCheck(CheckName(observation), CheckStatus(observation)));
        var converged = checks.Count > 0 &&
            report.Observations.All(static observation => observation.Status != EndpointObservationStatus.Failed);
        return new DeliveryHealth(checks, converged);
    }

    public static DeliveryHealthResult ToDeliveryHealthResult(EndpointVerificationReport report)
    {
        var health = ToDeliveryHealth(report);
        return new DeliveryHealthResult(health.Converged, health.Checks);
    }

    private static string CheckName(EndpointObservation observation)
    {
        var identity = observation.ProbeKind == EndpointProbeKind.GlobalRoute && observation.Vantage is { Length: > 0 } vantage
            ? vantage
            : observation.Region;
        var suffix = observation.Status switch
        {
            EndpointObservationStatus.Deferred => ":deferred",
            EndpointObservationStatus.Unavailable => ":unavailable",
            _ => string.Empty,
        };
        return $"endpoint-verification:{observation.ProbeKind}:{identity}{suffix}";
    }

    private static string CheckStatus(EndpointObservation observation) =>
        observation.Status == EndpointObservationStatus.Failed
            ? DeliveryHealthStatus.Failed
            : DeliveryHealthStatus.Passed;
}

