namespace TerraScale.Orchestrator.Contracts.Resources;

public enum RoleKind
{
    Platform = 1,
    Authentication = 2,
    CustomerDashboard = 3,
    TerraBaseMember = 4,
    Orchestrator = 5,
    ControlNatsServer = 6,
    ProductNatsServer = 7,
    Grafana = 8,
    MetricsStore = 9,
    Loki = 10,
    Tempo = 11,
    Alertmanager = 12,
    OtlpIngest = 13,
    SyntheticCheck = 14,
    RegionalTelemetryAgent = 15,
    VpnCoordinationRelay = 16,
    RoutePolicyController = 17,
    CiRunner = 18,
}

public enum ImplementationDomain
{
    MetricsStore = 1,
    RegionalTelemetry = 2,
    Vpn = 3,
}

public sealed record ApprovedImplementationCatalogKey
{
    public ApprovedImplementationCatalogKey(ImplementationDomain domain, ResourceId catalogEntryId)
    {
        if (!Enum.IsDefined(domain))
        {
            throw new ArgumentOutOfRangeException(nameof(domain));
        }

        Domain = domain;
        CatalogEntryId = catalogEntryId ?? throw new ArgumentNullException(nameof(catalogEntryId));
    }

    public ImplementationDomain Domain { get; }

    public ResourceId CatalogEntryId { get; }

    public override string ToString() => $"{Domain}:{CatalogEntryId}";
}

/// <summary>
/// Closed v1 role union for INV-017. The private-protected constructor prevents
/// consumers from inventing a workload kind outside this assembly.
/// </summary>
public abstract class AdmittedRole
{
    internal AdmittedRole(RoleKind kind) => Kind = kind;

    public RoleKind Kind { get; }

    internal virtual string Projection => Kind.ToString();
}

public sealed class PlatformRole : AdmittedRole { public PlatformRole() : base(RoleKind.Platform) { } }
public sealed class AuthenticationRole : AdmittedRole { public AuthenticationRole() : base(RoleKind.Authentication) { } }
public sealed class CustomerDashboardRole : AdmittedRole { public CustomerDashboardRole() : base(RoleKind.CustomerDashboard) { } }
public sealed class TerraBaseMemberRole : AdmittedRole { public TerraBaseMemberRole() : base(RoleKind.TerraBaseMember) { } }
public sealed class OrchestratorRole : AdmittedRole { public OrchestratorRole() : base(RoleKind.Orchestrator) { } }
public sealed class ControlNatsServerRole : AdmittedRole { public ControlNatsServerRole() : base(RoleKind.ControlNatsServer) { } }
public sealed class ProductNatsServerRole : AdmittedRole { public ProductNatsServerRole() : base(RoleKind.ProductNatsServer) { } }
public sealed class GrafanaRole : AdmittedRole { public GrafanaRole() : base(RoleKind.Grafana) { } }
public sealed class LokiRole : AdmittedRole { public LokiRole() : base(RoleKind.Loki) { } }
public sealed class TempoRole : AdmittedRole { public TempoRole() : base(RoleKind.Tempo) { } }
public sealed class AlertmanagerRole : AdmittedRole { public AlertmanagerRole() : base(RoleKind.Alertmanager) { } }
public sealed class OtlpIngestRole : AdmittedRole { public OtlpIngestRole() : base(RoleKind.OtlpIngest) { } }
public sealed class SyntheticCheckRole : AdmittedRole { public SyntheticCheckRole() : base(RoleKind.SyntheticCheck) { } }
public sealed class RoutePolicyControllerRole : AdmittedRole { public RoutePolicyControllerRole() : base(RoleKind.RoutePolicyController) { } }
public sealed class CiRunnerRole : AdmittedRole { public CiRunnerRole() : base(RoleKind.CiRunner) { } }

public sealed class MetricsStoreRole : AdmittedRole
{
    public MetricsStoreRole(ApprovedImplementationCatalogKey implementation) : base(RoleKind.MetricsStore)
    {
        Implementation = RequireDomain(implementation, ImplementationDomain.MetricsStore);
    }

    public ApprovedImplementationCatalogKey Implementation { get; }

    internal override string Projection => $"{Kind}:{Implementation.CatalogEntryId}";

    private static ApprovedImplementationCatalogKey RequireDomain(
        ApprovedImplementationCatalogKey implementation,
        ImplementationDomain expected)
    {
        ArgumentNullException.ThrowIfNull(implementation);
        return implementation.Domain == expected
            ? implementation
            : throw new ArgumentException($"Implementation must belong to {expected}.", nameof(implementation));
    }
}

public sealed class RegionalTelemetryAgentRole : AdmittedRole
{
    public RegionalTelemetryAgentRole(ApprovedImplementationCatalogKey implementation) : base(RoleKind.RegionalTelemetryAgent)
    {
        ArgumentNullException.ThrowIfNull(implementation);
        Implementation = implementation.Domain == ImplementationDomain.RegionalTelemetry
            ? implementation
            : throw new ArgumentException("A regional telemetry implementation is required.", nameof(implementation));
    }

    public ApprovedImplementationCatalogKey Implementation { get; }

    internal override string Projection => $"{Kind}:{Implementation.CatalogEntryId}";
}

public sealed class VpnCoordinationRelayRole : AdmittedRole
{
    public VpnCoordinationRelayRole(ApprovedImplementationCatalogKey implementation) : base(RoleKind.VpnCoordinationRelay)
    {
        ArgumentNullException.ThrowIfNull(implementation);
        Implementation = implementation.Domain == ImplementationDomain.Vpn
            ? implementation
            : throw new ArgumentException("A VPN implementation is required.", nameof(implementation));
    }

    public ApprovedImplementationCatalogKey Implementation { get; }

    internal override string Projection => $"{Kind}:{Implementation.CatalogEntryId}";
}
