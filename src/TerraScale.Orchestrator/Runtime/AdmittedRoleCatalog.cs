using System.Collections.Frozen;

namespace TerraScale.Orchestrator.Runtime;

public enum AdmittedRole
{
    CustomerDashboard,
    TerraBaseMember,
    Orchestrator,
    ControlNatsServer,
    ProductNatsServer,
    Grafana,
    MetricsStore,
    Loki,
    Tempo,
    Alertmanager,
    OtlpIngest,
    SyntheticCheck,
    RegionalTelemetryAgent,
    VpnCoordinationRelay,
    RoutePolicyController,
    CiRunner,
    JournalWriter,
    Authentication
}

public enum RuntimeDriver
{
    NativeSystemd,
    OciContainer
}

public enum RoleCapability
{
    PublicHttp,
    ProductDatabase,
    ControlAuthority,
    ControlMessaging,
    ProductMessaging,
    TelemetryQuery,
    TelemetryIngest,
    Alerting,
    SyntheticProbe,
    NetworkCoordination,
    RoutePolicy,
    IsolatedBuild,
    Authentication
}

public sealed record AdmittedRoleDescriptor(
    AdmittedRole Role,
    string ArtifactKey,
    RuntimeDriver DefaultDriver,
    IReadOnlyList<RuntimeDriver> AllowedDrivers,
    IReadOnlyList<RoleCapability> Capabilities,
    bool OnePerHost,
    int MinimumReplicas);

public static class AdmittedRoleCatalog
{
    private static readonly FrozenDictionary<AdmittedRole, AdmittedRoleDescriptor> Descriptors =
        CreateDescriptors().ToFrozenDictionary(descriptor => descriptor.Role);

    public static IReadOnlyList<AdmittedRoleDescriptor> All { get; } = Descriptors.Values
        .OrderBy(descriptor => descriptor.Role)
        .ToArray();

    public static AdmittedRoleDescriptor Get(AdmittedRole role) =>
        Descriptors.TryGetValue(role, out var descriptor)
            ? descriptor
            : throw new ArgumentOutOfRangeException(nameof(role), "The workload role is not admitted.");

    public static AdmittedRoleDescriptor Admit(AdmittedRole role, RuntimeDriver driver)
    {
        var descriptor = Get(role);
        if (!descriptor.AllowedDrivers.Contains(driver))
        {
            throw new InvalidOperationException($"{role} is not admitted on the {driver} runtime.");
        }
        return descriptor;
    }

    private static IEnumerable<AdmittedRoleDescriptor> CreateDescriptors()
    {
        // ts-auth is an OCI workload. Its secret profile and dependency contract
        // are supplied by the deployment handoff; the closed role catalog only
        // admits the runtime and public HTTP capability.
        yield return Oci(AdmittedRole.Authentication, "ts-auth", RoleCapability.PublicHttp, RoleCapability.Authentication);
        yield return Oci(AdmittedRole.CustomerDashboard, "terrascale-dashboard", RoleCapability.PublicHttp);
        yield return Both(
            AdmittedRole.TerraBaseMember,
            "terrabase-server",
            RuntimeDriver.NativeSystemd,
            onePerHost: true,
            minimumReplicas: 3,
            RoleCapability.ProductDatabase);
        yield return Native(
            AdmittedRole.Orchestrator,
            "terrascale-orchestrator",
            onePerHost: true,
            minimumReplicas: 3,
            RoleCapability.ControlAuthority);
        yield return Native(
            AdmittedRole.ControlNatsServer,
            "nats-server-control",
            onePerHost: true,
            minimumReplicas: 3,
            RoleCapability.ControlMessaging);
        yield return Native(
            AdmittedRole.ProductNatsServer,
            "nats-server-product",
            onePerHost: true,
            minimumReplicas: 3,
            RoleCapability.ProductMessaging);
        yield return Oci(AdmittedRole.Grafana, "grafana", RoleCapability.TelemetryQuery);
        yield return Oci(AdmittedRole.MetricsStore, "victoriametrics", RoleCapability.TelemetryQuery);
        yield return Oci(AdmittedRole.Loki, "loki", RoleCapability.TelemetryQuery);
        yield return Oci(AdmittedRole.Tempo, "tempo", RoleCapability.TelemetryQuery);
        yield return Oci(AdmittedRole.Alertmanager, "alertmanager", RoleCapability.Alerting);
        yield return Oci(AdmittedRole.OtlpIngest, "alloy-gru", RoleCapability.TelemetryIngest);
        yield return Oci(AdmittedRole.SyntheticCheck, "terrascale-synthetic-check", RoleCapability.SyntheticProbe);
        yield return Oci(AdmittedRole.RegionalTelemetryAgent, "alloy-regional", RoleCapability.TelemetryIngest);
        yield return Oci(AdmittedRole.VpnCoordinationRelay, "netbird-relay", RoleCapability.NetworkCoordination);
        yield return Native(AdmittedRole.RoutePolicyController, "terrascale-route-policy", false, 1, RoleCapability.RoutePolicy);
        yield return Oci(AdmittedRole.CiRunner, "terrascale-ci-runner", RoleCapability.IsolatedBuild);
        yield return Native(AdmittedRole.JournalWriter, "terrascale-orchestrator", true, 3, RoleCapability.ControlMessaging);
    }

    private static AdmittedRoleDescriptor Native(
        AdmittedRole role,
        string artifactKey,
        bool onePerHost,
        int minimumReplicas,
        params RoleCapability[] capabilities) =>
        new(
            role,
            artifactKey,
            RuntimeDriver.NativeSystemd,
            ReadOnly(RuntimeDriver.NativeSystemd),
            ReadOnly(capabilities),
            onePerHost,
            minimumReplicas);

    private static AdmittedRoleDescriptor Oci(
        AdmittedRole role,
        string artifactKey,
        params RoleCapability[] capabilities) =>
        new(
            role,
            artifactKey,
            RuntimeDriver.OciContainer,
            ReadOnly(RuntimeDriver.OciContainer),
            ReadOnly(capabilities),
            false,
            1);

    private static AdmittedRoleDescriptor Both(
        AdmittedRole role,
        string artifactKey,
        RuntimeDriver defaultDriver,
        bool onePerHost,
        int minimumReplicas,
        params RoleCapability[] capabilities) =>
        new(
            role,
            artifactKey,
            defaultDriver,
            ReadOnly(RuntimeDriver.NativeSystemd, RuntimeDriver.OciContainer),
            ReadOnly(capabilities),
            onePerHost,
            minimumReplicas);

    private static IReadOnlyList<T> ReadOnly<T>(params T[] values) =>
        Array.AsReadOnly(values);
}
