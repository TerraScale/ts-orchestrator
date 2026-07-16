using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Development;

internal static class DevelopmentRoleProjection
{
    public static AdmittedRoleDescriptor? Get(DevelopmentResourceKind kind) => kind switch
    {
        DevelopmentResourceKind.ControllerAgent => AdmittedRoleCatalog.Get(AdmittedRole.Orchestrator),
        DevelopmentResourceKind.ControlNats => AdmittedRoleCatalog.Get(AdmittedRole.ControlNatsServer),
        DevelopmentResourceKind.ProductNats => AdmittedRoleCatalog.Get(AdmittedRole.ProductNatsServer),
        DevelopmentResourceKind.TerraBase => AdmittedRoleCatalog.Get(AdmittedRole.TerraBaseMember),
        DevelopmentResourceKind.Authentication => AdmittedRoleCatalog.Get(AdmittedRole.Authentication),
        DevelopmentResourceKind.Api => AdmittedRoleCatalog.Get(AdmittedRole.Api),
        DevelopmentResourceKind.Dashboard => AdmittedRoleCatalog.Get(AdmittedRole.CustomerDashboard),
        DevelopmentResourceKind.EmailEmulator or DevelopmentResourceKind.StripeEmulator => null,
        _ => throw new ArgumentOutOfRangeException(nameof(kind))
    };
}
