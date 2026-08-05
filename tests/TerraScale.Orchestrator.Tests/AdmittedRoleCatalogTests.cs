using TerraScale.Orchestrator.Development;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Tests;

public sealed class AdmittedRoleCatalogTests
{
    [Test]
    public async Task CatalogIsClosedCompleteAndUsesProductionRuntimeDefaults()
    {
        await Assert.That(AdmittedRoleCatalog.All.Count).IsEqualTo(Enum.GetValues<AdmittedRole>().Length);
        await Assert.That(AdmittedRoleCatalog.All.Select(descriptor => descriptor.Role).Distinct().Count())
            .IsEqualTo(AdmittedRoleCatalog.All.Count);
        await Assert.That(AdmittedRoleCatalog.Get(AdmittedRole.TerraBaseMember).DefaultDriver)
            .IsEqualTo(RuntimeDriver.NativeSystemd);
        await Assert.That(AdmittedRoleCatalog.Get(AdmittedRole.Platform).DefaultDriver)
            .IsEqualTo(RuntimeDriver.OciContainer);
        await Assert.That(AdmittedRoleCatalog.Get(AdmittedRole.Authentication).DefaultDriver)
            .IsEqualTo(RuntimeDriver.OciContainer);
        await Assert.That(AdmittedRoleCatalog.Get(AdmittedRole.CustomerDashboard).DefaultDriver)
            .IsEqualTo(RuntimeDriver.OciContainer);
        await Assert.That(AdmittedRoleCatalog.Get(AdmittedRole.ControlNatsServer).MinimumReplicas).IsEqualTo(3);
        await Assert.That(AdmittedRoleCatalog.Get(AdmittedRole.ProductNatsServer).MinimumReplicas).IsEqualTo(3);
        await Assert.That(AdmittedRoleCatalog.Get(AdmittedRole.JournalWriter).DefaultDriver)
            .IsEqualTo(RuntimeDriver.NativeSystemd);
        await Assert.That(AdmittedRoleCatalog.Get(AdmittedRole.JournalWriter).OnePerHost).IsTrue();
    }

    [Test]
    public async Task DriverAdmissionRejectsAnUnapprovedRuntime()
    {
        await Assert.That(() => AdmittedRoleCatalog.Admit(AdmittedRole.Platform, RuntimeDriver.NativeSystemd))
            .Throws<InvalidOperationException>();
        await Assert.That(() => AdmittedRoleCatalog.Admit(AdmittedRole.Orchestrator, RuntimeDriver.OciContainer))
            .Throws<InvalidOperationException>();
        await Assert.That(AdmittedRoleCatalog.Admit(AdmittedRole.TerraBaseMember, RuntimeDriver.OciContainer).Role)
            .IsEqualTo(AdmittedRole.TerraBaseMember);
    }

    [Test]
    public async Task EveryProductionShapedDevelopmentResourceProjectsToTheClosedCatalog()
    {
        var resources = DevelopmentTopology.CreateRegional().Cells.SelectMany(cell => cell.Resources).ToArray();

        await Assert.That(resources.All(resource => DevelopmentRoleProjection.Get(resource.Kind) is not null)).IsTrue();
        foreach (var resource in resources)
        {
            var descriptor = DevelopmentRoleProjection.Get(resource.Kind)!;
            await Assert.That(AdmittedRoleCatalog.Get(descriptor.Role)).IsEqualTo(descriptor);
        }

        await Assert.That(DevelopmentRoleProjection.Get(DevelopmentResourceKind.EmailEmulator)).IsNull();
    }
}
