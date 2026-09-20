using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Tests;

public sealed class AdmittedRoleCatalogTests
{
    // TODO(rehome-agent): EveryProductionShapedDevelopmentResourceProjectsToTheClosedCatalog was
    // removed with the production Development/ lab fixtures; rehome a role-projection completeness
    // check onto a test-owned topology fixture.

    [Test]
    public async Task CatalogIsClosedCompleteAndUsesProductionRuntimeDefaults()
    {
        await Assert.That(AdmittedRoleCatalog.All.Count).IsEqualTo(Enum.GetValues<AdmittedRole>().Length);
        await Assert.That(AdmittedRoleCatalog.All.Select(descriptor => descriptor.Role).Distinct().Count())
            .IsEqualTo(AdmittedRoleCatalog.All.Count);
        await Assert.That(AdmittedRoleCatalog.Get(AdmittedRole.TerraBaseMember).DefaultDriver)
            .IsEqualTo(RuntimeDriver.NativeSystemd);
        await Assert.That(AdmittedRoleCatalog.Get(AdmittedRole.CustomerDashboard).DefaultDriver)
            .IsEqualTo(RuntimeDriver.OciContainer);
        await Assert.That(AdmittedRoleCatalog.Get(AdmittedRole.Authentication).ArtifactKey)
            .IsEqualTo("ts-auth");
        await Assert.That(AdmittedRoleCatalog.Get(AdmittedRole.Authentication).DefaultDriver)
            .IsEqualTo(RuntimeDriver.OciContainer);
        await Assert.That(AdmittedRoleCatalog.Get(AdmittedRole.Authentication).MinimumReplicas).IsEqualTo(1);
        await Assert.That(AdmittedRoleCatalog.Get(AdmittedRole.TerraBaseMember).MinimumReplicas).IsEqualTo(3);
        await Assert.That(HostRuntimeCli.ParseRole("authentication"))
            .IsEqualTo(AdmittedRole.Authentication);
        await Assert.That(AdmittedRoleCatalog.Get(AdmittedRole.Grafana).DefaultDriver)
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
        await Assert.That(() => AdmittedRoleCatalog.Admit(AdmittedRole.Grafana, RuntimeDriver.NativeSystemd))
            .Throws<InvalidOperationException>();
        await Assert.That(() => AdmittedRoleCatalog.Admit(AdmittedRole.Orchestrator, RuntimeDriver.OciContainer))
            .Throws<InvalidOperationException>();
        await Assert.That(AdmittedRoleCatalog.Admit(AdmittedRole.TerraBaseMember, RuntimeDriver.OciContainer).Role)
            .IsEqualTo(AdmittedRole.TerraBaseMember);
    }
}
