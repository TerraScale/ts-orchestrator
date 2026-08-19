using TerraScale.Orchestrator;
using TerraScale.Orchestrator.Development;

namespace TerraScale.Orchestrator.Tests;

public sealed class WorkspaceTopologyLeaseAdmissionTests
{
    [Test]
    public async Task OnlyTheThreeRegionLabUpRequiresTheWorkspaceTopologyLease()
    {
        await Assert.That(DevelopmentLab.RequiresWorkspaceTopologyLease(
            OrchestratorLabCommand.Up, DevelopmentTopology.CreateRegional())).IsTrue();
        await Assert.That(DevelopmentLab.RequiresWorkspaceTopologyLease(
            OrchestratorLabCommand.Plan, DevelopmentTopology.CreateRegional())).IsFalse();
        await Assert.That(DevelopmentLab.RequiresWorkspaceTopologyLease(
            OrchestratorLabCommand.Status, DevelopmentTopology.CreateRegional())).IsFalse();
    }
}
