using TerraScale.Orchestrator;
using TerraScale.Orchestrator.Development;

namespace TerraScale.Orchestrator.Tests;

public sealed class WorkspaceTopologyLeaseAdmissionTests
{
    [Test]
    public async Task OnlyProductUpProfilesRequireTheWorkspaceTopologyLease()
    {
        await Assert.That(DevelopmentLab.RequiresWorkspaceTopologyLease(
            OrchestratorLabCommand.Up, DevelopmentTopology.CreateQuick())).IsTrue();
        await Assert.That(DevelopmentLab.RequiresWorkspaceTopologyLease(
            OrchestratorLabCommand.Up, DevelopmentTopology.CreateRegional())).IsTrue();
        await Assert.That(DevelopmentLab.RequiresWorkspaceTopologyLease(
            OrchestratorLabCommand.Up, DevelopmentTopology.CreateControl())).IsFalse();
        await Assert.That(DevelopmentLab.RequiresWorkspaceTopologyLease(
            OrchestratorLabCommand.Plan, DevelopmentTopology.CreateQuick())).IsFalse();
        await Assert.That(DevelopmentLab.RequiresWorkspaceTopologyLease(
            OrchestratorLabCommand.Status, DevelopmentTopology.CreateRegional())).IsFalse();
    }
}
