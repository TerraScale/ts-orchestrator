using TerraScale.Orchestrator.Development;

namespace TerraScale.Orchestrator.Tests;

public sealed class DevelopmentTopologyTests
{
    [Test]
    public async Task ThreeCellProfileHasProductionReplicaCountsAndUniquePorts()
    {
        var topology = DevelopmentTopology.CreateThreeCellR3();

        await Assert.That(topology.Cells.Select(cell => cell.Cell)).IsEquivalentTo(["gru", "sfo", "fra"]);
        foreach (var cell in topology.Cells)
        {
            await Assert.That(cell.OfKind(DevelopmentResourceKind.ControllerAgent).Count).IsEqualTo(3);
            await Assert.That(cell.OfKind(DevelopmentResourceKind.ControlNats).Count).IsEqualTo(3);
            await Assert.That(cell.OfKind(DevelopmentResourceKind.ProductNats).Count).IsEqualTo(3);
            await Assert.That(cell.OfKind(DevelopmentResourceKind.TerraBase).Count).IsEqualTo(3);
            await Assert.That(cell.OfKind(DevelopmentResourceKind.Api).Count).IsEqualTo(1);
            await Assert.That(cell.OfKind(DevelopmentResourceKind.Authentication).Count).IsEqualTo(1);
            await Assert.That(cell.OfKind(DevelopmentResourceKind.Dashboard).Count).IsEqualTo(1);
        }

        var resources = topology.Cells.SelectMany(cell => cell.Resources)
            .Concat(topology.GlobalResources)
            .ToArray();
        var ports = resources.Select(resource => resource.Port)
            .Concat(resources.Where(resource => resource.ClusterPort is not null)
                .Select(resource => resource.ClusterPort!.Value))
            .Concat(resources.Where(resource => resource.SecondaryPort is not null)
                .Select(resource => resource.SecondaryPort!.Value))
            .ToArray();
        await Assert.That(ports.Distinct().Count()).IsEqualTo(ports.Length);
        await Assert.That(resources.Select(resource => resource.Name).Distinct().Count()).IsEqualTo(resources.Length);
    }

    [Test]
    public async Task BuiltInProfileCannotResolveAnUnknownCellOrReplica()
    {
        var topology = DevelopmentTopology.CreateThreeCellR3();

        await Assert.That(() => topology.GetRequired("unknown", DevelopmentResourceKind.Api))
            .Throws<InvalidOperationException>();
        await Assert.That(() => topology.GetRequired("gru", DevelopmentResourceKind.Api, replica: 2))
            .Throws<InvalidOperationException>();
    }
}
