using TerraScale.Orchestrator.Development;

namespace TerraScale.Orchestrator.Tests;

public sealed class DevelopmentTopologyTests
{
    [Test]
    public async Task ThreeCellContainerProfileHasOneReplicaPerRoleAndUniquePorts()
    {
        var topology = DevelopmentTopology.CreateThreeCellLean();

        await Assert.That(topology.Profile).IsEqualTo("dev-containers-three-cell-lean");
        await Assert.That(topology.Cells.Select(cell => cell.Cell)).IsEquivalentTo(["gru", "sfo", "fra"]);
        foreach (var cell in topology.Cells)
        {
            foreach (var kind in new[]
            {
                DevelopmentResourceKind.ControllerAgent,
                DevelopmentResourceKind.ControlNats,
                DevelopmentResourceKind.ProductNats,
                DevelopmentResourceKind.TerraBase,
                DevelopmentResourceKind.Api,
                DevelopmentResourceKind.Authentication,
                DevelopmentResourceKind.Dashboard
            })
            {
                await Assert.That(cell.OfKind(kind).Count).IsEqualTo(1);
            }
        }

        var resources = topology.Cells.SelectMany(cell => cell.Resources)
            .Concat(topology.GlobalResources)
            .ToArray();
        await Assert.That(resources.Length).IsEqualTo(23);
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
    public async Task RegionalServicesUseReducedDatabaseAndQueueReplication()
    {
        var topology = DevelopmentTopology.CreateThreeCellLean();
        var cell = topology.Cells.Single(candidate => candidate.Cell == "gru");
        var api = cell.OfKind(DevelopmentResourceKind.Api).Single();

        var environment = DevelopmentWorkloadRuntime.CreateServiceEnvironment(
            topology,
            cell,
            api,
            isApi: true,
            "/tmp/terrascale-orchestrator-tests");

        await Assert.That(environment["TerraScale__ServiceDatabases__AllowReducedDevelopmentTopology"])
            .IsEqualTo("true");
        await Assert.That(environment["TerraScale__ServiceDatabases__ShardCount"]).IsEqualTo("1");
        await Assert.That(environment["TerraScale__ServiceDatabases__ReplicationFactor"]).IsEqualTo("1");
        await Assert.That(environment["TerraScale__Queue__StreamReplicas"]).IsEqualTo("1");
        await Assert.That(environment["TerraScale__Queue__ConsumerReplicas"]).IsEqualTo("1");
        await Assert.That(environment.Keys.Count(key => key.StartsWith("TerraBase__Urls__", StringComparison.Ordinal)))
            .IsEqualTo(1);
    }

    [Test]
    public async Task DashboardRunsPublishedBuildOnAllInterfacesInsideThePod()
    {
        var dashboard = DevelopmentTopology.CreateThreeCellLean()
            .Cells.Single(cell => cell.Cell == "gru")
            .OfKind(DevelopmentResourceKind.Dashboard).Single();

        await Assert.That(DevelopmentWorkloadRuntime.CreateDashboardArguments(dashboard)).IsEquivalentTo([
            "run", "vinext:start", "--hostname", "0.0.0.0", "--port", dashboard.Port.ToString()
        ]);
    }

    [Test]
    public async Task SingleNatsMemberHasNoSelfRoute()
    {
        var member = DevelopmentTopology.CreateThreeCellLean().Cells
            .Single(cell => cell.Cell == "fra")
            .OfKind(DevelopmentResourceKind.ControlNats).Single();

        await Assert.That(NatsDevelopmentCluster.CreateRoutes([member], member)).IsEmpty();
    }

    [Test]
    public async Task ContainerImagesAndPodBudgetAreClosed()
    {
        await Assert.That(DevelopmentContainerImages.All).IsEquivalentTo([
            DevelopmentContainerImages.AspNet,
            DevelopmentContainerImages.RuntimeDependencies,
            DevelopmentContainerImages.Node,
            DevelopmentContainerImages.Nats
        ]);
        await Assert.That(DevelopmentProcessSupervisor.PodMemoryLimitBytes)
            .IsEqualTo(16L * 1024 * 1024 * 1024);
        await Assert.That(DevelopmentProcessSupervisor.OwnershipLabel)
            .IsEqualTo("io.terrascale.owner=devhost-orchestrator");
    }
}
