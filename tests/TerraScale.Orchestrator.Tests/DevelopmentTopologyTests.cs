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

    [Test]
    public async Task ControllerMessagingProbesAreIsolatedByStableInstance()
    {
        var first = new Messaging.NatsTopology("gru", 3, "1");
        var second = new Messaging.NatsTopology("gru", 3, "2");

        await Assert.That(first.StartupSubject).IsNotEqualTo(second.StartupSubject);
        await Assert.That(first.StartupConsumer.Name).IsNotEqualTo(second.StartupConsumer.Name);
        await Assert.That(first.ServiceName).IsNotEqualTo(second.ServiceName);
    }

    [Test]
    public async Task RegionalServicesUseTheProductionDatabaseTopologyFloor()
    {
        var topology = DevelopmentTopology.CreateThreeCellR3();
        var cell = topology.Cells.Single(candidate => candidate.Cell == "gru");
        var authentication = cell.OfKind(DevelopmentResourceKind.Authentication).Single();

        var environment = DevelopmentWorkloadRuntime.CreateServiceEnvironment(
            topology,
            cell,
            authentication,
            isApi: false,
            "/tmp/terrascale-orchestrator-tests");

        await Assert.That(environment["TerraScale__ServiceDatabases__AllowReducedDevelopmentTopology"])
            .IsEqualTo("false");
        await Assert.That(environment["TerraScale__ServiceDatabases__ShardCount"]).IsEqualTo("3");
        await Assert.That(environment["TerraScale__ServiceDatabases__ReplicationFactor"]).IsEqualTo("3");
        await Assert.That(environment["TerraScale__ServiceDatabases__DynamicNodesDistribution"]).IsEqualTo("true");
        await Assert.That(environment.Keys.Count(key => key.StartsWith(
                "TerraBase__Urls__",
                StringComparison.Ordinal)))
            .IsEqualTo(3);
    }

    [Test]
    public async Task DashboardUsesItsRegionalPortInsteadOfVinextDefault()
    {
        var topology = DevelopmentTopology.CreateThreeCellR3();
        var cell = topology.Cells.Single(candidate => candidate.Cell == "gru");
        var dashboard = cell.OfKind(DevelopmentResourceKind.Dashboard).Single();

        var arguments = DevelopmentWorkloadRuntime.CreateDashboardArguments(dashboard, watch: true);
        var environment = DevelopmentWorkloadRuntime.CreateDashboardEnvironment(
            topology,
            cell.OfKind(DevelopmentResourceKind.Api).Single(),
            cell.OfKind(DevelopmentResourceKind.Authentication).Single(),
            dashboard,
            watch: true);

        await Assert.That(arguments).IsEquivalentTo([
            "run",
            "vinext:dev",
            "--hostname",
            "127.0.0.1",
            "--port",
            dashboard.Port.ToString(System.Globalization.CultureInfo.InvariantCulture)
        ]);
        await Assert.That(environment["VINEXT_NO_DEV_LOCK"]).IsEqualTo("1");
        await Assert.That(environment["TERRASCALE_DASHBOARD_PUBLIC_URL"])
            .IsEqualTo($"http://127.0.0.1:{dashboard.Port}");
    }
}
