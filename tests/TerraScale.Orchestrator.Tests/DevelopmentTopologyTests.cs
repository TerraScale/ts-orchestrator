using TerraScale.Orchestrator.Development;

namespace TerraScale.Orchestrator.Tests;

public sealed class DevelopmentTopologyTests
{
    [Test]
    public async Task ControlPlaneProfileKeepsThreeRegionsAndStartsOnlySixResources()
    {
        var topology = DevelopmentTopology.CreateThreeCellControlPlane();

        await Assert.That(topology.Profile)
            .IsEqualTo("dev-containers-control-three-cell-lean");
        await Assert.That(topology.Cells.Select(cell => cell.Cell))
            .IsEquivalentTo(["gru", "sfo", "fra"]);
        await Assert.That(topology.GlobalResources).IsEmpty();
        foreach (var cell in topology.Cells)
        {
            await Assert.That(cell.Resources.Select(resource => resource.Kind)).IsEquivalentTo([
                DevelopmentResourceKind.ControlNats,
                DevelopmentResourceKind.ControllerAgent
            ]);
        }
        await Assert.That(topology.Cells.Sum(cell => cell.Resources.Count)).IsEqualTo(6);
        await Assert.That(DevelopmentContainerImages.RequiredBy(topology)).IsEquivalentTo([
            DevelopmentContainerImages.Nats,
            DevelopmentContainerImages.RuntimeDependencies
        ]);
    }

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
    public async Task EmulatorEnvironmentKeepsTheAssignedPort()
    {
        var emulator = DevelopmentTopology.CreateThreeCellLean().GlobalResources
            .Single(resource => resource.Kind == DevelopmentResourceKind.EmailEmulator);

        var environment = DevelopmentWorkloadRuntime.CreateEmulatorEnvironment(emulator);

        await Assert.That(environment["PORT"]).IsEqualTo(emulator.Port.ToString());
    }

    [Test]
    public async Task SingleNatsMemberHasNoSelfRoute()
    {
        var member = DevelopmentTopology.CreateThreeCellLean().Cells
            .Single(cell => cell.Cell == "fra")
            .OfKind(DevelopmentResourceKind.ControlNats).Single();

        await Assert.That(NatsDevelopmentCluster.CreateRoutes([member], member)).IsEmpty();
        await Assert.That(NatsDevelopmentCluster.ClusterConfiguration(
            [member],
            member,
            "orchestrator-fra",
            new("route.pem", "route.key.pem", "ca.pem", "spiffe://route"))).IsEmpty();
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
        await Assert.That(DevelopmentProcessSupervisor.PlannedMemoryLimitBytes(
            DevelopmentTopology.CreateThreeCellLean()))
            .IsEqualTo(13_248L * 1024 * 1024);
        await Assert.That(DevelopmentProcessSupervisor.PlannedMemoryLimitBytes(
            DevelopmentTopology.CreateThreeCellControlPlane()))
            .IsEqualTo(1_728L * 1024 * 1024);
        await Assert.That(DevelopmentProcessSupervisor.OwnershipLabel)
            .IsEqualTo("io.terrascale.owner=devhost-orchestrator");
    }

    [Test]
    public async Task OverBudgetTopologyFailsBeforeRuntimeStartup()
    {
        var resources = Enumerable.Range(1, 10)
            .Select(replica => new DevelopmentResourcePlan(
                $"gru-terrabase-{replica}",
                "gru",
                DevelopmentResourceKind.TerraBase,
                replica,
                20_000 + replica))
            .ToArray();
        var topology = new DevelopmentTopology(
            "over-budget",
            [new DevelopmentCellPlan("gru", 0, resources)],
            []);

        await Assert.That(() => DevelopmentProcessSupervisor.RequireResourceBudget(topology))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task CleanupOnlyTargetsExactlyOwnedPod()
    {
        await Assert.That(DevelopmentProcessSupervisor.IsOwnedPod("devhost-orchestrator\n")).IsTrue();
        await Assert.That(DevelopmentProcessSupervisor.IsOwnedPod("foreign-owner")).IsFalse();
        await Assert.That(DevelopmentProcessSupervisor.OwnedPodRemovalArguments("lab", 10))
            .IsEquivalentTo(["pod", "rm", "--force", "--time", "10", "lab"]);
    }

    [Test]
    public async Task ProductArtifactBuildUsesOneMsBuildNode()
    {
        await Assert.That(DevelopmentArtifactBuilder.DotNetBuildArguments("product.csproj"))
            .IsEquivalentTo([
                "build", "product.csproj", "--configuration", "Release", "--no-restore", "--nologo",
                "--no-incremental", "--maxcpucount:1", "--nodeReuse:false"
            ]);
    }

    [Test]
    public async Task PodCreationUsesOneNameAndPinnedInfraWithoutHostHelpers()
    {
        var arguments = DevelopmentProcessSupervisor.PodCreationArguments(
            DevelopmentTopology.CreateThreeCellControlPlane(),
            "control-lab");

        await Assert.That(arguments.Count(argument => argument == "control-lab")).IsEqualTo(1);
        await Assert.That(arguments).Contains("--infra-image");
        await Assert.That(arguments).Contains(DevelopmentContainerImages.RuntimeDependencies);
        await Assert.That(arguments).Contains("--infra-command");
        await Assert.That(arguments).Contains("sleep infinity");
        await Assert.That(arguments).Contains("pasta:--host-lo-to-ns-lo");
    }

    [Test]
    public async Task TerraBaseRuntimeUsesAPrivateWritableOverlay()
    {
        var topology = DevelopmentTopology.CreateThreeCellLean();

        await Assert.That(DevelopmentProcessSupervisor.WritableRuntimeOverlay(
            topology,
            "gru-terrabase-1",
            "/workspace"))
            .IsEqualTo(
                "/workspace/TerraBase/src/TerraBase.Server/bin/Release/net10.0:" +
                "/workspace/TerraBase/src/TerraBase.Server/bin/Release/net10.0:O");
        await Assert.That(DevelopmentProcessSupervisor.WritableRuntimeOverlay(
            topology,
            "gru-api",
            "/workspace"))
            .IsNull();
    }
}
