using TerraScale.Orchestrator.Development;

namespace TerraScale.Orchestrator.Tests;

public sealed class DevelopmentTopologyTests
{
    [Test]
    public async Task QuickProfileRunsOneGruCopyOfEveryProductResource()
    {
        var topology = DevelopmentTopology.CreateQuick();

        await Assert.That(topology.Profile).IsEqualTo("quick");
        await Assert.That(topology.Cells.Select(cell => cell.Cell)).IsEquivalentTo(["gru"]);
        await Assert.That(topology.Cells.Single().Resources.Select(resource => resource.Kind))
            .IsEquivalentTo([
                DevelopmentResourceKind.ControlNats,
                DevelopmentResourceKind.ProductNats,
                DevelopmentResourceKind.ControllerAgent,
                DevelopmentResourceKind.TerraBase,
                DevelopmentResourceKind.Authentication,
                DevelopmentResourceKind.Platform,
                DevelopmentResourceKind.Dashboard
            ]);
        await Assert.That(topology.GlobalResources.Select(resource => resource.Kind))
            .IsEquivalentTo([
                DevelopmentResourceKind.EmailEmulator
            ]);
    }

    [Test]
    public async Task ControllerHealthProbeUsesCanonicalControllerInstance()
    {
        await Assert.That(DevelopmentHealthProbe.ControllerInstanceHealthSubject("gru", 1))
            .IsEqualTo("ts.orch.v1.gru.query.health.controller-1");
    }

    [Test]
    public async Task ControlPlaneProfileKeepsThreeRegionsAndStartsOnlySixResources()
    {
        var topology = DevelopmentTopology.CreateControl();

        await Assert.That(topology.Profile).IsEqualTo("control");
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
        var topology = DevelopmentTopology.CreateRegional();

        await Assert.That(topology.Profile).IsEqualTo("regional");
        await Assert.That(topology.Cells.Select(cell => cell.Cell)).IsEquivalentTo(["gru", "sfo", "fra"]);
        foreach (var cell in topology.Cells)
        {
            foreach (var kind in new[]
            {
                DevelopmentResourceKind.ControllerAgent,
                DevelopmentResourceKind.ControlNats,
                DevelopmentResourceKind.ProductNats,
                DevelopmentResourceKind.TerraBase,
                DevelopmentResourceKind.Platform,
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
        await Assert.That(resources.Length).IsEqualTo(22);
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
        var topology = DevelopmentTopology.CreateRegional();
        var cell = topology.Cells.Single(candidate => candidate.Cell == "gru");
        var platform = cell.OfKind(DevelopmentResourceKind.Platform).Single();
        var authentication = cell.OfKind(DevelopmentResourceKind.Authentication).Single();

        var environment = DevelopmentWorkloadRuntime.CreateServiceEnvironment(
            topology,
            cell,
            platform,
            isPlatform: true,
            "/tmp/terrascale-orchestrator-tests");
        var authenticationEnvironment = DevelopmentWorkloadRuntime.CreateServiceEnvironment(
            topology,
            cell,
            authentication,
            isPlatform: false,
            "/tmp/terrascale-orchestrator-tests");

        await Assert.That(environment["HOME"])
            .IsEqualTo("/tmp/terrascale-orchestrator-tests/workloads/gru-platform/home");
        await Assert.That(environment["DOTNET_CLI_HOME"]).IsEqualTo(environment["HOME"]);
        await Assert.That(environment["Logging__LogLevel__Microsoft.Extensions.Diagnostics.HealthChecks.DefaultHealthCheckService"])
            .IsEqualTo("Critical");
        await Assert.That(authenticationEnvironment["HOME"])
            .IsEqualTo("/tmp/terrascale-orchestrator-tests/workloads/gru-authentication/home");
        await Assert.That(environment["TerraScale__ServiceDatabases__AllowReducedDevelopmentTopology"])
            .IsEqualTo("true");
        await Assert.That(environment["TerraScale__ServiceDatabases__ShardCount"]).IsEqualTo("1");
        await Assert.That(environment["TerraScale__ServiceDatabases__ReplicationFactor"]).IsEqualTo("1");
        await Assert.That(environment["TerraScale__Queue__StreamReplicas"]).IsEqualTo("1");
        await Assert.That(environment["TerraScale__Queue__ConsumerReplicas"]).IsEqualTo("1");
        await Assert.That(environment["TerraScale__Billing__OperationMetering__PublishTimeout"])
            .IsEqualTo("00:00:02");
        await Assert.That(environment["Payments__Provider"]).IsEqualTo("polar");
        await Assert.That(environment["Payments__polar__Enabled"]).IsEqualTo("true");
        await Assert.That(environment["Payments__Polar__AccessToken"]).IsEqualTo("devhost-local-access-token");
        await Assert.That(environment["Payments__Polar__WebhookSecret"]).IsEqualTo("devhost-local-webhook-secret");
        await Assert.That(environment.ContainsKey("Services__Dashboard__BaseUrl")).IsFalse();
        await Assert.That(environment.ContainsKey("DashboardAdmin__OwnerEmails__0")).IsFalse();
        await Assert.That(environment.ContainsKey("AuthenticationService__BaseUrl")).IsFalse();
        await Assert.That(environment.Keys.Count(key => key.StartsWith("TerraBase__Urls__", StringComparison.Ordinal)))
            .IsEqualTo(1);
        // Private MagicOnion listeners: auth SecondaryPort is AuthenticationEndpoint;
        // each platform SecondaryPort is RegionalEndpoints:{cell}.
        await Assert.That(authentication.SecondaryPort).IsEqualTo(18673);
        await Assert.That(platform.SecondaryPort).IsEqualTo(18674);
        await Assert.That(authenticationEnvironment["TerraScale__Kestrel__InternalRpcPort"]).IsEqualTo("18673");
        await Assert.That(environment["TerraScale__Kestrel__InternalRpcPort"]).IsEqualTo("18674");
        await Assert.That(environment["InternalRpc__AuthenticationEndpoint"]).IsEqualTo("http://127.0.0.1:18673");
        await Assert.That(environment["InternalRpc__LocalPublicEndpoint"]).IsEqualTo("http://127.0.0.1:18671");
        await Assert.That(environment["InternalRpc__RegionalEndpoints__gru"]).IsEqualTo("http://127.0.0.1:18674");
        await Assert.That(environment["InternalRpc__RegionalEndpoints__sfo"]).IsEqualTo("http://127.0.0.1:18874");
        await Assert.That(environment["InternalRpc__RegionalEndpoints__fra"]).IsEqualTo("http://127.0.0.1:19074");

        var stripeEnvironment = DevelopmentWorkloadRuntime.CreateServiceEnvironment(
            topology,
            cell,
            platform,
            isPlatform: true,
            "/tmp/terrascale-orchestrator-tests",
            paymentEnvironment: new Dictionary<string, string?>
            {
                ["Payments__Provider"] = "stripe",
                ["Payments__Stripe__SecretKey"] = "test-secret"
            });
        await Assert.That(stripeEnvironment["Payments__Provider"]).IsEqualTo("stripe");
        await Assert.That(stripeEnvironment["Payments__stripe__Enabled"]).IsEqualTo("true");
        await Assert.That(stripeEnvironment["Payments__Stripe__SecretKey"]).IsEqualTo("test-secret");
    }

    [Test]
    public async Task DashboardRunsPublishedBuildOnAllInterfacesInsideThePod()
    {
        var topology = DevelopmentTopology.CreateRegional();
        var cell = topology.Cells.Single(cell => cell.Cell == "gru");
        var dashboard = cell.OfKind(DevelopmentResourceKind.Dashboard).Single();
        var environment = DevelopmentWorkloadRuntime.CreateDashboardEnvironment(
            topology,
            cell.OfKind(DevelopmentResourceKind.Platform).Single(),
            cell.OfKind(DevelopmentResourceKind.Authentication).Single(),
            dashboard,
            "/runtime/product-ca.pem",
            "/runtime/gru-dashboard/vite-task-cache",
            getEnvironmentVariable: _ => null);

        await Assert.That(DevelopmentWorkloadRuntime.CreateDashboardArguments(dashboard))
            .IsEquivalentTo(["server.js"]);
        await Assert.That(environment["SSL_CERT_FILE"]).IsEqualTo("/runtime/product-ca.pem");
        await Assert.That(environment["VITE_CACHE_PATH"])
            .IsEqualTo("/runtime/gru-dashboard/vite-task-cache");
        await Assert.That(environment["TERRASCALE_DASHBOARD_PUBLIC_URL"])
            .IsEqualTo($"http://127.0.0.1:{dashboard.Port}");
        await Assert.That(environment["TERRASCALE_DEVELOPMENT_PAYMENT_BYPASS"]).IsEqualTo("true");
        await Assert.That(environment.ContainsKey("TERRASCALE_DASHBOARD_CLIENT_ID")).IsFalse();
        await Assert.That(environment.ContainsKey("TERRASCALE_DASHBOARD_PROJECT_ID")).IsFalse();
        await Assert.That(environment.ContainsKey("TERRASCALE_DASHBOARD_TENANT_ID")).IsFalse();
        await Assert.That(environment.ContainsKey("TERRASCALE_DASHBOARD_DATABASE_IDS")).IsFalse();
    }

    [Test]
    public async Task DashboardPublicUrlPrefersDevHostTailscaleMagicDns()
    {
        var topology = DevelopmentTopology.CreateRegional();
        var cell = topology.Cells.Single(candidate => candidate.Cell == "gru");
        var dashboard = cell.OfKind(DevelopmentResourceKind.Dashboard).Single();
        const string publicUrl = "https://terrascale-dev.tail057f.ts.net:18446";
        var environment = DevelopmentWorkloadRuntime.CreateDashboardEnvironment(
            topology,
            cell.OfKind(DevelopmentResourceKind.Platform).Single(),
            cell.OfKind(DevelopmentResourceKind.Authentication).Single(),
            dashboard,
            "/runtime/product-ca.pem",
            "/runtime/gru-dashboard/vite-task-cache",
            getEnvironmentVariable: name =>
                name == DevelopmentPublicSurfaces.PublicDashboardUrlEnvironmentVariable
                    ? publicUrl
                    : null);

        await Assert.That(environment["TERRASCALE_DASHBOARD_PUBLIC_URL"]).IsEqualTo(publicUrl);
        // Server-side API targets stay on loopback inside the lab pod.
        await Assert.That(environment["TERRASCALE_API_BASE_URL"]).StartsWith("http://127.0.0.1:");
        await Assert.That(environment["TERRASCALE_AUTH_API_BASE_URL"]).StartsWith("http://127.0.0.1:");
    }

    [Test]
    public async Task EmulatorEnvironmentKeepsTheAssignedPort()
    {
        var emulator = DevelopmentTopology.CreateRegional().GlobalResources
            .Single(resource => resource.Kind == DevelopmentResourceKind.EmailEmulator);

        var environment = DevelopmentWorkloadRuntime.CreateEmulatorEnvironment(emulator);

        await Assert.That(environment["PORT"]).IsEqualTo(emulator.Port.ToString());
    }

    [Test]
    public async Task SingleNatsMemberHasNoSelfRoute()
    {
        var member = DevelopmentTopology.CreateRegional().Cells
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
    public async Task ControllerUsesTlsForRegionalControlNats()
    {
        await Assert.That(DevelopmentLab.ControllerNatsUrl(18_600))
            .IsEqualTo("tls://127.0.0.1:18600");
    }

    [Test]
    public async Task DevelopmentJournalProvisioningUsesInfrastructureAuthorityBeforeControllerStartup()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = Path.Combine(Path.GetTempPath(), $"ts-orch-provision-options-{Guid.NewGuid():N}");
        try
        {
            var topology = DevelopmentTopology.CreateQuick();
            var cell = topology.Cells.Single();
            var controller = cell.OfKind(DevelopmentResourceKind.ControllerAgent).Single();
            var security = DevelopmentNatsSecurity.Create(topology, root).Cell(cell.Cell);

            var options = DevelopmentLab.CreateJournalProvisioningOptions(cell, controller, security);

            await Assert.That(options.Command).IsEqualTo(OrchestratorCommand.ProvisionJournal);
            await Assert.That(options.NatsUrl)
                .IsEqualTo($"tls://127.0.0.1:{cell.OfKind(DevelopmentResourceKind.ControlNats).Single().Port}");
            await Assert.That(options.Instance).IsEqualTo($"controller-{controller.Replica}");
            await Assert.That(options.InfrastructureNatsNKeyFile).IsEqualTo(security.Infrastructure.SeedFile);
            await Assert.That(options.InfrastructureNatsTls!.CertificateFile)
                .IsEqualTo(security.Tls.Control.Clients["operator-read"].CertificateFile);
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Test]
    public async Task ContainerImagesAndPodBudgetAreClosed()
    {
        await Assert.That(DevelopmentContainerImages.AspNet).IsEqualTo(
            "mcr.microsoft.com/dotnet/aspnet@sha256:385243b43a2e8b30ffde1eab09a3457b7226bc3cbefedbc3a8b06fa35842c7f6");
        await Assert.That(DevelopmentContainerImages.All).IsEquivalentTo([
            DevelopmentContainerImages.AspNet,
            DevelopmentContainerImages.RuntimeDependencies,
            DevelopmentContainerImages.Node,
            DevelopmentContainerImages.Nats
        ]);
        // 3× TerraBase at 3072 MiB (+1024 MiB each vs previous 2048) = +3072 MiB.
        await Assert.That(DevelopmentProcessSupervisor.PlannedMemoryLimitBytes(
            DevelopmentTopology.CreateRegional()))
            .IsEqualTo(16_128L * 1024 * 1024);
        await Assert.That(DevelopmentProcessSupervisor.PlannedMemoryLimitBytes(
            DevelopmentTopology.CreateControl()))
            .IsEqualTo(1_728L * 1024 * 1024);
        await Assert.That(DevelopmentProcessSupervisor.OwnershipLabel)
            .IsEqualTo("io.terrascale.owner=devhost-orchestrator");
    }

    [Test]
    public async Task OverBudgetTopologyFailsBeforeRuntimeStartup()
    {
        var resources = Enumerable.Range(1, 11)
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
    public async Task UsablePodStatesAcceptOnlyRunningOrCreated()
    {
        await Assert.That(DevelopmentProcessSupervisor.IsUsablePodState("Running")).IsTrue();
        await Assert.That(DevelopmentProcessSupervisor.IsUsablePodState("Created\n")).IsTrue();
        await Assert.That(DevelopmentProcessSupervisor.IsUsablePodState("Degraded")).IsFalse();
        await Assert.That(DevelopmentProcessSupervisor.IsUsablePodState("Exited")).IsFalse();
        await Assert.That(DevelopmentProcessSupervisor.IsUsablePodState(null)).IsFalse();
    }

    [Test]
    public async Task MissingPodExitCodeMatchesPodmanCliWrapperFailure()
    {
        await Assert.That(DevelopmentProcessSupervisor.IsMissingPodExitCode(125)).IsTrue();
        await Assert.That(DevelopmentProcessSupervisor.IsMissingPodExitCode(0)).IsFalse();
        await Assert.That(DevelopmentProcessSupervisor.IsMissingPodExitCode(1)).IsFalse();
    }

    [Test]
    public async Task TerraBaseServerArgumentsRaiseClusterTimeoutsForLabColdStart()
    {
        var resource = DevelopmentTopology.CreateRegional().Cells[0]
            .OfKind(DevelopmentResourceKind.TerraBase)[0];
        var arguments = DevelopmentWorkloadRuntime.CreateTerraBaseServerArguments(
            resource,
            "/profile/workloads/gru-terrabase-1");

        await Assert.That(arguments).Contains("--Cluster.ReceiveFromWorkerTimeoutInMs=30000");
        await Assert.That(arguments).Contains("--Cluster.TimeBeforeMovingToRehabInSec=300");
        await Assert.That(arguments).Contains("--Cluster.TcpTimeoutInMs=30000");
        await Assert.That(arguments).Contains($"--PublicServerUrl=http://127.0.0.1:{resource.Port}");
    }

    [Test]
    public async Task ServiceContainersUseReadOnlyBoundedRootlessIsolation()
    {
        var arguments = DevelopmentProcessSupervisor.ContainerIsolationArguments("335544320");

        await Assert.That(arguments).IsEquivalentTo([
            "--read-only",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", "512",
            "--memory", "335544320",
            "--memory-swap", "335544320",
        ]);
    }

    [Test]
    public async Task ProductArtifactBuildUsesOneMsBuildNode()
    {
        await Assert.That(DevelopmentArtifactBuilder.DotNetBuildArguments("product.csproj", "/profile"))
            .IsEquivalentTo([
                "build", "product.csproj", "--configuration", "Release", "--nologo",
                "--no-incremental", "--maxcpucount:1", "--nodeReuse:false",
                "--artifacts-path", "/profile/artifacts/dotnet"
            ]);
    }

    [Test]
    public async Task PodCreationUsesOneNameAndPinnedInfraWithoutHostHelpers()
    {
        var arguments = DevelopmentProcessSupervisor.PodCreationArguments(
            DevelopmentTopology.CreateControl(),
            "control-lab");

        await Assert.That(arguments.Count(argument => argument == "control-lab")).IsEqualTo(1);
        await Assert.That(arguments).Contains("--infra-image");
        await Assert.That(arguments).Contains(DevelopmentContainerImages.RuntimeDependencies);
        await Assert.That(arguments).Contains("--infra-command");
        await Assert.That(arguments).Contains("sleep infinity");
        await Assert.That(arguments).Contains("pasta:--host-lo-to-ns-lo,--log-file=/dev/null");
    }

    [Test]
    public async Task TerraBaseRuntimeUsesAPrivateWritableCopy()
    {
        var topology = DevelopmentTopology.CreateRegional();
        var root = Path.Combine(Path.GetTempPath(), "terrascale-runtime-" + Guid.NewGuid().ToString("N"));
        try
        {
            var runtime = DevelopmentProcessSupervisor.WritableRuntimeVolume(
                topology,
                "gru-terrabase-1",
                root);

            await Assert.That(runtime).IsNotNull();
            await Assert.That(runtime!.Destination).IsEqualTo(
                Path.Combine(root, "artifacts", "dotnet", "bin", "TerraBase.Server", "release"));
            await Assert.That(runtime.Source).IsEqualTo(
                Path.Combine(root, "workloads", "gru-terrabase-1", "runtime"));

            Directory.CreateDirectory(Path.Combine(runtime.Destination, "nested"));
            File.WriteAllText(Path.Combine(runtime.Destination, "TerraBase.Server.dll"), "first");
            File.WriteAllText(Path.Combine(runtime.Destination, "nested", "asset.json"), "asset");
            DevelopmentProcessSupervisor.PrepareWritableRuntimeVolume(runtime);

            await Assert.That(File.ReadAllText(
                Path.Combine(runtime.Source, "TerraBase.Server.dll"))).IsEqualTo("first");
            await Assert.That(File.ReadAllText(
                Path.Combine(runtime.Source, "nested", "asset.json"))).IsEqualTo("asset");

            File.WriteAllText(Path.Combine(runtime.Destination, "TerraBase.Server.dll"), "second");
            DevelopmentProcessSupervisor.PrepareWritableRuntimeVolume(runtime);
            await Assert.That(File.ReadAllText(
                Path.Combine(runtime.Source, "TerraBase.Server.dll"))).IsEqualTo("second");

            await Assert.That(DevelopmentProcessSupervisor.WritableRuntimeVolume(
                topology,
                "gru-platform",
                root))
                .IsNull();
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }
}
