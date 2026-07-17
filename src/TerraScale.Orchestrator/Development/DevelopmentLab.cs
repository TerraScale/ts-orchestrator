using System.Text.Json;
using System.Text.Json.Serialization;

namespace TerraScale.Orchestrator.Development;

public static class DevelopmentLab
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    public static async Task<int> ExecuteAsync(
        OrchestratorOptions options,
        CancellationToken cancellationToken)
    {
        if (options.Command is not OrchestratorCommand.Lab || options.LabCommand is null)
        {
            throw new InvalidOperationException("DevelopmentLab requires a lab command.");
        }
        var topology = options.LabProfile switch
        {
            OrchestratorLabProfile.DevContainers => DevelopmentTopology.CreateThreeCellLean(),
            OrchestratorLabProfile.DevContainersControl =>
                DevelopmentTopology.CreateThreeCellControlPlane(),
            _ => throw new InvalidOperationException($"Unsupported lab profile {options.LabProfile}.")
        };
        return options.LabCommand switch
        {
            OrchestratorLabCommand.Plan => PrintPlan(topology),
            OrchestratorLabCommand.Status => await PrintStatusAsync(options, cancellationToken),
            OrchestratorLabCommand.Up => await RunAsync(options, topology, cancellationToken),
            _ => throw new InvalidOperationException($"Unsupported lab command {options.LabCommand}.")
        };
    }

    private static int PrintPlan(DevelopmentTopology topology)
    {
        Console.WriteLine(JsonSerializer.Serialize(topology, SerializerOptions));
        return 0;
    }

    private static async Task<int> PrintStatusAsync(
        OrchestratorOptions options,
        CancellationToken cancellationToken)
    {
        var state = await DevelopmentStateStore.ReadAsync(options.StateFile!, cancellationToken);
        if (state is null)
        {
            Console.Error.WriteLine("The Orchestrator development lab has no recorded state.");
            return 1;
        }
        Console.WriteLine(JsonSerializer.Serialize(state, SerializerOptions));
        return state.Resources.All(resource => resource.State is DevelopmentResourceState.Ready)
            ? 0
            : 1;
    }

    private static async Task<int> RunAsync(
        OrchestratorOptions options,
        DevelopmentTopology topology,
        CancellationToken cancellationToken)
    {
        await PreDeploymentEvidence.RequireAsync(
            options.EvidenceFile,
            options.WorkspaceRoot!,
            topology.Profile,
            cancellationToken);
        using var validationLease = LocalValidationLease.Acquire();
        Directory.CreateDirectory(options.DataDirectory!);
        if (HasProductWorkloads(topology))
        {
            await DevelopmentArtifactBuilder.BuildAsync(options.WorkspaceRoot!, cancellationToken);
        }
        var previous = await DevelopmentStateStore.ReadAsync(options.StateFile!, cancellationToken);
        var generation = (previous?.Generation ?? 0) + 1;
        var startedAt = DateTimeOffset.UtcNow;
        File.Delete(options.EndpointsFile!);

        var supervisor = new DevelopmentProcessSupervisor(
            topology,
            options.WorkspaceRoot!,
            options.DataDirectory!,
            options.Instance);
        try
        {
            await using (supervisor)
            {
                await supervisor.InitializeAsync(cancellationToken);
                var natsSecurity = DevelopmentNatsSecurity.Create(topology, options.DataDirectory!);
                await PersistAsync(
                    options,
                    topology,
                    supervisor,
                    generation,
                    startedAt,
                    DevelopmentResourceState.Starting,
                    null,
                    publishEndpoints: false,
                    cancellationToken);

                foreach (var cell in topology.Cells)
                {
                    foreach (var kind in new[]
                    {
                        DevelopmentResourceKind.ControlNats,
                        DevelopmentResourceKind.ProductNats
                    })
                    {
                        if (cell.OfKind(kind).Count == 0)
                        {
                            continue;
                        }
                        var resources = NatsDevelopmentCluster.Start(
                            supervisor,
                            cell,
                            kind,
                            Path.Combine(options.DataDirectory!, "nats"),
                            natsSecurity.Cell(cell.Cell));
                        await NatsDevelopmentCluster.WaitReadyAsync(
                            resources, supervisor, natsSecurity.Cell(cell.Cell), cancellationToken);
                    }
                }

                StartControllers(supervisor, topology, natsSecurity, options.WorkspaceRoot!);
                await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken);
                supervisor.ThrowIfAnyExited();
                if (HasProductWorkloads(topology))
                {
                    await DevelopmentWorkloadRuntime.StartAsync(
                        supervisor,
                        topology,
                        options.WorkspaceRoot!,
                        options.DataDirectory!,
                        natsSecurity,
                        cancellationToken);
                }
                supervisor.ThrowIfAnyExited();

                var initialHealth = await WaitForInitialHealthAsync(
                    options, topology, supervisor, natsSecurity, generation, startedAt, cancellationToken);
                await PersistAsync(
                    options,
                    topology,
                    supervisor,
                    generation,
                    startedAt,
                    DevelopmentResourceState.Ready,
                    initialHealth,
                    publishEndpoints: true,
                    cancellationToken);
                Console.WriteLine($"TerraScale Orchestrator development topology generation {generation} is ready.");

                var consecutiveUnhealthyObservations = new Dictionary<string, int>(StringComparer.Ordinal);
                while (!cancellationToken.IsCancellationRequested)
                {
                    await Task.Delay(TimeSpan.FromSeconds(5), cancellationToken);
                    foreach (var resourceName in supervisor.ExitedResources())
                    {
                        await supervisor.RestartAsync(resourceName);
                        consecutiveUnhealthyObservations[resourceName] = 0;
                        Console.WriteLine($"Restarted development resource {resourceName} after an unexpected exit.");
                    }
                    var health = await DevelopmentHealthProbe.ProbeAsync(
                        topology,
                        supervisor,
                        natsSecurity,
                        cancellationToken);
                    await PersistAsync(
                        options,
                        topology,
                        supervisor,
                        generation,
                        startedAt,
                        DevelopmentResourceState.Ready,
                        health,
                        publishEndpoints: true,
                        cancellationToken);
                    foreach (var observation in health)
                    {
                        if (observation.Value.Healthy ||
                            supervisor.IsWithinStartupGrace(observation.Key, TimeSpan.FromSeconds(90)))
                        {
                            consecutiveUnhealthyObservations[observation.Key] = 0;
                            continue;
                        }
                        var failures = consecutiveUnhealthyObservations.GetValueOrDefault(observation.Key) + 1;
                        consecutiveUnhealthyObservations[observation.Key] = failures;
                        if (failures < 3)
                        {
                            continue;
                        }
                        await supervisor.RestartAsync(observation.Key);
                        consecutiveUnhealthyObservations[observation.Key] = 0;
                        Console.WriteLine(
                            $"Restarted unhealthy development resource {observation.Key}: {observation.Value.Detail}");
                    }
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        finally
        {
            await PersistAsync(
                options,
                topology,
                supervisor,
                generation,
                startedAt,
                DevelopmentResourceState.Stopped,
                null,
                publishEndpoints: false,
                CancellationToken.None);
            File.Delete(options.EndpointsFile!);
        }
        return 0;
    }

    private static void StartControllers(
        DevelopmentProcessSupervisor supervisor,
        DevelopmentTopology topology,
        DevelopmentNatsSecurity natsSecurity,
        string workspaceRoot)
    {
        var executable = Environment.ProcessPath
            ?? throw new InvalidOperationException("The current Orchestrator executable path is unavailable.");
        var workingDirectory = Path.Combine(workspaceRoot, "TerraScale.Orchestrator");
        foreach (var cell in topology.Cells)
        {
            var controlNats = cell.OfKind(DevelopmentResourceKind.ControlNats).First();
            foreach (var controller in cell.OfKind(DevelopmentResourceKind.ControllerAgent))
            {
                var cellSecurity = natsSecurity.Cell(cell.Cell);
                var tls = cellSecurity.Tls.Control.Clients[controller.Name];
                supervisor.Start(
                    controller.Name,
                    DevelopmentContainerImages.RuntimeDependencies,
                    [executable, "run"],
                    workingDirectory,
                    new Dictionary<string, string?>
                    {
                        ["TS_ORCH_CELL"] = cell.Cell,
                        ["TS_ORCH_NATS_URL"] = $"nats://127.0.0.1:{controlNats.Port}",
                        ["TS_ORCH_REPLICAS"] = "1",
                        ["TS_ORCH_NATS_NKEY_FILE"] = cellSecurity.Controllers[controller.Replica].SeedFile,
                        ["TS_ORCH_NATS_TLS_CA_FILE"] = tls.CaFile,
                        ["TS_ORCH_NATS_TLS_CERT_FILE"] = tls.CertificateFile,
                        ["TS_ORCH_NATS_TLS_KEY_FILE"] = tls.KeyFile,
                        ["TS_ORCH_INSTANCE"] = controller.Replica.ToString(
                            System.Globalization.CultureInfo.InvariantCulture)
                    });
            }
        }
    }

    private static async Task<IReadOnlyDictionary<string, DevelopmentResourceHealth>> WaitForInitialHealthAsync(
        OrchestratorOptions options,
        DevelopmentTopology topology,
        DevelopmentProcessSupervisor supervisor,
        DevelopmentNatsSecurity natsSecurity,
        long generation,
        DateTimeOffset startedAt,
        CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromMinutes(2));
        while (true)
        {
            supervisor.ThrowIfAnyExited();
            var health = await DevelopmentHealthProbe.ProbeAsync(
                topology,
                supervisor,
                natsSecurity,
                timeout.Token);
            if (health.Values.All(value => value.Healthy))
            {
                return health;
            }
            await PersistAsync(
                options,
                topology,
                supervisor,
                generation,
                startedAt,
                DevelopmentResourceState.Starting,
                health,
                publishEndpoints: false,
                timeout.Token);
            await Task.Delay(TimeSpan.FromSeconds(1), timeout.Token);
        }
    }

    private static async Task PersistAsync(
        OrchestratorOptions options,
        DevelopmentTopology topology,
        DevelopmentProcessSupervisor supervisor,
        long generation,
        DateTimeOffset startedAt,
        DevelopmentResourceState state,
        IReadOnlyDictionary<string, DevelopmentResourceHealth>? health,
        bool publishEndpoints,
        CancellationToken cancellationToken)
    {
        var observedAt = DateTimeOffset.UtcNow;
        var all = topology.Cells.SelectMany(cell => cell.Resources)
            .Concat(topology.GlobalResources)
            .Select(resource => Observe(resource, supervisor, state, health, observedAt))
            .ToArray();
        var reconciliation = DevelopmentReconciliation.Evaluate(topology, generation, all);
        if (state == DevelopmentResourceState.Ready &&
            all.All(resource => resource.State == DevelopmentResourceState.Ready) &&
            (reconciliation.Errors.Count != 0 || reconciliation.ConvergedResources != all.Length))
        {
            throw new InvalidOperationException(
                "The development graph cannot be accepted until typed reconciliation proves exact convergence.");
        }
        var runtimeState = new DevelopmentRuntimeState(
            2,
            topology.Profile,
            generation,
            startedAt,
            observedAt,
            all,
            reconciliation);
        var endpointValues = all.Where(observation => observation.Endpoint is not null)
            .ToDictionary(observation => observation.Name, observation => observation.Endpoint!, StringComparer.Ordinal);
        AddDevHostAliases(endpointValues, topology);
        var endpoints = new DevelopmentEndpointMap(
            1,
            generation,
            endpointValues);
        await DevelopmentStateStore.WriteAsync(
            options.StateFile!,
            options.EndpointsFile!,
            runtimeState,
            publishEndpoints ? endpoints : null,
            cancellationToken);
    }

    private static DevelopmentResourceObservation Observe(
        DevelopmentResourcePlan resource,
        DevelopmentProcessSupervisor supervisor,
        DevelopmentResourceState desiredState,
        IReadOnlyDictionary<string, DevelopmentResourceHealth>? health,
        DateTimeOffset observedAt)
    {
        supervisor.Processes.TryGetValue(resource.Name, out var process);
        var exited = process?.HasExited == true;
        DevelopmentResourceHealth? resourceHealth = null;
        if (health is not null)
        {
            health.TryGetValue(resource.Name, out resourceHealth);
        }
        var withinStartupGrace = supervisor.IsWithinStartupGrace(resource.Name, TimeSpan.FromSeconds(90));
        var state = exited
            ? DevelopmentResourceState.Failed
            : resourceHealth is { Healthy: false }
                ? withinStartupGrace
                    ? DevelopmentResourceState.Starting
                    : DevelopmentResourceState.Degraded
                : desiredState;
        var healthy = state is DevelopmentResourceState.Ready && resourceHealth?.Healthy is not false;
        return new(
            resource.Name,
            resource.Cell,
            resource.Kind,
            resource.Replica,
            state,
            healthy,
            process is not null && !exited ? supervisor.GetContainerProcessId(resource.Name) : null,
            process is not null ? supervisor.GetContainerId(resource.Name) : null,
            Endpoint(resource),
            exited
                ? $"Exited with code {process!.ExitCode}."
                : resourceHealth?.Detail ?? state.ToString(),
            observedAt);
    }

    private static string? Endpoint(DevelopmentResourcePlan resource) => resource.Kind switch
    {
        DevelopmentResourceKind.ControlNats or DevelopmentResourceKind.ProductNats =>
            $"nats://127.0.0.1:{resource.Port}",
        DevelopmentResourceKind.TerraBase or
        DevelopmentResourceKind.Authentication or
        DevelopmentResourceKind.Api or
        DevelopmentResourceKind.Dashboard or
        DevelopmentResourceKind.EmailEmulator or
        DevelopmentResourceKind.StripeEmulator =>
            $"http://127.0.0.1:{resource.Port}",
        _ => null
    };

    private static void AddDevHostAliases(
        IDictionary<string, string> endpoints,
        DevelopmentTopology topology)
    {
        var gru = topology.Cells.Single(cell => cell.Cell == "gru");
        if (gru.OfKind(DevelopmentResourceKind.ProductNats).Count == 0)
        {
            return;
        }
        endpoints["nats"] = endpoints[gru.OfKind(DevelopmentResourceKind.ProductNats).First().Name];
        endpoints["api"] = endpoints[gru.OfKind(DevelopmentResourceKind.Api).Single().Name];
        endpoints["authentication"] = endpoints[gru.OfKind(DevelopmentResourceKind.Authentication).Single().Name];
        endpoints["dashboard"] = endpoints[gru.OfKind(DevelopmentResourceKind.Dashboard).Single().Name];
        var terraBase = gru.OfKind(DevelopmentResourceKind.TerraBase);
        endpoints["terrabase"] = endpoints[terraBase[0].Name];
        endpoints["terrabase-b"] = endpoints[terraBase[0].Name];
        endpoints["terrabase-c"] = endpoints[terraBase[0].Name];
    }

    private static bool HasProductWorkloads(DevelopmentTopology topology) =>
        topology.Cells.Any(cell => cell.OfKind(DevelopmentResourceKind.ProductNats).Count != 0);
}
