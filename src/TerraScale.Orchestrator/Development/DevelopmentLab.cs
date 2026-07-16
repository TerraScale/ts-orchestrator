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

        var topology = DevelopmentTopology.CreateThreeCellR3();
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
        Directory.CreateDirectory(options.DataDirectory!);
        var previous = await DevelopmentStateStore.ReadAsync(options.StateFile!, cancellationToken);
        var generation = (previous?.Generation ?? 0) + 1;
        var startedAt = DateTimeOffset.UtcNow;

        await using var supervisor = new DevelopmentProcessSupervisor();
        await PersistAsync(
            options,
            topology,
            supervisor,
            generation,
            startedAt,
            DevelopmentResourceState.Starting,
            cancellationToken);

        foreach (var cell in topology.Cells)
        {
            var control = NatsDevelopmentCluster.Start(
                supervisor,
                cell,
                DevelopmentResourceKind.ControlNats,
                Path.Combine(options.DataDirectory!, "nats"));
            var product = NatsDevelopmentCluster.Start(
                supervisor,
                cell,
                DevelopmentResourceKind.ProductNats,
                Path.Combine(options.DataDirectory!, "nats"));
            await NatsDevelopmentCluster.WaitReadyAsync(control, supervisor, cancellationToken);
            await NatsDevelopmentCluster.WaitReadyAsync(product, supervisor, cancellationToken);
        }

        StartControllers(supervisor, topology, options.WorkspaceRoot!);
        await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken);
        supervisor.ThrowIfAnyExited();
        await DevelopmentWorkloadRuntime.StartAsync(
            supervisor,
            topology,
            options.WorkspaceRoot!,
            options.DataDirectory!,
            options.Watch,
            cancellationToken);
        supervisor.ThrowIfAnyExited();

        await PersistAsync(
            options,
            topology,
            supervisor,
            generation,
            startedAt,
            DevelopmentResourceState.Ready,
            cancellationToken);
        Console.WriteLine($"TerraScale Orchestrator development topology generation {generation} is ready.");

        while (!cancellationToken.IsCancellationRequested)
        {
            supervisor.ThrowIfAnyExited();
            await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken);
            await PersistAsync(
                options,
                topology,
                supervisor,
                generation,
                startedAt,
                DevelopmentResourceState.Ready,
                cancellationToken);
        }
        return 0;
    }

    private static void StartControllers(
        DevelopmentProcessSupervisor supervisor,
        DevelopmentTopology topology,
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
                supervisor.Start(
                    controller.Name,
                    executable,
                    ["run"],
                    workingDirectory,
                    new Dictionary<string, string?>
                    {
                        ["TS_ORCH_CELL"] = cell.Cell,
                        ["TS_ORCH_NATS_URL"] = $"nats://127.0.0.1:{controlNats.Port}",
                        ["TS_ORCH_REPLICAS"] = "3",
                        ["TS_ORCH_INSTANCE"] = controller.Replica.ToString(
                            System.Globalization.CultureInfo.InvariantCulture)
                    });
            }
        }
    }

    private static async Task PersistAsync(
        OrchestratorOptions options,
        DevelopmentTopology topology,
        DevelopmentProcessSupervisor supervisor,
        long generation,
        DateTimeOffset startedAt,
        DevelopmentResourceState state,
        CancellationToken cancellationToken)
    {
        var observedAt = DateTimeOffset.UtcNow;
        var all = topology.Cells.SelectMany(cell => cell.Resources)
            .Concat(topology.GlobalResources)
            .Select(resource => Observe(resource, supervisor, state, observedAt))
            .ToArray();
        var runtimeState = new DevelopmentRuntimeState(
            1,
            topology.Profile,
            generation,
            startedAt,
            observedAt,
            all);
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
            endpoints,
            cancellationToken);
    }

    private static DevelopmentResourceObservation Observe(
        DevelopmentResourcePlan resource,
        DevelopmentProcessSupervisor supervisor,
        DevelopmentResourceState desiredState,
        DateTimeOffset observedAt)
    {
        supervisor.Processes.TryGetValue(resource.Name, out var process);
        var exited = process?.HasExited == true;
        var state = exited ? DevelopmentResourceState.Failed : desiredState;
        return new(
            resource.Name,
            resource.Cell,
            resource.Kind,
            resource.Replica,
            state,
            state is DevelopmentResourceState.Ready,
            process is not null && !exited ? process.Id : null,
            Endpoint(resource),
            exited ? $"Exited with code {process!.ExitCode}." : state.ToString(),
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
        endpoints["nats"] = endpoints[gru.OfKind(DevelopmentResourceKind.ProductNats).First().Name];
        endpoints["api"] = endpoints[gru.OfKind(DevelopmentResourceKind.Api).Single().Name];
        endpoints["authentication"] = endpoints[gru.OfKind(DevelopmentResourceKind.Authentication).Single().Name];
        endpoints["dashboard"] = endpoints[gru.OfKind(DevelopmentResourceKind.Dashboard).Single().Name];
        var terraBase = gru.OfKind(DevelopmentResourceKind.TerraBase);
        endpoints["terrabase"] = endpoints[terraBase[0].Name];
        endpoints["terrabase-b"] = endpoints[terraBase[1].Name];
        endpoints["terrabase-c"] = endpoints[terraBase[2].Name];
    }
}
