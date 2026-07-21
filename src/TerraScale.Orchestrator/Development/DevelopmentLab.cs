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
            await DevelopmentArtifactBuilder.BuildAsync(
                options.WorkspaceRoot!,
                options.DataDirectory!,
                cancellationToken);
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
                    // Expired on-disk leaves cannot be healed by RestartAsync alone: NATS and
                    // clients reload the same PEM paths. Remint before health-driven restarts.
                    if (await TryRemintAndRestartTlsConsumersAsync(
                            topology,
                            options.DataDirectory!,
                            supervisor,
                            natsSecurity,
                            force: false,
                            cancellationToken))
                    {
                        consecutiveUnhealthyObservations.Clear();
                        continue;
                    }
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
                    var certificateFailure = health.Values.Any(static observation =>
                        !observation.Healthy && LooksLikeCertificateFailure(observation.Detail));
                    if (certificateFailure &&
                        await TryRemintAndRestartTlsConsumersAsync(
                            topology,
                            options.DataDirectory!,
                            supervisor,
                            natsSecurity,
                            force: true,
                            cancellationToken))
                    {
                        // operator-read / controller / platform handshakes that fail x509
                        // verification cannot be healed by RestartAsync on the same PEMs.
                        consecutiveUnhealthyObservations.Clear();
                        continue;
                    }
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
                        // Re-check near-expiry after probes: a leaf can cross NotAfter between
                        // the top-of-loop remint check and this restart decision.
                        if (await TryRemintAndRestartTlsConsumersAsync(
                                topology,
                                options.DataDirectory!,
                                supervisor,
                                natsSecurity,
                                force: false,
                                cancellationToken))
                        {
                            consecutiveUnhealthyObservations.Clear();
                            break;
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

    private static async Task<bool> TryRemintAndRestartTlsConsumersAsync(
        DevelopmentTopology topology,
        string dataDirectory,
        DevelopmentProcessSupervisor supervisor,
        DevelopmentNatsSecurity natsSecurity,
        bool force,
        CancellationToken cancellationToken)
    {
        // Decide before stopping anything: near-expiry survey or forced recovery after
        // an observed x509 failure. Create always rewrites the full regional tree.
        if (!force && !DevelopmentPki.LeavesNeedRemint(dataDirectory, DateTimeOffset.UtcNow))
        {
            return false;
        }

        // Critical ordering for continuous labs:
        // 1) Stop mTLS clients (controllers, platforms, …) FIRST.
        // 2) Remint PEMs onto stable paths.
        // 3) Recycle control/product NATS so servers load the new CA.
        // 4) Restart clients so they present the new leaves.
        //
        // If Create runs while controllers/platforms are still up, they keep
        // presenting the pre-remint leaf (often past NotAfter) to still-running
        // NATS and log the continuous-lab failure shapes:
        //   [fra-control-nats-1] … certificate has expired … (CN=fra-controller-1 …)
        //   [fra-product-nats-1] … certificate has expired … (CN=fra-platform …)
        // until those clients are eventually stopped. Stopping first cuts that window.
        var tlsClients = TlsClientResourceNames(topology)
            .Where(name => supervisor.Processes.ContainsKey(name))
            .ToArray();
        foreach (var name in tlsClients)
        {
            await supervisor.StopAsync(name);
        }

        DevelopmentPki.Create(topology, dataDirectory);
        Console.WriteLine(
            force
                ? "Reminted development mTLS material after certificate handshake failures; restarting TLS consumers."
                : "Reminted development mTLS material near leaf expiry; restarting TLS consumers.");
        await RestartNatsAndTlsClientsAfterRemintAsync(
            supervisor,
            topology,
            natsSecurity,
            tlsClients,
            cancellationToken);
        return true;
    }

    /// <summary>
    /// Detects x509 verification failures in health-probe details. NATS.Net wraps OpenSSL
    /// alerts under a generic outer message ("can not start to connect"); probes flatten
    /// inner exceptions and annotate expired on-disk leaves so these patterns match.
    /// Broader plain TLS connect errors must not force a full PKI remint.
    /// </summary>
    internal static bool LooksLikeCertificateFailure(string detail)
    {
        return detail.Contains("certificate has expired", StringComparison.OrdinalIgnoreCase)
            || detail.Contains("certificate expired", StringComparison.OrdinalIgnoreCase)
            || detail.Contains("certificate is not yet valid", StringComparison.OrdinalIgnoreCase)
            || detail.Contains("failed to verify certificate", StringComparison.OrdinalIgnoreCase)
            || detail.Contains("remote certificate is invalid", StringComparison.OrdinalIgnoreCase)
            || detail.Contains("ssl/tls alert certificate", StringComparison.OrdinalIgnoreCase)
            || detail.Contains("alert certificate expired", StringComparison.OrdinalIgnoreCase)
            || detail.Contains("x509:", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// After clients are already stopped and PEMs reminted: recycle NATS planes, then
    /// bring the previously stopped mTLS clients back so they load the new leaves.
    /// </summary>
    private static async Task RestartNatsAndTlsClientsAfterRemintAsync(
        DevelopmentProcessSupervisor supervisor,
        DevelopmentTopology topology,
        DevelopmentNatsSecurity natsSecurity,
        IReadOnlyList<string> tlsClients,
        CancellationToken cancellationToken)
    {
        foreach (var cell in topology.Cells)
        {
            foreach (var kind in new[]
            {
                DevelopmentResourceKind.ControlNats,
                DevelopmentResourceKind.ProductNats
            })
            {
                var resources = cell.OfKind(kind);
                foreach (var resource in resources)
                {
                    if (!supervisor.Processes.ContainsKey(resource.Name))
                    {
                        continue;
                    }
                    await supervisor.RestartAsync(resource.Name);
                }
                if (resources.Count == 0 ||
                    resources.Any(resource => !supervisor.Processes.ContainsKey(resource.Name)))
                {
                    continue;
                }
                await NatsDevelopmentCluster.WaitReadyAsync(
                    resources,
                    supervisor,
                    natsSecurity.Cell(cell.Cell),
                    cancellationToken);
            }
        }

        foreach (var name in tlsClients)
        {
            await supervisor.RestartAsync(name);
        }
    }

    /// <summary>
    /// Non-NATS lab resources that hold or consume regional mTLS material and must
    /// be stopped before PEMs are reminted and NATS is recycled.
    /// </summary>
    internal static IReadOnlyList<string> TlsClientResourceNames(DevelopmentTopology topology) =>
        topology.Cells
            .SelectMany(cell => cell.Resources)
            .Concat(topology.GlobalResources)
            .Where(resource => resource.Kind is not DevelopmentResourceKind.ControlNats
                and not DevelopmentResourceKind.ProductNats)
            .Select(resource => resource.Name)
            .ToArray();

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
            var controlNats = cell.OfKind(DevelopmentResourceKind.ControlNats)[0];
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
        DevelopmentResourceKind.Platform or
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
        var productNats = gru.OfKind(DevelopmentResourceKind.ProductNats);
        if (productNats.Count == 0)
        {
            return;
        }
        endpoints["nats"] = endpoints[productNats[0].Name];
        endpoints["platform"] = endpoints[gru.OfKind(DevelopmentResourceKind.Platform).Single().Name];
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
