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
                    // Probe identities (operator-read, platform, controllers) are the leaves
                    // that emit NATS server TLS handshake logs when presented. LeavesNeedRemint
                    // surveys NotAfter across existing PEMs and can miss a single deleted leaf
                    // while siblings remain valid; force remint before ProbeAsync so the health
                    // cycle is not the first detector of an already-invalid operator-read PEM
                    // (fingerprint e517701a… / sfo-control-nats multi-occurrence).
                    if (AnyProbeTlsLeafInvalid(topology, natsSecurity) &&
                        await TryRemintAndRestartTlsConsumersAsync(
                            topology,
                            options.DataDirectory!,
                            supervisor,
                            natsSecurity,
                            force: true,
                            cancellationToken))
                    {
                        consecutiveUnhealthyObservations.Clear();
                        continue;
                    }
                    // Unexpected exits cannot be healed by restarting onto expired PEMs.
                    // Remint first when leaves already need rotation or an exited mTLS
                    // consumer's probe leaf is already invalid, then restart victims.
                    var exitedResources = supervisor.ExitedResources();
                    if (exitedResources.Count > 0 &&
                        (DevelopmentPki.LeavesNeedRemint(options.DataDirectory!, DateTimeOffset.UtcNow) ||
                         exitedResources.Any(name =>
                             ResourceHasInvalidTlsLeaf(topology, natsSecurity, name))) &&
                        await TryRemintAndRestartTlsConsumersAsync(
                            topology,
                            options.DataDirectory!,
                            supervisor,
                            natsSecurity,
                            force: true,
                            cancellationToken))
                    {
                        consecutiveUnhealthyObservations.Clear();
                        continue;
                    }
                    foreach (var resourceName in exitedResources)
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
                        if (observation.Value.Healthy)
                        {
                            consecutiveUnhealthyObservations[observation.Key] = 0;
                            continue;
                        }

                        // Certificate failures must not be swallowed by startup grace.
                        // Bare RestartAsync after NATS recycle (cid reset) re-loads the same
                        // expired PEMs; control-plane probes then re-present CN=operator-read
                        // every few minutes (fingerprint c6627a56bf45… / gru-control-nats and
                        // e517701a… / sfo-control-nats).
                        var observationCertificateFailure =
                            LooksLikeCertificateFailure(observation.Value.Detail);
                        if (!observationCertificateFailure &&
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
                        // Certificate-shaped unhealth, invalid reconnect leaf (operator-read,
                        // controllers, platforms), or near-expiry survey: never bare-restart
                        // mTLS consumers. RestartAsync alone recycled NATS while client PEMs
                        // stayed expired (cid 29237 → 62 → 69 for CN=operator-read;
                        // cid 29238 → 63 → 70 for CN=sfo-controller-1 on sfo-control-nats-1;
                        // cid 29238 → 32 → 63 → 70 for CN=gru-controller-1 on
                        // gru-control-nats-1, fingerprint c2bf6b539a62…).
                        if ((observationCertificateFailure ||
                             ResourceHasInvalidTlsLeaf(topology, natsSecurity, observation.Key) ||
                             DevelopmentPki.LeavesNeedRemint(
                                 options.DataDirectory!,
                                 DateTimeOffset.UtcNow)) &&
                            await TryRemintAndRestartTlsConsumersAsync(
                                topology,
                                options.DataDirectory!,
                                supervisor,
                                natsSecurity,
                                force: true,
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

        // Capture the running sets first so RestartAsync can bring back exactly the
        // resources that were live for this generation (specifications survive Stop).
        var natsServers = NatsResourceNames(topology)
            .Where(name => supervisor.Processes.ContainsKey(name))
            .ToArray();
        var tlsClients = TlsClientResourceNames(topology)
            .Where(name => supervisor.Processes.ContainsKey(name))
            .ToArray();

        // Critical ordering for continuous labs:
        // 1) Stop control/product NATS FIRST. Server-side logs are the incident source
        //    ("TLS handshake error … certificate has expired … CN=sfo-controller-1").
        //    Leaving NATS up while clients are stopped one-by-one (15s grace each)
        //    produced multi-minute reconnect storms across gru/sfo/fra for both
        //    controllers and platforms, plus operator-read health probes.
        // 2) Stop mTLS clients so they cannot present pre-remint leaves after NATS returns.
        // 3) Remint PEMs onto stable paths.
        // 4) Restart NATS (new CA) then clients (new leaves).
        await supervisor.StopManyAsync(natsServers);
        await supervisor.StopManyAsync(tlsClients);

        DevelopmentPki.Create(topology, dataDirectory);
        Console.WriteLine(
            force
                ? "Reminted development mTLS material after certificate handshake failures; restarting TLS consumers."
                : "Reminted development mTLS material near leaf expiry; restarting TLS consumers.");
        await RestartNatsAndTlsClientsAfterRemintAsync(
            supervisor,
            topology,
            natsSecurity,
            natsServers,
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
    /// Returns true when any health-probe mTLS identity (operator-read, platform leaf, or
    /// controller leaf) is expired, not yet valid, missing, or unreadable on disk.
    /// Used to force remint before <see cref="DevelopmentHealthProbe.ProbeAsync"/> so the
    /// continuous-lab loop never relies on a failed ConnectAsync to discover invalid PEMs.
    /// </summary>
    internal static bool AnyProbeTlsLeafInvalid(
        DevelopmentTopology topology,
        DevelopmentNatsSecurity natsSecurity)
    {
        foreach (var resource in topology.Cells
                     .SelectMany(cell => cell.Resources)
                     .Concat(topology.GlobalResources))
        {
            if (ResourceHasInvalidTlsLeaf(topology, natsSecurity, resource.Name))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Returns true when any on-disk mTLS leaf that reconnects to
    /// <paramref name="resourceName"/> (or that the resource itself presents) is already
    /// invalid. Health probes for control NATS only present operator-read, but long-running
    /// controllers also reconnect to that plane; bare RestartAsync of NATS while a controller
    /// leaf stays expired re-emits multi-occurrence server logs
    /// (fingerprint f490b625… / sfo-control-nats CN=sfo-controller-1 cid 29238 → 63 → 70,
    /// fingerprint c2bf6b539a62… / gru-control-nats CN=gru-controller-1 cid 29238 → 32 → 63 → 70,
    /// and the e517701a… operator-read twin). Product NATS is analogous for platform leaves.
    /// Cell-agnostic: every control-plane client in the NATS resource's cell is surveyed so
    /// gru/sfo/fra controller-only expiry cannot fall through to bare NATS recycle.
    /// </summary>
    internal static bool ResourceHasInvalidTlsLeaf(
        DevelopmentTopology topology,
        DevelopmentNatsSecurity natsSecurity,
        string resourceName)
    {
        foreach (var identity in EnumerateReconnectTlsIdentities(topology, natsSecurity, resourceName))
        {
            if (DevelopmentHealthProbe.DescribeLeafValidity(identity.CertificateFile) is not null)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Resolves the mTLS client identity that health probes present for a lab resource,
    /// or null when the resource does not use a regional probe leaf.
    /// </summary>
    internal static DevelopmentTlsIdentity? TryGetProbeTlsIdentity(
        DevelopmentTopology topology,
        DevelopmentNatsSecurity natsSecurity,
        string resourceName)
    {
        var resource = FindResource(topology, resourceName);
        if (resource is null)
        {
            return null;
        }

        var cellSecurity = natsSecurity.Cell(resource.Cell);
        return resource.Kind switch
        {
            DevelopmentResourceKind.ControlNats =>
                cellSecurity.Tls.Control.Clients["operator-read"],
            DevelopmentResourceKind.ProductNats =>
                cellSecurity.Tls.Product.Clients[$"{resource.Cell}-platform"],
            DevelopmentResourceKind.ControllerAgent =>
                cellSecurity.Tls.Control.Clients[resource.Name],
            DevelopmentResourceKind.Platform =>
                cellSecurity.Tls.Product.Clients[resource.Name],
            _ => null
        };
    }

    /// <summary>
    /// Every client leaf that would re-handshake against <paramref name="resourceName"/> after a
    /// bare RestartAsync, plus the resource's own client leaf when it is a controller/platform.
    /// Control NATS includes operator-read and every controller in the cell so an expired
    /// CN=*-controller-1 leaf (sfo f490b625…, gru c2bf6b539a62…, and fra twins) alone still
    /// forces remint instead of NATS recycle.
    /// </summary>
    internal static IEnumerable<DevelopmentTlsIdentity> EnumerateReconnectTlsIdentities(
        DevelopmentTopology topology,
        DevelopmentNatsSecurity natsSecurity,
        string resourceName)
    {
        var resource = FindResource(topology, resourceName);
        if (resource is null)
        {
            yield break;
        }

        var cellSecurity = natsSecurity.Cell(resource.Cell);
        switch (resource.Kind)
        {
            case DevelopmentResourceKind.ControlNats:
                foreach (var client in cellSecurity.Tls.Control.Clients.Values)
                {
                    yield return client;
                }
                yield break;
            case DevelopmentResourceKind.ProductNats:
                foreach (var client in cellSecurity.Tls.Product.Clients.Values)
                {
                    yield return client;
                }
                yield break;
            case DevelopmentResourceKind.ControllerAgent:
                yield return cellSecurity.Tls.Control.Clients[resource.Name];
                yield break;
            case DevelopmentResourceKind.Platform:
                yield return cellSecurity.Tls.Product.Clients[resource.Name];
                yield break;
        }
    }

    private static DevelopmentResourcePlan? FindResource(
        DevelopmentTopology topology,
        string resourceName) =>
        topology.Cells
            .SelectMany(cell => cell.Resources)
            .Concat(topology.GlobalResources)
            .FirstOrDefault(candidate =>
                string.Equals(candidate.Name, resourceName, StringComparison.Ordinal));

    /// <summary>
    /// After NATS and clients are already stopped and PEMs reminted: bring control/product
    /// NATS back on the new CA, wait for readiness, then restart the previously stopped
    /// mTLS clients so they load the new leaves.
    /// </summary>
    private static async Task RestartNatsAndTlsClientsAfterRemintAsync(
        DevelopmentProcessSupervisor supervisor,
        DevelopmentTopology topology,
        DevelopmentNatsSecurity natsSecurity,
        IReadOnlyList<string> natsServers,
        IReadOnlyList<string> tlsClients,
        CancellationToken cancellationToken)
    {
        var natsSet = natsServers.ToHashSet(StringComparer.Ordinal);
        foreach (var cell in topology.Cells)
        {
            foreach (var kind in new[]
            {
                DevelopmentResourceKind.ControlNats,
                DevelopmentResourceKind.ProductNats
            })
            {
                var resources = cell.OfKind(kind)
                    .Where(resource => natsSet.Contains(resource.Name))
                    .ToArray();
                if (resources.Length == 0)
                {
                    continue;
                }
                foreach (var resource in resources)
                {
                    // Already stopped above; RestartAsync starts from the retained spec.
                    await supervisor.RestartAsync(resource.Name);
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
    /// Control and product NATS resources that must be stopped before PKI remint so
    /// they cannot keep logging client-certificate expiry while peers reconnect.
    /// </summary>
    internal static IReadOnlyList<string> NatsResourceNames(DevelopmentTopology topology) =>
        topology.Cells
            .SelectMany(cell => cell.Resources)
            .Where(resource => resource.Kind is DevelopmentResourceKind.ControlNats
                or DevelopmentResourceKind.ProductNats)
            .Select(resource => resource.Name)
            .ToArray();

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
