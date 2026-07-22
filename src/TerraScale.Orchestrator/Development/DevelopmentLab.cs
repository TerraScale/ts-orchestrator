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
                    // (fingerprint c6627a56… / gru-control-nats multi-occurrence and denser
                    // twin c48cbf142a9a… cid 29239 → 34 → 66 → 72 and two-occurrence
                    // post-recycle twin f4f92376efda… cid 31 → 46 at 18:45:50Z on
                    // 127.0.0.1:56170 and 18:49:50Z on 127.0.0.1:45996 and second
                    // two-occurrence post-recycle twin b252d8996050… cid 34 → 51 at
                    // 18:45:56Z on 127.0.0.1:54410 and 18:49:56Z on 127.0.0.1:35762 and
                    // third two-occurrence post-recycle twin 6a650c470be6… cid 37 → 69 at
                    // 18:46:01Z on 127.0.0.1:54470 and 18:47:01Z on 127.0.0.1:57302 and
                    // fourth two-occurrence post-recycle twin 5c56829c01e4… cid 40 → 72 at
                    // 18:46:07Z on 127.0.0.1:48998 and 18:47:07Z on 127.0.0.1:42902 and
                    // fifth two-occurrence post-recycle twin 9dd8feb97fa2… cid 43 → 75 at
                    // 18:46:13Z on 127.0.0.1:49032 and 18:47:13Z on 127.0.0.1:42960 and
                    // three-occurrence post-recycle twin 5807fcff9600… cid 46 → 78 → 30 at
                    // 18:46:19Z on 127.0.0.1:37264, 18:47:19Z on 127.0.0.1:34126, and
                    // 18:49:19Z on 127.0.0.1:45286 against
                    // the same 4e40db2b… leaf; fingerprint e517701a… / sfo-control-nats multi-
                    // occurrence and denser twin f08d1c577176… cid 29239 → 33 → 65 → 72 and
                    // two-occurrence post-recycle twin 62860f83eeb6… cid 30 → 46 at
                    // 18:45:50Z on 127.0.0.1:50596 and 18:49:50Z on 127.0.0.1:34070 and
                    // second two-occurrence post-recycle twin 97d33257778a… cid 33 → 50 at
                    // 18:45:56Z on 127.0.0.1:52196 and 18:49:56Z on 127.0.0.1:36654 and
                    // third two-occurrence post-recycle twin d80a6067f126… cid 37 → 68 at
                    // 18:46:01Z on 127.0.0.1:52246 and 18:47:01Z on 127.0.0.1:34762 and
                    // fourth two-occurrence post-recycle twin 58dda0785551… cid 40 → 72 at
                    // 18:46:07Z on 127.0.0.1:49186 and 18:47:07Z on 127.0.0.1:53880 and
                    // fifth two-occurrence post-recycle twin 69541ea34d1d… cid 43 → 75 at
                    // 18:46:13Z on 127.0.0.1:49240 and 18:47:13Z on 127.0.0.1:53920 and
                    // three-occurrence post-recycle twin 0c8da303bb67… cid 46 → 78 → 30 at
                    // 18:46:19Z on 127.0.0.1:40988, 18:47:19Z on 127.0.0.1:59820, and
                    // 18:49:19Z on 127.0.0.1:35640 against
                    // the same aa00c1c3… leaf; fingerprint 9a811bb8… / fra-control-nats multi-
                    // occurrence and denser twin f95adc65… cid 29239 → 33 → 65 → 72 and
                    // two-occurrence post-recycle twin 7421834a4183… cid 30 → 46 at
                    // 18:45:50Z on 127.0.0.1:34654 and 18:49:50Z on 127.0.0.1:33762 and second
                    // two-occurrence post-recycle twin c74671d2c0e4… cid 33 → 49 at
                    // 18:45:56Z on 127.0.0.1:43890 and 18:49:56Z on 127.0.0.1:37146 and
                    // third two-occurrence post-recycle twin b2dec42a6166… cid 36 → 68 at
                    // 18:46:01Z on 127.0.0.1:43922 and 18:47:01Z on 127.0.0.1:42774 and
                    // fourth two-occurrence post-recycle twin d26af782af24… cid 40 → 71 at
                    // 18:46:07Z on 127.0.0.1:48686 and 18:47:07Z on 127.0.0.1:46486 and
                    // fifth two-occurrence post-recycle twin 424b0b6af457… cid 43 → 75 at
                    // 18:46:13Z on 127.0.0.1:48710 and 18:47:13Z on 127.0.0.1:46544 and
                    // three-occurrence post-recycle twin 461d52d6f097… cid 46 → 78 → 29 at
                    // 18:46:19Z on 127.0.0.1:45414, 18:47:19Z on 127.0.0.1:34512, and
                    // 18:49:19Z on 127.0.0.1:44846 and single-occurrence post-recycle twin
                    // e9d264fcee49… cid:49 at 18:46:26Z on 127.0.0.1:38796 against
                    // the same 6477b788… leaf).
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
                        // every few minutes (fingerprint c6627a56bf45… / gru-control-nats,
                        // fingerprint c48cbf142a9a… / gru-control-nats four-occurrence twin
                        // cid 29239 → 34 → 66 → 72 at 18:45:40Z / 18:47:40Z / 18:48:40Z /
                        // 18:50:40Z against the same 4e40db2b… leaf, fingerprint
                        // f4f92376efda… / gru-control-nats two-occurrence post-recycle twin
                        // cid 31 → 46 at 18:45:50Z on 127.0.0.1:56170 and 18:49:50Z on
                        // 127.0.0.1:45996 against the same 4e40db2b… leaf, fingerprint
                        // b252d8996050… / gru-control-nats second two-occurrence
                        // post-recycle twin cid 34 → 51 at 18:45:56Z on 127.0.0.1:54410 and
                        // 18:49:56Z on 127.0.0.1:35762 against the same 4e40db2b… leaf,
                        // fingerprint 6a650c470be6… / gru-control-nats third two-occurrence
                        // post-recycle twin cid 37 → 69 at 18:46:01Z on 127.0.0.1:54470 and
                        // 18:47:01Z on 127.0.0.1:57302 against the same 4e40db2b… leaf,
                        // fingerprint 5c56829c01e4… / gru-control-nats fourth two-occurrence
                        // post-recycle twin cid 40 → 72 at 18:46:07Z on 127.0.0.1:48998 and
                        // 18:47:07Z on 127.0.0.1:42902 against the same 4e40db2b… leaf,
                        // fingerprint 9dd8feb97fa2… / gru-control-nats fifth two-occurrence
                        // post-recycle twin cid 43 → 75 at 18:46:13Z on 127.0.0.1:49032 and
                        // 18:47:13Z on 127.0.0.1:42960 against the same 4e40db2b… leaf,
                        // fingerprint 5807fcff9600… / gru-control-nats three-occurrence
                        // post-recycle twin cid 46 → 78 → 30 at 18:46:19Z on
                        // 127.0.0.1:37264, 18:47:19Z on 127.0.0.1:34126, and 18:49:19Z on
                        // 127.0.0.1:45286 against the same 4e40db2b… leaf,
                        // e517701a… / sfo-control-nats, fingerprint f08d1c577176… /
                        // sfo-control-nats four-occurrence twin cid 29239 → 33 → 65 → 72 at
                        // 18:45:40Z / 18:47:40Z / 18:48:40Z / 18:50:40Z against the same
                        // aa00c1c3… leaf,
                        // fingerprint 62860f83eeb6… / sfo-control-nats two-occurrence
                        // post-recycle twin cid 30 → 46 at 18:45:50Z on 127.0.0.1:50596 and
                        // 18:49:50Z on 127.0.0.1:34070 against the same aa00c1c3… leaf,
                        // fingerprint 97d33257778a… / sfo-control-nats second two-occurrence
                        // post-recycle twin cid 33 → 50 at 18:45:56Z on 127.0.0.1:52196 and
                        // 18:49:56Z on 127.0.0.1:36654 against the same aa00c1c3… leaf,
                        // fingerprint d80a6067f126… / sfo-control-nats third two-occurrence
                        // post-recycle twin cid 37 → 68 at 18:46:01Z on 127.0.0.1:52246 and
                        // 18:47:01Z on 127.0.0.1:34762 against the same aa00c1c3… leaf,
                        // fingerprint 58dda0785551… / sfo-control-nats fourth two-occurrence
                        // post-recycle twin cid 40 → 72 at 18:46:07Z on 127.0.0.1:49186 and
                        // 18:47:07Z on 127.0.0.1:53880 against the same aa00c1c3… leaf,
                        // fingerprint 69541ea34d1d… / sfo-control-nats fifth two-occurrence
                        // post-recycle twin cid 43 → 75 at 18:46:13Z on 127.0.0.1:49240 and
                        // 18:47:13Z on 127.0.0.1:53920 against the same aa00c1c3… leaf,
                        // fingerprint 0c8da303bb67… / sfo-control-nats three-occurrence
                        // post-recycle twin cid 46 → 78 → 30 at 18:46:19Z on
                        // 127.0.0.1:40988, 18:47:19Z on 127.0.0.1:59820, and 18:49:19Z on
                        // 127.0.0.1:35640 against the same aa00c1c3… leaf,
                        // fingerprint f95adc65… / fra-control-nats four-occurrence twin
                        // cid 29239 → 33 → 65 → 72 at 18:45:40Z / 18:47:40Z / 18:48:40Z /
                        // 18:50:40Z against the same 6477b788… leaf, fingerprint
                        // 7421834a4183… / fra-control-nats two-occurrence post-recycle twin
                        // cid 30 → 46 at 18:45:50Z on 127.0.0.1:34654 and 18:49:50Z on
                        // 127.0.0.1:33762 against the same 6477b788… leaf, fingerprint
                        // c74671d2c0e4… / fra-control-nats second two-occurrence
                        // post-recycle twin cid 33 → 49 at 18:45:56Z on 127.0.0.1:43890 and
                        // 18:49:56Z on 127.0.0.1:37146 against the same 6477b788… leaf,
                        // fingerprint b2dec42a6166… / fra-control-nats third two-occurrence
                        // post-recycle twin cid 36 → 68 at 18:46:01Z on 127.0.0.1:43922 and
                        // 18:47:01Z on 127.0.0.1:42774 against the same 6477b788… leaf, and
                        // fingerprint d26af782af24… / fra-control-nats fourth two-occurrence
                        // post-recycle twin cid 40 → 71 at 18:46:07Z on 127.0.0.1:48686 and
                        // 18:47:07Z on 127.0.0.1:46486 against the same 6477b788… leaf, and
                        // fingerprint 424b0b6af457… / fra-control-nats fifth two-occurrence
                        // post-recycle twin cid 43 → 75 at 18:46:13Z on 127.0.0.1:48710 and
                        // 18:47:13Z on 127.0.0.1:46544 against the same 6477b788… leaf,
                        // fingerprint 461d52d6f097… / fra-control-nats three-occurrence
                        // post-recycle twin cid 46 → 78 → 29 at 18:46:19Z on
                        // 127.0.0.1:45414, 18:47:19Z on 127.0.0.1:34512, and 18:49:19Z on
                        // 127.0.0.1:44846 against the same 6477b788… leaf,
                        // fingerprint e9d264fcee49… / fra-control-nats single-occurrence
                        // post-recycle twin cid:49 at 18:46:26Z on 127.0.0.1:38796 against
                        // the same 6477b788… leaf).
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
                        // stayed expired (cid 29237 → 62 → 69 for CN=operator-read on
                        // gru/sfo-control-nats; cid 29239 → 34 → 66 → 72 for CN=operator-read on
                        // gru-control-nats-1, fingerprint c48cbf142a9a… — four-occurrence twin of
                        // c6627a56bf45… against the same 4e40db2b… leaf at 18:45:40Z / 18:47:40Z /
                        // 18:48:40Z / 18:50:40Z; cid 31 → 46 for CN=operator-read on
                        // gru-control-nats-1, fingerprint f4f92376efda… — two-occurrence
                        // post-recycle reconnect twin of c6627a56bf45… / c48cbf142a9a… against the
                        // same 4e40db2b… leaf at 18:45:50Z on 127.0.0.1:56170 and 18:49:50Z on
                        // 127.0.0.1:45996 after bare control-NATS RestartAsync reloads the same
                        // expired operator-read PEM; cid 34 → 51 for CN=operator-read on
                        // gru-control-nats-1, fingerprint b252d8996050… — second two-occurrence
                        // post-recycle reconnect twin of c6627a56bf45… / c48cbf142a9a… /
                        // f4f92376efda… against the same 4e40db2b… leaf at 18:45:56Z on
                        // 127.0.0.1:54410 and 18:49:56Z on 127.0.0.1:35762 after bare
                        // control-NATS RestartAsync reloads the same expired operator-read PEM;
                        // cid 37 → 69 for CN=operator-read on
                        // gru-control-nats-1, fingerprint 6a650c470be6… — third two-occurrence
                        // post-recycle reconnect twin of c6627a56bf45… / c48cbf142a9a… /
                        // f4f92376efda… / b252d8996050… against the same 4e40db2b… leaf at
                        // 18:46:01Z on 127.0.0.1:54470 and 18:47:01Z on 127.0.0.1:57302 after
                        // bare control-NATS RestartAsync reloads the same expired operator-read
                        // PEM (gru peer of sfo d80a6067f126… cid 37 → 68 at the same wall-clock
                        // :01 steps);
                        // cid 40 → 72 for CN=operator-read on
                        // gru-control-nats-1, fingerprint 5c56829c01e4… — fourth two-occurrence
                        // post-recycle reconnect twin of c6627a56bf45… / c48cbf142a9a… /
                        // f4f92376efda… / b252d8996050… / 6a650c470be6… against the same
                        // 4e40db2b… leaf at 18:46:07Z on 127.0.0.1:48998 and 18:47:07Z on
                        // 127.0.0.1:42902 after bare control-NATS RestartAsync reloads the same
                        // expired operator-read PEM (gru peer of sfo 58dda0785551… cid 40 → 72
                        // and fra-controller 88eec19ebb94… / sfo-platform ef71b6e32493… at the
                        // same wall-clock :07 steps);
                        // cid 43 → 75 for CN=operator-read on
                        // gru-control-nats-1, fingerprint 9dd8feb97fa2… — fifth two-occurrence
                        // post-recycle reconnect twin of c6627a56bf45… / c48cbf142a9a… /
                        // f4f92376efda… / b252d8996050… / 6a650c470be6… / 5c56829c01e4… against
                        // the same 4e40db2b… leaf at 18:46:13Z on 127.0.0.1:49032 and
                        // 18:47:13Z on 127.0.0.1:42960 after bare control-NATS RestartAsync
                        // reloads the same expired operator-read PEM (gru peer of sfo-platform
                        // e583d837318a… / fra-platform d86f81358e32… at the same wall-clock
                        // :13 steps);
                        // cid 46 → 78 → 30 for CN=operator-read on
                        // gru-control-nats-1, fingerprint 5807fcff9600… — three-occurrence
                        // post-recycle reconnect twin of c6627a56bf45… / c48cbf142a9a… /
                        // f4f92376efda… / b252d8996050… / 6a650c470be6… / 5c56829c01e4… /
                        // 9dd8feb97fa2… against the same 4e40db2b… leaf at 18:46:19Z on
                        // 127.0.0.1:37264, 18:47:19Z on 127.0.0.1:34126, and 18:49:19Z on
                        // 127.0.0.1:45286 after bare control-NATS RestartAsync reloads the
                        // same expired operator-read PEM (gru control-plane peer of
                        // gru-platform 1f9106a25f41… / sfo-platform 1668f8c0e10f… /
                        // fra-platform 59a0656971a4… at the same wall-clock :19 steps);
                        // cid 29239 → 33 → 65 → 72 for CN=operator-read on
                        // sfo-control-nats-1, fingerprint f08d1c577176… — four-occurrence twin of
                        // e517701a… against the same aa00c1c3… leaf at 18:45:40Z / 18:47:40Z /
                        // 18:48:40Z / 18:50:40Z; cid 30 → 46 for CN=operator-read on
                        // sfo-control-nats-1, fingerprint 62860f83eeb6… — two-occurrence
                        // post-recycle reconnect twin of e517701a… / f08d1c577176… against the
                        // same aa00c1c3… leaf at 18:45:50Z on 127.0.0.1:50596 and 18:49:50Z on
                        // 127.0.0.1:34070 after bare control-NATS RestartAsync reloads the same
                        // expired operator-read PEM; cid 33 → 50 for CN=operator-read on
                        // sfo-control-nats-1, fingerprint 97d33257778a… — second two-occurrence
                        // post-recycle reconnect twin of e517701a… / f08d1c577176… / 62860f83eeb6…
                        // against the same aa00c1c3… leaf at 18:45:56Z on 127.0.0.1:52196 and
                        // 18:49:56Z on 127.0.0.1:36654 after bare control-NATS RestartAsync
                        // reloads the same expired operator-read PEM; cid 37 → 68 for
                        // CN=operator-read on sfo-control-nats-1, fingerprint d80a6067f126… —
                        // third two-occurrence post-recycle reconnect twin of e517701a… /
                        // f08d1c577176… / 62860f83eeb6… / 97d33257778a… against the same
                        // aa00c1c3… leaf at 18:46:01Z on 127.0.0.1:52246 and 18:47:01Z on
                        // 127.0.0.1:34762 after bare control-NATS RestartAsync reloads the same
                        // expired operator-read PEM; cid 40 → 72 for
                        // CN=operator-read on sfo-control-nats-1, fingerprint 58dda0785551… —
                        // fourth two-occurrence post-recycle reconnect twin of e517701a… /
                        // f08d1c577176… / 62860f83eeb6… / 97d33257778a… / d80a6067f126… against
                        // the same aa00c1c3… leaf at 18:46:07Z on 127.0.0.1:49186 and
                        // 18:47:07Z on 127.0.0.1:53880 after bare control-NATS RestartAsync
                        // reloads the same expired operator-read PEM (sfo peer of fra-controller
                        // 88eec19ebb94… and sfo-platform ef71b6e32493… at the same wall-clock
                        // :07 steps);
                        // cid 43 → 75 for
                        // CN=operator-read on sfo-control-nats-1, fingerprint 69541ea34d1d… —
                        // fifth two-occurrence post-recycle reconnect twin of e517701a… /
                        // f08d1c577176… / 62860f83eeb6… / 97d33257778a… / d80a6067f126… /
                        // 58dda0785551… against the same aa00c1c3… leaf at 18:46:13Z on
                        // 127.0.0.1:49240 and 18:47:13Z on 127.0.0.1:53920 after bare
                        // control-NATS RestartAsync reloads the same expired operator-read
                        // PEM (sfo peer of gru 9dd8feb97fa2… cid 43 → 75 / fra 424b0b6af457…
                        // cid 43 → 75 / sfo-platform e583d837318a… / fra-platform
                        // d86f81358e32… at the same wall-clock :13 steps);
                        // cid 46 → 78 → 30 for CN=operator-read on
                        // sfo-control-nats-1, fingerprint 0c8da303bb67… — three-occurrence
                        // post-recycle reconnect twin of e517701a… / f08d1c577176… /
                        // 62860f83eeb6… / 97d33257778a… / d80a6067f126… / 58dda0785551… /
                        // 69541ea34d1d… against the same aa00c1c3… leaf at 18:46:19Z on
                        // 127.0.0.1:40988, 18:47:19Z on 127.0.0.1:59820, and 18:49:19Z on
                        // 127.0.0.1:35640 after bare control-NATS RestartAsync reloads the
                        // same expired operator-read PEM (sfo control-plane peer of gru
                        // 5807fcff9600… cid 46 → 78 → 30 / fra 461d52d6f097… cid 46 → 78 → 29
                        // / gru-platform 1f9106a25f41… / sfo-platform 1668f8c0e10f… /
                        // fra-platform 59a0656971a4… at the same wall-clock :19 steps);
                        // cid 29237 → 63 → 68 for
                        // CN=operator-read on fra-control-nats, fingerprint 9a811bb8…; cid
                        // 29239 → 33 → 65 → 72 for CN=operator-read on fra-control-nats-1,
                        // fingerprint f95adc65… —
                        // four-occurrence twin of 9a811bb8… against the same 6477b788… leaf at
                        // 18:45:40Z / 18:47:40Z / 18:48:40Z / 18:50:40Z; cid 30 → 46 for
                        // CN=operator-read on fra-control-nats-1, fingerprint 7421834a4183… —
                        // two-occurrence post-recycle reconnect twin of 9a811bb8… / f95adc65…
                        // against the same 6477b788… leaf at 18:45:50Z on 127.0.0.1:34654 and
                        // 18:49:50Z on 127.0.0.1:33762 after bare control-NATS RestartAsync
                        // reloads the same expired operator-read PEM; cid 33 → 49 for
                        // CN=operator-read on fra-control-nats-1, fingerprint c74671d2c0e4… —
                        // second two-occurrence post-recycle reconnect twin of 9a811bb8… /
                        // f95adc65… / 7421834a4183… against the same 6477b788… leaf at
                        // 18:45:56Z on 127.0.0.1:43890 and 18:49:56Z on 127.0.0.1:37146 after
                        // bare control-NATS RestartAsync reloads the same expired
                        // operator-read PEM; cid 36 → 68 for
                        // CN=operator-read on fra-control-nats-1, fingerprint b2dec42a6166… —
                        // third two-occurrence post-recycle reconnect twin of 9a811bb8… /
                        // f95adc65… / 7421834a4183… / c74671d2c0e4… against the same 6477b788…
                        // leaf at 18:46:01Z on 127.0.0.1:43922 and 18:47:01Z on 127.0.0.1:42774
                        // after bare control-NATS RestartAsync reloads the same expired
                        // operator-read PEM (fra peer of gru 6a650c470be6… cid 37 → 69 and sfo
                        // d80a6067f126… cid 37 → 68 at the same wall-clock :01 steps);
                        // cid 40 → 71 for
                        // CN=operator-read on fra-control-nats-1, fingerprint d26af782af24… —
                        // fourth two-occurrence post-recycle reconnect twin of 9a811bb8… /
                        // f95adc65… / 7421834a4183… / c74671d2c0e4… / b2dec42a6166… against
                        // the same 6477b788… leaf at 18:46:07Z on 127.0.0.1:48686 and
                        // 18:47:07Z on 127.0.0.1:46486 after bare control-NATS RestartAsync
                        // reloads the same expired operator-read PEM (fra peer of gru
                        // 5c56829c01e4… cid 40 → 72 / sfo 58dda0785551… cid 40 → 72 /
                        // fra-controller 88eec19ebb94… / sfo-platform ef71b6e32493… /
                        // gru-platform 0401b56675fd… at the same wall-clock :07 steps);
                        // cid 43 → 75 for
                        // CN=operator-read on fra-control-nats-1, fingerprint 424b0b6af457… —
                        // fifth two-occurrence post-recycle reconnect twin of 9a811bb8… /
                        // f95adc65… / 7421834a4183… / c74671d2c0e4… / b2dec42a6166… /
                        // d26af782af24… against the same 6477b788… leaf at 18:46:13Z on
                        // 127.0.0.1:48710 and 18:47:13Z on 127.0.0.1:46544 after bare
                        // control-NATS RestartAsync reloads the same expired operator-read
                        // PEM (fra peer of gru 9dd8feb97fa2… cid 43 → 75 / sfo-platform
                        // e583d837318a… / fra-platform d86f81358e32… at the same wall-clock
                        // :13 steps);
                        // cid 46 → 78 → 29 for CN=operator-read on
                        // fra-control-nats-1, fingerprint 461d52d6f097… — three-occurrence
                        // post-recycle reconnect twin of 9a811bb8… / f95adc65… /
                        // 7421834a4183… / c74671d2c0e4… / b2dec42a6166… / d26af782af24… /
                        // 424b0b6af457… against the same 6477b788… leaf at 18:46:19Z on
                        // 127.0.0.1:45414, 18:47:19Z on 127.0.0.1:34512, and 18:49:19Z on
                        // 127.0.0.1:44846 after bare control-NATS RestartAsync reloads the
                        // same expired operator-read PEM (fra peer of gru 5807fcff9600…
                        // cid 46 → 78 → 30 / gru-platform 1f9106a25f41… / sfo-platform
                        // 1668f8c0e10f… / fra-platform 59a0656971a4… at the same wall-clock
                        // :19 steps);
                        // cid:49 for CN=operator-read on
                        // fra-control-nats-1, fingerprint e9d264fcee49… — single-occurrence
                        // post-recycle reconnect twin of 9a811bb8… / f95adc65… /
                        // 7421834a4183… / c74671d2c0e4… / b2dec42a6166… / d26af782af24… /
                        // 424b0b6af457… / 461d52d6f097… against the same 6477b788… leaf at
                        // 18:46:26Z on 127.0.0.1:38796 after bare control-NATS RestartAsync
                        // reloads the same expired operator-read PEM (seven seconds after
                        // 461d52d6f097… cid 46 on 127.0.0.1:45414 at :19; concurrent with
                        // fra-platform 86b0b173f024… cid 57 → 96 → 97 → 32 / gru-platform
                        // d26427e1c533… cid 58 → 97 → 98 → 32 at the adjacent wall-clock
                        // :25/:26 steps);
                        // cid 29238 → 63 → 70 for
                        // CN=sfo-controller-1 on sfo-control-nats-1, fingerprint f490b625…;
                        // cid 29240 → 34 → 35 → 66 → 73 for CN=sfo-controller-1 on
                        // sfo-control-nats-1, fingerprint 9815ef5a… — denser five-occurrence twin
                        // of f490b625… against the same f56fe7a4… leaf at 18:45:40Z /
                        // 18:47:40Z (dual cid 34+35) / 18:48:40Z / 18:50:40Z: long-running
                        // sfo-controller-1 reconnects while bare control-NATS RestartAsync
                        // reloads the same expired controller leaf;
                        // cid 28 → 36 for CN=sfo-controller-1 on sfo-control-nats-1,
                        // fingerprint 4eeeee0520a1… — two-occurrence post-recycle reconnect twin
                        // of f490b625… / 9815ef5a… against the same f56fe7a4… leaf at
                        // 18:45:45Z on 127.0.0.1:50552 and 18:47:45Z on 127.0.0.1:37302 after
                        // bare control-NATS RestartAsync reloads the same expired controller leaf;
                        // cid 29 → 61 for CN=sfo-controller-1 on sfo-control-nats-1,
                        // fingerprint e8e55fe0bef9… — second two-occurrence post-recycle reconnect
                        // twin of f490b625… / 9815ef5a… / 4eeeee0520a1… against the same f56fe7a4…
                        // leaf at 18:45:47Z on 127.0.0.1:50560 and 18:46:47Z on 127.0.0.1:55476
                        // after bare control-NATS RestartAsync reloads the same expired
                        // controller leaf;
                        // cid 31 → 39 → 47 for CN=sfo-controller-1 on sfo-control-nats-1,
                        // fingerprint 412baaa56842… — three-occurrence post-recycle reconnect twin
                        // of f490b625… / 9815ef5a… / 4eeeee0520a1… / e8e55fe0bef9… against the same
                        // f56fe7a4… leaf at 18:45:50Z on 127.0.0.1:50606, 18:47:50Z on
                        // 127.0.0.1:37360, and 18:49:50Z on 127.0.0.1:34092 after bare
                        // control-NATS RestartAsync reloads the same expired controller leaf;
                        // cid 32 → 41 → 71 → 48 for CN=sfo-controller-1 on sfo-control-nats-1,
                        // fingerprint 71cf8514f4d6… — four-occurrence post-recycle reconnect twin
                        // of f490b625… / 9815ef5a… / 4eeeee0520a1… / e8e55fe0bef9… / 412baaa56842…
                        // against the same f56fe7a4… leaf at 18:45:51Z on 127.0.0.1:50616,
                        // 18:47:51Z on 127.0.0.1:37414, 18:48:51Z on 127.0.0.1:58882, and
                        // 18:49:51Z on 127.0.0.1:34106 after bare control-NATS RestartAsync
                        // reloads the same expired controller leaf;
                        // cid 64 → 73 → 78 → 80 for CN=sfo-controller-1 on sfo-control-nats-1,
                        // fingerprint ce40d219dc90… — four-occurrence post-recycle reconnect twin
                        // of f490b625… / 9815ef5a… / 4eeeee0520a1… / e8e55fe0bef9… / 412baaa56842… /
                        // 71cf8514f4d6… against the same f56fe7a4… leaf at 18:46:52Z on
                        // 127.0.0.1:55524, 18:48:52Z on 127.0.0.1:58922, and 18:50:52Z on
                        // 127.0.0.1:52222 / 127.0.0.1:52258 (dual cid 78+80) after bare
                        // control-NATS RestartAsync reloads the same expired controller leaf;
                        // cid 34 → 35 → 74 → 49 → 51 for CN=sfo-controller-1 on sfo-control-nats-1,
                        // fingerprint fc867739e2e2… — five-occurrence post-recycle reconnect twin
                        // of f490b625… / 9815ef5a… / 4eeeee0520a1… / e8e55fe0bef9… / 412baaa56842… /
                        // 71cf8514f4d6… / ce40d219dc90… against the same f56fe7a4… leaf at
                        // 18:45:56Z on 127.0.0.1:52202 / 127.0.0.1:52218 (dual cid 34+35),
                        // 18:48:56Z on 127.0.0.1:51334, and 18:49:56Z on 127.0.0.1:36626 /
                        // 127.0.0.1:36656 (dual cid 49+51) after bare control-NATS RestartAsync
                        // reloads the same expired controller leaf;
                        // cid 36 → 38 → 69 → 77 → 52 for CN=sfo-controller-1 on sfo-control-nats-1,
                        // fingerprint 3db5efff618c… — five-occurrence post-recycle reconnect twin
                        // of f490b625… / 9815ef5a… / 4eeeee0520a1… / e8e55fe0bef9… / 412baaa56842… /
                        // 71cf8514f4d6… / ce40d219dc90… / fc867739e2e2… against the same f56fe7a4…
                        // leaf at 18:46:01Z on 127.0.0.1:52226 / 127.0.0.1:52264 (dual cid 36+38),
                        // 18:47:01Z on 127.0.0.1:34778, 18:49:01Z on 127.0.0.1:51374, and
                        // 18:50:01Z on 127.0.0.1:36672 after bare control-NATS RestartAsync
                        // reloads the same expired controller leaf;
                        // cid 39 → 80 → 55 for CN=sfo-controller-1 on sfo-control-nats-1,
                        // fingerprint c9f4a06686ba… — three-occurrence post-recycle reconnect twin
                        // of f490b625… / 9815ef5a… / 4eeeee0520a1… / e8e55fe0bef9… / 412baaa56842… /
                        // 71cf8514f4d6… / ce40d219dc90… / fc867739e2e2… / 3db5efff618c… against the
                        // same f56fe7a4… leaf at 18:46:06Z on 127.0.0.1:49160, 18:49:06Z on
                        // 127.0.0.1:37578, and 18:50:06Z on 127.0.0.1:48750 after bare
                        // control-NATS RestartAsync reloads the same expired controller leaf
                        // (sfo peer of gru 024cbd22bdf4… cid 39 → 71 → 80 → 55 at the same
                        // wall-clock :05/:06 steps, sparse without the mid-window cid 71);
                        // cid 41 → 71 → 73 for CN=sfo-controller-1 on sfo-control-nats-1,
                        // fingerprint a5ee4c55235d… — three-occurrence post-recycle reconnect twin
                        // of f490b625… / 9815ef5a… / 4eeeee0520a1… / e8e55fe0bef9… / 412baaa56842… /
                        // 71cf8514f4d6… / ce40d219dc90… / fc867739e2e2… / 3db5efff618c… /
                        // c9f4a06686ba… against the same f56fe7a4… leaf at 18:46:07Z on
                        // 127.0.0.1:49206 and 18:47:07Z on 127.0.0.1:53864 / 127.0.0.1:53886
                        // (dual cid 71+73) after bare control-NATS RestartAsync reloads the same
                        // expired controller leaf (sfo peer of gru e7ad7a71e395… cid 41 → 73 /
                        // operator-read 58dda0785551… cid 40 → 72 / gru 5c56829c01e4… /
                        // fra d26af782af24… / fra-controller 88eec19ebb94… / sfo-platform
                        // ef71b6e32493… / gru-platform 0401b56675fd… at the same wall-clock
                        // :07 steps);
                        // cid 42 → 83 → 58 for CN=sfo-controller-1 on sfo-control-nats-1,
                        // fingerprint 914b99d5fbc6… — three-occurrence post-recycle reconnect twin
                        // of f490b625… / 9815ef5a… / 4eeeee0520a1… / e8e55fe0bef9… / 412baaa56842… /
                        // 71cf8514f4d6… / ce40d219dc90… / fc867739e2e2… / 3db5efff618c… /
                        // c9f4a06686ba… / a5ee4c55235d… against the same f56fe7a4… leaf at
                        // 18:46:11Z on 127.0.0.1:49220, 18:49:11Z on 127.0.0.1:37634, and
                        // 18:50:11Z on 127.0.0.1:48798 after bare control-NATS RestartAsync
                        // reloads the same expired controller leaf (sfo peer of gru
                        // 96fe8dda09bb… cid 42 → 74 → 50 → 51 → 81 → 83 → 58 at the adjacent
                        // wall-clock :10/:11 steps, sparse without the mid-window dual-cid
                        // reconnects);
                        // cid 44 → 76 for CN=sfo-controller-1 on sfo-control-nats-1,
                        // fingerprint 53b4362b4444… — two-occurrence post-recycle reconnect twin
                        // of f490b625… / 9815ef5a… / 4eeeee0520a1… / e8e55fe0bef9… / 412baaa56842… /
                        // 71cf8514f4d6… / ce40d219dc90… / fc867739e2e2… / 3db5efff618c… /
                        // c9f4a06686ba… / a5ee4c55235d… / 914b99d5fbc6… against the same f56fe7a4…
                        // leaf at 18:46:13Z on 127.0.0.1:49260 and 18:47:13Z on 127.0.0.1:53940
                        // after bare control-NATS RestartAsync reloads the same expired
                        // controller leaf (sfo peer of gru operator-read 9dd8feb97fa2… cid 43 →
                        // 75 / fra operator-read 424b0b6af457… cid 43 → 75 / sfo-platform
                        // e583d837318a… / fra-platform d86f81358e32… at the same wall-clock :13
                        // steps, and two seconds after 914b99d5fbc6… cid 42 on adjacent port
                        // 49220);
                        // cid 45 → 29 → 61 for CN=sfo-controller-1 on sfo-control-nats-1,
                        // fingerprint bbdb6e0d6006… — three-occurrence post-recycle reconnect twin
                        // of f490b625… / 9815ef5a… / 4eeeee0520a1… / e8e55fe0bef9… / 412baaa56842… /
                        // 71cf8514f4d6… / ce40d219dc90… / fc867739e2e2… / 3db5efff618c… /
                        // c9f4a06686ba… / a5ee4c55235d… / 914b99d5fbc6… / 53b4362b4444… against the
                        // same f56fe7a4… leaf at 18:46:16Z on 127.0.0.1:40982, 18:49:16Z on
                        // 127.0.0.1:35628, and 18:50:16Z on 127.0.0.1:52900 after bare
                        // control-NATS RestartAsync reloads the same expired controller leaf
                        // (three seconds after 53b4362b4444… cid 44 on adjacent :13 steps, and
                        // sfo peer of gru d00ef05a1026… cid 45 → 77 → 52 → 54 → 29 → 60 → 61 at
                        // the adjacent wall-clock :15 steps);
                        // cid 47 → 79 → 31 for CN=sfo-controller-1 on sfo-control-nats-1,
                        // fingerprint 1cdbb448aebb… — three-occurrence post-recycle reconnect twin
                        // of f490b625… / 9815ef5a… / 4eeeee0520a1… / e8e55fe0bef9… / 412baaa56842… /
                        // 71cf8514f4d6… / ce40d219dc90… / fc867739e2e2… / 3db5efff618c… /
                        // c9f4a06686ba… / a5ee4c55235d… / 914b99d5fbc6… / 53b4362b4444… /
                        // bbdb6e0d6006… against the same f56fe7a4… leaf at 18:46:19Z on
                        // 127.0.0.1:41010, 18:47:19Z on 127.0.0.1:59830, and 18:49:19Z on
                        // 127.0.0.1:35648 after bare control-NATS RestartAsync reloads the same
                        // expired controller leaf (three seconds after bbdb6e0d6006… cid 45 →
                        // 29 → 61 on adjacent :16 steps / ports 40982/35628, concurrent with
                        // sfo-platform 1668f8c0e10f… at the same wall-clock :19 steps);
                        // cid 48 → 57 → 63 → 64 for CN=sfo-controller-1 on sfo-control-nats-1,
                        // fingerprint 2e80728c5df4… — four-occurrence post-recycle reconnect twin
                        // of f490b625… / 9815ef5a… / 4eeeee0520a1… / e8e55fe0bef9… / 412baaa56842… /
                        // 71cf8514f4d6… / ce40d219dc90… / fc867739e2e2… / 3db5efff618c… /
                        // c9f4a06686ba… / a5ee4c55235d… / 914b99d5fbc6… / 53b4362b4444… /
                        // bbdb6e0d6006… / 1cdbb448aebb… against the same f56fe7a4… leaf at
                        // 18:46:21Z on 127.0.0.1:41016, 18:48:21Z on 127.0.0.1:54454, and
                        // 18:50:21Z on 127.0.0.1:52952 / 127.0.0.1:52960 (dual cid 63+64) after
                        // bare control-NATS RestartAsync reloads the same expired controller leaf
                        // (two seconds after 1cdbb448aebb… cid 47 on adjacent :19 steps / port
                        // 41010 → 41016, concurrent with gru e51d12dd4525… cid 48 → 55 → 32 → 62
                        // at the adjacent wall-clock :20/:21 steps);
                        // cid 50 → 51 → 65 for CN=sfo-controller-1 on sfo-control-nats-1,
                        // fingerprint 306f7d4a6890… — three-occurrence post-recycle reconnect twin
                        // of f490b625… / 9815ef5a… / 4eeeee0520a1… / e8e55fe0bef9… / 412baaa56842… /
                        // 71cf8514f4d6… / ce40d219dc90… / fc867739e2e2… / 3db5efff618c… /
                        // c9f4a06686ba… / a5ee4c55235d… / 914b99d5fbc6… / 53b4362b4444… /
                        // bbdb6e0d6006… / 1cdbb448aebb… / 2e80728c5df4… against the same
                        // f56fe7a4… leaf at 18:46:26Z on 127.0.0.1:33714 / 127.0.0.1:33728
                        // (dual cid 50+51) and 18:50:26Z on 127.0.0.1:55442 after bare
                        // control-NATS RestartAsync reloads the same expired controller leaf
                        // (five seconds after 2e80728c5df4… cid 48 → 57 → 63 → 64 on adjacent
                        // :21 steps, concurrent with gru 1455d09f7030… cid 51 → 83 at the same
                        // wall-clock :26 steps);
                        // cid 29238 → 32 → 63 → 70
                        // for CN=gru-controller-1 on gru-control-nats-1, fingerprint c2bf6b539a62…;
                        // cid 29240 → 58 → 35 → 65 → 67 → 42 → 73 for CN=gru-controller-1 on
                        // gru-control-nats-1, fingerprint 782d6308… — denser seven-occurrence twin
                        // of c2bf6b539a62… against the same d467c210… leaf at 18:45:40Z /
                        // 18:46:40Z / 18:47:40Z / 18:48:40Z (dual cid 65+67) / 18:49:40Z /
                        // 18:50:40Z: long-running gru-controller-1 reconnects while bare
                        // control-NATS RestartAsync reloads the same expired controller leaf;
                        // cid 28 → 60 for CN=gru-controller-1 on gru-control-nats-1,
                        // fingerprint 003657d51ecd… — two-occurrence post-recycle reconnect twin
                        // of c2bf6b539a62… / 782d6308… against the same d467c210… leaf at
                        // 18:45:43Z on 127.0.0.1:49796 and 18:46:43Z on 127.0.0.1:60312 after
                        // bare control-NATS RestartAsync reloads the same expired controller leaf;
                        // cid 29 → 61 → 68 → 45 for CN=gru-controller-1 on gru-control-nats-1,
                        // fingerprint b9dc4dd1a8ef… — four-occurrence post-recycle reconnect twin
                        // of c2bf6b539a62… / 782d6308… / 003657d51ecd… against the same d467c210…
                        // leaf at 18:45:45Z on 127.0.0.1:56146, 18:46:45Z on 127.0.0.1:57182,
                        // 18:48:45Z on 127.0.0.1:55606, and 18:49:45Z on 127.0.0.1:45982 after
                        // bare control-NATS RestartAsync reloads the same expired controller leaf;
                        // cid 30 → 32 → 64 → 71 → 47 → 48 for CN=gru-controller-1 on
                        // gru-control-nats-1, fingerprint 7b6a047263d8… — six-occurrence
                        // post-recycle reconnect twin of c2bf6b539a62… / 782d6308… /
                        // 003657d51ecd… / b9dc4dd1a8ef… against the same d467c210… leaf at
                        // 18:45:50Z on 127.0.0.1:56154 / 127.0.0.1:56178 (dual cid 30+32),
                        // 18:46:50Z on 127.0.0.1:57224, 18:48:50Z on 127.0.0.1:55652, and
                        // 18:49:50Z on 127.0.0.1:46006 / 127.0.0.1:46018 (dual cid 47+48) after
                        // bare control-NATS RestartAsync reloads the same expired controller leaf;
                        // cid 33 → 67 → 65 → 74 → 49 for CN=gru-controller-1 on
                        // gru-control-nats-1, fingerprint 87f7f1566c88… — five-occurrence
                        // post-recycle reconnect twin of c2bf6b539a62… / 782d6308… /
                        // 003657d51ecd… / b9dc4dd1a8ef… / 7b6a047263d8… against the same
                        // d467c210… leaf at 18:45:55Z on 127.0.0.1:54390, 18:46:55Z on
                        // 127.0.0.1:57284 / 127.0.0.1:57238 (dual cid 67+65), 18:48:55Z on
                        // 127.0.0.1:46006, and 18:49:55Z on 127.0.0.1:35748 after bare
                        // control-NATS RestartAsync reloads the same expired controller leaf;
                        // cid 35 → 50 → 81 for CN=gru-controller-1 on gru-control-nats-1,
                        // fingerprint a9bf884a363b… — three-occurrence post-recycle reconnect
                        // twin of c2bf6b539a62… / 782d6308… / 003657d51ecd… / b9dc4dd1a8ef… /
                        // 7b6a047263d8… / 87f7f1566c88… against the same d467c210… leaf at
                        // 18:45:56Z on 127.0.0.1:54434, 18:49:56Z on 127.0.0.1:35776, and
                        // 18:50:56Z on 127.0.0.1:34540 after bare control-NATS RestartAsync
                        // reloads the same expired controller leaf;
                        // cid 36 → 68 → 77 → 52 for CN=gru-controller-1 on gru-control-nats-1,
                        // fingerprint 25b92b919c66… — four-occurrence post-recycle reconnect
                        // twin of c2bf6b539a62… / 782d6308… / 003657d51ecd… / b9dc4dd1a8ef… /
                        // 7b6a047263d8… / 87f7f1566c88… / a9bf884a363b… against the same
                        // d467c210… leaf at 18:46:00Z on 127.0.0.1:54442, 18:47:00Z on
                        // 127.0.0.1:57286, 18:49:00Z on 127.0.0.1:46044, and 18:50:00Z on
                        // 127.0.0.1:35784 after bare control-NATS RestartAsync reloads the
                        // same expired controller leaf;
                        // cid 38 → 70 for CN=gru-controller-1 on gru-control-nats-1,
                        // fingerprint 34c89dedb769… — two-occurrence post-recycle reconnect
                        // twin of c2bf6b539a62… / 782d6308… / 003657d51ecd… / b9dc4dd1a8ef… /
                        // 7b6a047263d8… / 87f7f1566c88… / a9bf884a363b… / 25b92b919c66… against
                        // the same d467c210… leaf at 18:46:01Z on 127.0.0.1:54492 and
                        // 18:47:01Z on 127.0.0.1:57318 after bare control-NATS RestartAsync
                        // reloads the same expired controller leaf (gru peer of sfo
                        // 3db5efff618c… cid 36+38 / 69 at the same wall-clock :01 steps);
                        // cid 39 → 71 → 80 → 55 for CN=gru-controller-1 on gru-control-nats-1,
                        // fingerprint 024cbd22bdf4… — four-occurrence post-recycle reconnect
                        // twin of c2bf6b539a62… / 782d6308… / 003657d51ecd… / b9dc4dd1a8ef… /
                        // 7b6a047263d8… / 87f7f1566c88… / a9bf884a363b… / 25b92b919c66… /
                        // 34c89dedb769… against the same d467c210… leaf at 18:46:05Z on
                        // 127.0.0.1:48986, 18:47:05Z on 127.0.0.1:42886, 18:49:05Z on
                        // 127.0.0.1:51702, and 18:50:05Z on 127.0.0.1:35504 after bare
                        // control-NATS RestartAsync reloads the same expired controller leaf;
                        // cid 41 → 73 for CN=gru-controller-1 on gru-control-nats-1,
                        // fingerprint e7ad7a71e395… — two-occurrence post-recycle reconnect
                        // twin of c2bf6b539a62… / 782d6308… / 003657d51ecd… / b9dc4dd1a8ef… /
                        // 7b6a047263d8… / 87f7f1566c88… / a9bf884a363b… / 25b92b919c66… /
                        // 34c89dedb769… / 024cbd22bdf4… against the same d467c210… leaf at
                        // 18:46:07Z on 127.0.0.1:49008 and 18:47:07Z on 127.0.0.1:42932 after
                        // bare control-NATS RestartAsync reloads the same expired controller
                        // leaf (gru peer of operator-read 5c56829c01e4… cid 40 → 72 / sfo
                        // 58dda0785551… / fra d26af782af24… / fra-controller 88eec19ebb94… /
                        // sfo-platform ef71b6e32493… / gru-platform 0401b56675fd… at the same
                        // wall-clock :07 steps);
                        // cid 42 → 74 → 50 → 51 → 81 → 83 → 58 for CN=gru-controller-1 on
                        // gru-control-nats-1, fingerprint 96fe8dda09bb… — seven-occurrence
                        // post-recycle reconnect twin of c2bf6b539a62… / 782d6308… /
                        // 003657d51ecd… / b9dc4dd1a8ef… / 7b6a047263d8… / 87f7f1566c88… /
                        // a9bf884a363b… / 25b92b919c66… / 34c89dedb769… / 024cbd22bdf4… /
                        // e7ad7a71e395… against the same d467c210… leaf at 18:46:10Z on
                        // 127.0.0.1:49018, 18:47:10Z on 127.0.0.1:42948, 18:48:10Z on
                        // 127.0.0.1:40182 / 127.0.0.1:40194 dual, 18:49:10Z on 127.0.0.1:51716 /
                        // 127.0.0.1:51744 dual, and 18:50:10Z on 127.0.0.1:35554 after bare
                        // control-NATS RestartAsync reloads the same expired controller leaf;
                        // cid 44 → 76 → 28 for CN=gru-controller-1 on gru-control-nats-1,
                        // fingerprint d2538c612184… — three-occurrence post-recycle reconnect
                        // twin of c2bf6b539a62… / 782d6308… / 003657d51ecd… / b9dc4dd1a8ef… /
                        // 7b6a047263d8… / 87f7f1566c88… / a9bf884a363b… / 25b92b919c66… /
                        // 34c89dedb769… / 024cbd22bdf4… / e7ad7a71e395… / 96fe8dda09bb… against
                        // the same d467c210… leaf at 18:46:13Z on 127.0.0.1:49052, 18:47:13Z on
                        // 127.0.0.1:42988, and 18:49:13Z on 127.0.0.1:51756 after bare
                        // control-NATS RestartAsync reloads the same expired controller leaf
                        // (three-seconds-later sparse twin of 96fe8dda09bb… on adjacent ports
                        // 49018 → 49052 / 42948 → 42988 / 51716 → 51756; control-plane peer of
                        // fra-controller 7063631384a4… cid 44 → 74 → 76 → 83 and product-plane
                        // peer of gru-platform 88ff8c404d3b… cid 51 → 90 at the same wall-clock
                        // :13 steps);
                        // cid 45 → 77 → 52 → 54 → 29 → 60 → 61 for CN=gru-controller-1 on
                        // gru-control-nats-1, fingerprint d00ef05a1026… — seven-occurrence
                        // post-recycle reconnect twin of c2bf6b539a62… / 782d6308… /
                        // 003657d51ecd… / b9dc4dd1a8ef… / 7b6a047263d8… / 87f7f1566c88… /
                        // a9bf884a363b… / 25b92b919c66… / 34c89dedb769… / 024cbd22bdf4… /
                        // e7ad7a71e395… / 96fe8dda09bb… / d2538c612184… against the same
                        // d467c210… leaf at 18:46:15Z on 127.0.0.1:37246, 18:47:15Z on
                        // 127.0.0.1:34118, 18:48:15Z on 127.0.0.1:52154 / 127.0.0.1:52194 dual,
                        // 18:49:15Z on 127.0.0.1:45258, and 18:50:15Z on 127.0.0.1:57522 /
                        // 127.0.0.1:57524 dual after bare control-NATS RestartAsync reloads the
                        // same expired controller leaf (two-seconds-later denser twin of
                        // d2538c612184… on ports 37246 / 34118 / 52154 / 52194 / 45258 / 57522 /
                        // 57524; denser seven-occurrence peer of 96fe8dda09bb… cid 42 → 74 →
                        // 50 → 51 → 81 → 83 → 58 at the adjacent wall-clock :10 steps);
                        // cid 47 → 79 → 31 for CN=gru-controller-1 on gru-control-nats-1,
                        // fingerprint d56bf3307e7b… — three-occurrence post-recycle reconnect twin
                        // of c2bf6b539a62… / 782d6308… / 003657d51ecd… / b9dc4dd1a8ef… /
                        // 7b6a047263d8… / 87f7f1566c88… / a9bf884a363b… / 25b92b919c66… /
                        // 34c89dedb769… / 024cbd22bdf4… / e7ad7a71e395… / 96fe8dda09bb… /
                        // d2538c612184… / d00ef05a1026… against the same d467c210… leaf at
                        // 18:46:19Z on 127.0.0.1:37282, 18:47:19Z on 127.0.0.1:34142, and
                        // 18:49:19Z on 127.0.0.1:45312 after bare control-NATS RestartAsync
                        // reloads the same expired controller leaf (four seconds after
                        // d00ef05a1026… cid 45 on adjacent :15 steps / ports 37246 → 37282 and
                        // 34118 → 34142; gru peer of sfo 1cdbb448aebb… cid 47 → 79 → 31 and
                        // fra 4cab25065be5… cid 47 → 79 → 30 at the same wall-clock :19 steps,
                        // concurrent with gru-platform 1f9106a25f41… / sfo-platform 1668f8c0e10f… /
                        // fra-platform 59a0656971a4… / gru operator-read 5807fcff9600… at the same
                        // wall-clock :19 steps);
                        // cid 48 → 55 → 32 → 62 for CN=gru-controller-1 on gru-control-nats-1,
                        // fingerprint e51d12dd4525… — four-occurrence post-recycle reconnect twin
                        // of c2bf6b539a62… / 782d6308… / 003657d51ecd… / b9dc4dd1a8ef… /
                        // 7b6a047263d8… / 87f7f1566c88… / a9bf884a363b… / 25b92b919c66… /
                        // 34c89dedb769… / 024cbd22bdf4… / e7ad7a71e395… / 96fe8dda09bb… /
                        // d2538c612184… / d00ef05a1026… / d56bf3307e7b… against the same
                        // d467c210… leaf at 18:46:20Z on 127.0.0.1:37298, 18:48:20Z on
                        // 127.0.0.1:52196, 18:49:20Z on 127.0.0.1:45314, and 18:50:20Z on
                        // 127.0.0.1:57526 after bare control-NATS RestartAsync reloads the same
                        // expired controller leaf (one second after d56bf3307e7b… cid 47 → 79 → 31
                        // on adjacent :19 steps / ports 37282 → 37298 and 45312 → 45314, and
                        // five seconds after d00ef05a1026… dual ports 52154/52194 → 52196 and
                        // 57522/57524 → 57526 at the :15/:20 wall-clock pair);
                        // cid 49 → 82 → 58 → 33 → 35 → 65 for CN=gru-controller-1 on
                        // gru-control-nats-1, fingerprint 73ac000434f0… — six-occurrence
                        // post-recycle reconnect twin of c2bf6b539a62… / 782d6308… /
                        // 003657d51ecd… / b9dc4dd1a8ef… / 7b6a047263d8… / 87f7f1566c88… /
                        // a9bf884a363b… / 25b92b919c66… / 34c89dedb769… / 024cbd22bdf4… /
                        // e7ad7a71e395… / 96fe8dda09bb… / d2538c612184… / d00ef05a1026… /
                        // d56bf3307e7b… / e51d12dd4525… against the same d467c210… leaf at
                        // 18:46:25Z on 127.0.0.1:46536, 18:47:25Z on 127.0.0.1:55148,
                        // 18:48:25Z on 127.0.0.1:44408, 18:49:25Z on 127.0.0.1:38192 /
                        // 127.0.0.1:38210 dual (cid 33+35), and 18:50:25Z on 127.0.0.1:56214
                        // after bare control-NATS RestartAsync reloads the same expired
                        // controller leaf (five seconds after e51d12dd4525… cid 48 → 55 → 32 →
                        // 62 on adjacent :20 steps);
                        // cid 51 → 83 for CN=gru-controller-1 on gru-control-nats-1,
                        // fingerprint 1455d09f7030… — two-occurrence post-recycle reconnect
                        // twin of c2bf6b539a62… / 782d6308… / 003657d51ecd… / b9dc4dd1a8ef… /
                        // 7b6a047263d8… / 87f7f1566c88… / a9bf884a363b… / 25b92b919c66… /
                        // 34c89dedb769… / 024cbd22bdf4… / e7ad7a71e395… / 96fe8dda09bb… /
                        // d2538c612184… / d00ef05a1026… / d56bf3307e7b… / e51d12dd4525… /
                        // 73ac000434f0… against the same d467c210… leaf at 18:46:26Z on
                        // 127.0.0.1:46574 and 18:47:26Z on 127.0.0.1:55160 after bare
                        // control-NATS RestartAsync reloads the same expired controller leaf
                        // (one second after 73ac000434f0… cid 49 → 82 on adjacent :25 steps /
                        // ports 46536 → 46574 and 55148 → 55160);
                        // cid 29238 → 62 → 69 → 70 for CN=fra-controller-1 on fra-control-nats-1,
                        // fingerprint 91b5b852… — fra twin of the sfo/gru controller storms:
                        // long-running fra-controller-1 reconnects while bare control-NATS
                        // RestartAsync reloads the same expired controller leaf;
                        // cid 29240 → 34 → 66 → 73 for CN=fra-controller-1 on fra-control-nats-1,
                        // fingerprint ffcef075c58c… — denser four-occurrence twin of 91b5b852…
                        // against the same 8f6e801c… leaf at 18:45:40Z / 18:47:40Z /
                        // 18:48:40Z / 18:50:40Z: long-running fra-controller-1 reconnects while
                        // bare control-NATS RestartAsync reloads the same expired controller leaf;
                        // cid 28 → 37 → 69 → 76 for CN=fra-controller-1 on fra-control-nats-1,
                        // fingerprint bca21682b315… — four-occurrence post-recycle reconnect twin
                        // of 91b5b852… / ffcef075c58c… (and gru b9dc4dd1a8ef…) against the same
                        // 8f6e801c… leaf at 18:45:46Z on 127.0.0.1:34624, 18:47:46Z on
                        // 127.0.0.1:60304, 18:48:46Z on 127.0.0.1:50796, and 18:50:46Z on
                        // 127.0.0.1:54352 after bare control-NATS RestartAsync reloads the same
                        // expired controller leaf;
                        // cid:29 for CN=fra-controller-1 on fra-control-nats-1,
                        // fingerprint 23eafce842f6… — single post-recycle reconnect twin of
                        // 91b5b852… / ffcef075c58c… / bca21682b315… (and gru b9dc4dd1a8ef… /
                        // sfo e8e55fe0bef9… leading cid 29) against the same 8f6e801c… leaf at
                        // 18:45:48Z on 127.0.0.1:34626 after bare control-NATS RestartAsync
                        // reloads the same expired controller leaf;
                        // cid 31 → 47 for CN=fra-controller-1 on fra-control-nats-1,
                        // fingerprint 4046b92fa615… — two-occurrence post-recycle reconnect twin
                        // of 91b5b852… / ffcef075c58c… / bca21682b315… / 23eafce842f6… (and sfo
                        // 412baaa56842… cid 31/47 steps, operator-read twins f4f92376efda… /
                        // 62860f83eeb6… at the same wall-clock pair) against the same 8f6e801c…
                        // leaf at 18:45:50Z on 127.0.0.1:34668 and 18:49:50Z on 127.0.0.1:33784
                        // after bare control-NATS RestartAsync reloads the same expired
                        // controller leaf;
                        // cid 32 → 64 → 41 → 72 → 73 → 48 → 79 for CN=fra-controller-1 on
                        // fra-control-nats-1, fingerprint 87c737a0ed10… — seven-occurrence
                        // post-recycle reconnect twin of 91b5b852… / ffcef075c58c… /
                        // bca21682b315… / 23eafce842f6… / 4046b92fa615… (and sfo 71cf8514f4d6…
                        // cid 32/41/48 steps, gru-platform b22018f7aa7b… at adjacent wall-clock
                        // :52 steps) against the same 8f6e801c… leaf at 18:45:52Z on
                        // 127.0.0.1:34674, 18:46:52Z on 127.0.0.1:53654, 18:47:52Z on
                        // 127.0.0.1:60380, 18:48:52Z on 127.0.0.1:50844 / 50858 (dual cid 72+73),
                        // 18:49:52Z on 127.0.0.1:33786, and 18:50:52Z on 127.0.0.1:54412 after
                        // bare control-NATS RestartAsync reloads the same expired controller leaf;
                        // cid 34 → 50 for CN=fra-controller-1 on fra-control-nats-1,
                        // fingerprint 5e5b835252fe… — two-occurrence post-recycle reconnect twin
                        // of 91b5b852… / ffcef075c58c… / bca21682b315… / 23eafce842f6… /
                        // 4046b92fa615… / 87c737a0ed10… (and gru a9bf884a363b… cid 35/50 steps at
                        // the same wall-clock :56 pair) against the same 8f6e801c… leaf at
                        // 18:45:56Z on 127.0.0.1:43900 and 18:49:56Z on 127.0.0.1:37150 after
                        // bare control-NATS RestartAsync reloads the same expired controller leaf;
                        // cid 35 → 42 → 44 → 51 for CN=fra-controller-1 on fra-control-nats-1,
                        // fingerprint 6e08a77cd4b6… — four-occurrence post-recycle reconnect twin
                        // of 91b5b852… / ffcef075c58c… / bca21682b315… / 23eafce842f6… /
                        // 4046b92fa615… / 87c737a0ed10… / 5e5b835252fe… (and gru a9bf884a363b… /
                        // sfo-platform 9b960cc93f83… at adjacent wall-clock :56/:57 steps) against
                        // the same 8f6e801c… leaf at 18:45:57Z on 127.0.0.1:43906, 18:47:57Z on
                        // 127.0.0.1:44698 / 127.0.0.1:44730 (dual cid 42+44), and 18:49:57Z on
                        // 127.0.0.1:37152 after bare control-NATS RestartAsync reloads the same
                        // expired controller leaf;
                        // cid 37 → 69 for CN=fra-controller-1 on fra-control-nats-1,
                        // fingerprint 876de6711801… — two-occurrence post-recycle reconnect twin
                        // of 91b5b852… / ffcef075c58c… / bca21682b315… / 23eafce842f6… /
                        // 4046b92fa615… / 87c737a0ed10… / 5e5b835252fe… / 6e08a77cd4b6… against
                        // the same 8f6e801c… leaf at 18:46:01Z on 127.0.0.1:43944 and 18:47:01Z
                        // on 127.0.0.1:42784 after bare control-NATS RestartAsync reloads the
                        // same expired controller leaf (fra peer of gru 34c89dedb769… cid 38 → 70
                        // and sfo 3db5efff618c… cid 36+38 / 69 at the same wall-clock :01 steps);
                        // cid 38 → 45 → 52 for CN=fra-controller-1 on fra-control-nats-1,
                        // fingerprint 52a227218acf… — three-occurrence post-recycle reconnect twin
                        // of 91b5b852… / ffcef075c58c… / bca21682b315… / 23eafce842f6… /
                        // 4046b92fa615… / 87c737a0ed10… / 5e5b835252fe… / 6e08a77cd4b6… /
                        // 876de6711801… against the same 8f6e801c… leaf at 18:46:02Z on
                        // 127.0.0.1:43948, 18:48:02Z on 127.0.0.1:44744, and 18:50:02Z on
                        // 127.0.0.1:37162 after bare control-NATS RestartAsync reloads the same
                        // expired controller leaf (adjacent :02 second after 876de6711801… cid 37
                        // at 18:46:01Z on nearby 43944, with ~2 min reconnect gaps matching the
                        // denser 91b5b852… / ffcef075c58c… wall-clock cadence);
                        // cid 39 → 41 → 72 → 48 → 55 for CN=fra-controller-1 on fra-control-nats-1,
                        // fingerprint 88eec19ebb94… — five-occurrence post-recycle reconnect twin
                        // of 91b5b852… / ffcef075c58c… / bca21682b315… / 23eafce842f6… /
                        // 4046b92fa615… / 87c737a0ed10… / 5e5b835252fe… / 6e08a77cd4b6… /
                        // 876de6711801… / 52a227218acf… against the same 8f6e801c… leaf at
                        // 18:46:07Z on 127.0.0.1:48674 / 127.0.0.1:48694 (dual cid 39+41),
                        // 18:47:07Z on 127.0.0.1:46502, 18:48:07Z on 127.0.0.1:55402, and
                        // 18:50:07Z on 127.0.0.1:60620 after bare control-NATS RestartAsync
                        // reloads the same expired controller leaf (fra peer of gru
                        // 024cbd22bdf4… cid 39 → 71 → 80 → 55 at adjacent wall-clock :05 steps);
                        // cid 42 → 51 → 58 for CN=fra-controller-1 on fra-control-nats-1,
                        // fingerprint 49ec50da2e2a… — three-occurrence post-recycle reconnect twin
                        // of 91b5b852… / ffcef075c58c… / bca21682b315… / 23eafce842f6… /
                        // 4046b92fa615… / 87c737a0ed10… / 5e5b835252fe… / 6e08a77cd4b6… /
                        // 876de6711801… / 52a227218acf… / 88eec19ebb94… against the same 8f6e801c…
                        // leaf at 18:46:12Z on 127.0.0.1:48696, 18:48:12Z on 127.0.0.1:55440, and
                        // 18:50:12Z on 127.0.0.1:60662 after bare control-NATS RestartAsync
                        // reloads the same expired controller leaf (sparse five-seconds-later twin
                        // of 88eec19ebb94… on adjacent ports 48674/48694 → 48696, 55402 → 55440,
                        // 60620 → 60662; fra peer of sfo 914b99d5fbc6… cid 42 → 83 → 58 at the
                        // adjacent :11 steps and gru 96fe8dda09bb… cid 42 → 74 → 50 → 51 → 81 →
                        // 83 → 58 at the adjacent :10/:11 steps);
                        // cid 44 → 74 → 76 → 83 for CN=fra-controller-1 on fra-control-nats-1,
                        // fingerprint 7063631384a4… — four-occurrence post-recycle reconnect twin
                        // of 91b5b852… / ffcef075c58c… / bca21682b315… / 23eafce842f6… /
                        // 4046b92fa615… / 87c737a0ed10… / 5e5b835252fe… / 6e08a77cd4b6… /
                        // 876de6711801… / 52a227218acf… / 88eec19ebb94… / 49ec50da2e2a… against
                        // the same 8f6e801c… leaf at 18:46:13Z on 127.0.0.1:48726, 18:47:13Z on
                        // 127.0.0.1:46524 / 127.0.0.1:46564 (dual cid 74+76), and 18:49:13Z on
                        // 127.0.0.1:52176 after bare control-NATS RestartAsync reloads the same
                        // expired controller leaf (one-second-later twin of 49ec50da2e2a… on
                        // adjacent port 48696 → 48726; denser mid-window dual reconnect than the
                        // sparse :12 triple; product-plane peer of gru-platform 88ff8c404d3b…
                        // cid 51 → 90 at the same wall-clock :13 steps);
                        // cid 45 → 54 → 61 for CN=fra-controller-1 on fra-control-nats-1,
                        // fingerprint d7de94966c92… — three-occurrence post-recycle reconnect twin
                        // of 91b5b852… / ffcef075c58c… / bca21682b315… / 23eafce842f6… /
                        // 4046b92fa615… / 87c737a0ed10… / 5e5b835252fe… / 6e08a77cd4b6… /
                        // 876de6711801… / 52a227218acf… / 88eec19ebb94… / 49ec50da2e2a… /
                        // 7063631384a4… against the same 8f6e801c… leaf at 18:46:17Z on
                        // 127.0.0.1:45396, 18:48:17Z on 127.0.0.1:33434, and 18:50:17Z on
                        // 127.0.0.1:58410 after bare control-NATS RestartAsync reloads the same
                        // expired controller leaf (four seconds after 7063631384a4… cid 44 on
                        // adjacent :13 steps; fra peer of sfo bbdb6e0d6006… cid 45 → 29 → 61 at
                        // the adjacent wall-clock :16 steps and gru d00ef05a1026… cid 45 → 77 →
                        // 52 → 54 → 29 → 60 → 61 at the adjacent wall-clock :15 steps; product-
                        // plane peer of fra-platform ec156a1db321… cid 52 → 91 at the same
                        // wall-clock :17 steps);
                        // cid 47 → 79 → 30 for CN=fra-controller-1 on fra-control-nats-1,
                        // fingerprint 4cab25065be5… — three-occurrence post-recycle reconnect twin
                        // of 91b5b852… / ffcef075c58c… / bca21682b315… / 23eafce842f6… /
                        // 4046b92fa615… / 87c737a0ed10… / 5e5b835252fe… / 6e08a77cd4b6… /
                        // 876de6711801… / 52a227218acf… / 88eec19ebb94… / 49ec50da2e2a… /
                        // 7063631384a4… / d7de94966c92… against the same 8f6e801c… leaf at
                        // 18:46:19Z on 127.0.0.1:45434, 18:47:19Z on 127.0.0.1:34540, and
                        // 18:49:19Z on 127.0.0.1:44862 after bare control-NATS RestartAsync
                        // reloads the same expired controller leaf (two seconds after
                        // d7de94966c92… cid 45 on adjacent :17 steps / ports 45396 → 45434;
                        // fra peer of sfo 1cdbb448aebb… cid 47 → 79 → 31 at the same wall-clock
                        // :19 steps, concurrent with gru-platform 1f9106a25f41… /
                        // sfo-platform 1668f8c0e10f… / fra-platform 59a0656971a4… /
                        // gru operator-read 5807fcff9600… at the same wall-clock :19 steps);
                        // cid 48 → 57 for CN=fra-controller-1 on fra-control-nats-1,
                        // fingerprint 4aa0ebad5b5b… — two-occurrence post-recycle reconnect twin
                        // of 91b5b852… / ffcef075c58c… / bca21682b315… / 23eafce842f6… /
                        // 4046b92fa615… / 87c737a0ed10… / 5e5b835252fe… / 6e08a77cd4b6… /
                        // 876de6711801… / 52a227218acf… / 88eec19ebb94… / 49ec50da2e2a… /
                        // 7063631384a4… / d7de94966c92… / 4cab25065be5… against the same
                        // 8f6e801c… leaf at 18:46:22Z on 127.0.0.1:45440 and 18:48:22Z on
                        // 127.0.0.1:33458 after bare control-NATS RestartAsync reloads the same
                        // expired controller leaf (three seconds after 4cab25065be5… cid 47 on
                        // adjacent :19 steps / ports 45434 → 45440; fra peer of sfo
                        // 2e80728c5df4… cid 48 → 57 → 63 → 64 at the adjacent wall-clock :21
                        // steps and gru e51d12dd4525… cid 48 → 55 → 32 → 62 at the adjacent
                        // wall-clock :20 steps);
                        // cid 14634 → 63 → 50 → 43 for CN=fra-platform on fra-product-nats-1,
                        // fingerprint 25ef0004168c… — product-plane twin: platform process
                        // reconnects while bare product-NATS RestartAsync reloads the same
                        // expired leaf;
                        // cid 14635 → 67 → 38 → 51 → 44 for CN=fra-platform on fra-product-nats-1,
                        // fingerprint dacc95d0e7ba… — denser five-occurrence twin of
                        // 25ef0004168c… against the same 7ef9d0a4… leaf at 18:45:40Z /
                        // 18:46:40Z / 18:47:40Z / 18:48:40Z / 18:50:40Z: long-running
                        // fra-platform reconnects while bare product-NATS RestartAsync
                        // reloads the same expired platform leaf;
                        // cid:31 for CN=fra-platform on fra-product-nats-1,
                        // fingerprint 1e8b88f75d43… — single post-recycle reconnect twin of
                        // 25ef0004168c… / dacc95d0e7ba… (and gru 0b23b4fb5a75… / sfo
                        // d739f8d83bed…) against the same 7ef9d0a4… leaf at 18:45:45Z on
                        // 127.0.0.1:34466 after bare product-NATS RestartAsync reloads the
                        // same expired platform leaf;
                        // cid 32 → 71 → 41 → 42 → 52 → 45 for CN=fra-platform on fra-product-nats-1,
                        // fingerprint 30e9c320e15b… — six-occurrence post-recycle reconnect twin
                        // of 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… (and gru 0cbc78bc3a3a…)
                        // against the same 7ef9d0a4… leaf at 18:45:46Z on 127.0.0.1:34468,
                        // 18:46:46Z on 127.0.0.1:45732, 18:47:46Z on 127.0.0.1:49922 / 49934
                        // (dual cid 41+42), 18:48:46Z on 127.0.0.1:44248, and 18:50:46Z on
                        // 127.0.0.1:58440 after bare product-NATS RestartAsync reloads the same
                        // expired platform leaf;
                        // cid 33 → 72 for CN=fra-platform on fra-product-nats-1,
                        // fingerprint fc4e0317d2a1… — two-occurrence post-recycle reconnect twin
                        // of 30e9c320e15b… / 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… (and
                        // gru 6a1c43a93378…) against the same 7ef9d0a4… leaf at 18:45:48Z on
                        // 127.0.0.1:34476 and 18:46:48Z on 127.0.0.1:45738 after bare
                        // product-NATS RestartAsync reloads the same expired platform leaf;
                        // cid 34 → 35 → 74 → 36 for CN=fra-platform on fra-product-nats-1,
                        // fingerprint 92ed0baffd5b… — four-occurrence post-recycle reconnect twin
                        // of fc4e0317d2a1… / 30e9c320e15b… / 25ef0004168c… / dacc95d0e7ba… /
                        // 1e8b88f75d43… (and gru ed3f4504d5e1… / sfo 146c64f3fc52… / operator-read
                        // twins f4f92376efda… / 62860f83eeb6… / 7421834a4183… at the same
                        // wall-clock pair) against the same 7ef9d0a4… leaf at 18:45:50Z on
                        // 127.0.0.1:34504 / 34506 (dual cid 34+35), 18:46:50Z on 127.0.0.1:45768,
                        // and 18:49:50Z on 127.0.0.1:59726 after bare product-NATS RestartAsync
                        // reloads the same expired platform leaf;
                        // cid 36 → 75 → 53 → 46 for CN=fra-platform on fra-product-nats-1,
                        // fingerprint 7904dd055f87… — four-occurrence post-recycle reconnect twin
                        // of 92ed0baffd5b… / fc4e0317d2a1… / 30e9c320e15b… / 25ef0004168c… /
                        // dacc95d0e7ba… / 1e8b88f75d43… (and gru b22018f7aa7b… at the same
                        // wall-clock :52 steps) against the same 7ef9d0a4… leaf at 18:45:52Z on
                        // 127.0.0.1:34510, 18:46:52Z on 127.0.0.1:45778, 18:48:52Z on
                        // 127.0.0.1:44268, and 18:50:52Z on 127.0.0.1:58444 after bare
                        // product-NATS RestartAsync reloads the same expired platform leaf;
                        // cid 37 → 76 for CN=fra-platform on fra-product-nats-1,
                        // fingerprint 5804cb3aaf61… — two-occurrence post-recycle reconnect twin
                        // of 7904dd055f87… / 92ed0baffd5b… / fc4e0317d2a1… / 30e9c320e15b… /
                        // 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… (and gru 9371738eec92… /
                        // b22018f7aa7b… / sfo e33d87402e17… / operator-read twins at adjacent
                        // wall-clock :52/:53/:54 steps) against the same 7ef9d0a4… leaf at
                        // 18:45:54Z on 127.0.0.1:50978 and 18:46:54Z on 127.0.0.1:38754 after
                        // bare product-NATS RestartAsync reloads the same expired platform leaf;
                        // cid 38 → 39 → 78 → 37 for CN=fra-platform on fra-product-nats-1,
                        // fingerprint 5d30a28d7f44… — four-occurrence post-recycle reconnect twin
                        // of 5804cb3aaf61… / 7904dd055f87… / 92ed0baffd5b… / fc4e0317d2a1… /
                        // 30e9c320e15b… / 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… (and
                        // gru be7bee33b946… / sfo 26b95f54769c… / gru operator-read b252d8996050… /
                        // gru-controller a9bf884a363b… / sfo operator-read 97d33257778a… /
                        // fra operator-read c74671d2c0e4… / fra-controller 5e5b835252fe… at the
                        // same wall-clock :56 steps) against the same 7ef9d0a4… leaf at
                        // 18:45:56Z on 127.0.0.1:51008 / 127.0.0.1:51016 (dual cid 38+39),
                        // 18:46:56Z on 127.0.0.1:38782, and 18:49:56Z on 127.0.0.1:52794 after
                        // bare product-NATS RestartAsync reloads the same expired platform leaf;
                        // cid 40 → 79 → 54 for CN=fra-platform on fra-product-nats-1,
                        // fingerprint 639501fa4228… — three-occurrence post-recycle reconnect twin
                        // of 5d30a28d7f44… / 5804cb3aaf61… / 7904dd055f87… / 92ed0baffd5b… /
                        // fc4e0317d2a1… / 30e9c320e15b… / 25ef0004168c… / dacc95d0e7ba… /
                        // 1e8b88f75d43… (and gru a2e01c16a27c… / sfo 9b960cc93f83… / gru
                        // operator-read b252d8996050… / gru-controller a9bf884a363b… / sfo
                        // operator-read 97d33257778a… / fra operator-read c74671d2c0e4… at
                        // adjacent wall-clock :56/:57/:58 steps) against the same 7ef9d0a4…
                        // leaf at 18:45:58Z on 127.0.0.1:51030, 18:46:58Z on 127.0.0.1:38798,
                        // and 18:48:58Z on 127.0.0.1:38302 after bare product-NATS RestartAsync
                        // reloads the same expired platform leaf;
                        // cid 41 → 80 for CN=fra-platform on fra-product-nats-1,
                        // fingerprint eebfa17cec6b… — two-occurrence post-recycle reconnect twin
                        // of 639501fa4228… / 5d30a28d7f44… / 5804cb3aaf61… / 7904dd055f87… /
                        // 92ed0baffd5b… / fc4e0317d2a1… / 30e9c320e15b… / 25ef0004168c… /
                        // dacc95d0e7ba… / 1e8b88f75d43… (and gru 764b28c3439a… / gru
                        // a2e01c16a27c… / sfo 9b960cc93f83… / gru operator-read b252d8996050… /
                        // gru-controller a9bf884a363b… / 25b92b919c66… / sfo operator-read
                        // 97d33257778a… / fra operator-read c74671d2c0e4… at the same wall-clock
                        // 18:46:00Z / 18:47:00Z steps) against the same 7ef9d0a4… leaf at
                        // 18:46:00Z on 127.0.0.1:51046 and 18:47:00Z on 127.0.0.1:38810 after
                        // bare product-NATS RestartAsync reloads the same expired platform leaf;
                        // cid 42 → 81 for CN=fra-platform on fra-product-nats-1,
                        // fingerprint 669e26dad203… — two-occurrence post-recycle reconnect twin
                        // of eebfa17cec6b… / 639501fa4228… / 5d30a28d7f44… / 5804cb3aaf61… /
                        // 7904dd055f87… / 92ed0baffd5b… / fc4e0317d2a1… / 30e9c320e15b… /
                        // 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… (and gru 6d84bda1e560…
                        // cid 43 → 82 / gru 764b28c3439a… cid 42 → 81 / sfo eacb3282ca0c… dual
                        // cid 41+42 → 80+81 at the same wall-clock 18:46:01Z / 18:47:01Z steps)
                        // against the same 7ef9d0a4… leaf at 18:46:01Z on 127.0.0.1:51068 and
                        // 18:47:01Z on 127.0.0.1:38828 after bare product-NATS RestartAsync
                        // reloads the same expired platform leaf;
                        // cid 43 → 38 for CN=fra-platform on fra-product-nats-1,
                        // fingerprint 67d134aeab25… — two-occurrence sparse post-recycle reconnect
                        // twin of 669e26dad203… / eebfa17cec6b… / 639501fa4228… / 5d30a28d7f44… /
                        // 5804cb3aaf61… / 7904dd055f87… / 92ed0baffd5b… / fc4e0317d2a1… /
                        // 30e9c320e15b… / 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… (and gru
                        // 6d84bda1e560… cid 43 → 82 / gru 764b28c3439a… cid 42 → 81 / sfo
                        // eacb3282ca0c… dual cid 41+42 → 80+81 at the adjacent wall-clock
                        // 18:46:01Z / 18:47:01Z steps) against the same 7ef9d0a4… leaf at
                        // 18:46:03Z on 127.0.0.1:51072 and 18:50:03Z on 127.0.0.1:52810 after
                        // bare product-NATS RestartAsync reloads the same expired platform leaf;
                        // cid:44 for CN=fra-platform on fra-product-nats-1,
                        // fingerprint b8e719ba13ca… — single-occurrence post-recycle reconnect twin
                        // of 67d134aeab25… / 669e26dad203… / eebfa17cec6b… / 639501fa4228… /
                        // 5d30a28d7f44… / 5804cb3aaf61… / 7904dd055f87… / 92ed0baffd5b… /
                        // fc4e0317d2a1… / 30e9c320e15b… / 25ef0004168c… / dacc95d0e7ba… /
                        // 1e8b88f75d43… (and gru 3f4dc73e62f2… cid 45 → 84 → 44 → 54 / gru
                        // 5990e53d2fde… cid 44 → 83 / sfo c907c56a7c0c… cid 43 → 82 → 38 at the
                        // adjacent wall-clock 18:46:02Z / 18:46:03Z / 18:46:04Z / 18:46:05Z steps)
                        // against the same 7ef9d0a4… leaf at 18:46:05Z on 127.0.0.1:38810 after
                        // bare product-NATS RestartAsync reloads the same expired platform leaf;
                        // cid 45 → 46 → 84 → 85 for CN=fra-platform on fra-product-nats-1,
                        // fingerprint aae9c8a6b484… — four-occurrence dual-cid post-recycle
                        // reconnect twin of b8e719ba13ca… / 67d134aeab25… / 669e26dad203… /
                        // eebfa17cec6b… / 639501fa4228… / 5d30a28d7f44… / 5804cb3aaf61… /
                        // 7904dd055f87… / 92ed0baffd5b… / fc4e0317d2a1… / 30e9c320e15b… /
                        // 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… (and gru e962f4a49508…
                        // cid 46 → 85 / gru 3f4dc73e62f2… cid 45 → 84 → 44 → 54 / gru
                        // 5990e53d2fde… cid 44 → 83 / sfo b439248687d8… cid 44 → 83 / sfo
                        // c907c56a7c0c… cid 43 → 82 → 38 at the adjacent wall-clock 18:46:02Z /
                        // 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z /
                        // 18:47:02Z / 18:47:05Z / 18:47:06Z / 18:47:07Z steps) against the same
                        // 7ef9d0a4… leaf at 18:46:07Z on 127.0.0.1:38812 / 127.0.0.1:38824
                        // (dual cid 45+46) and 18:47:07Z on 127.0.0.1:40184 / 127.0.0.1:40196
                        // (dual cid 84+85) after bare product-NATS RestartAsync reloads the same
                        // expired platform leaf;
                        // cid 47 → 86 → 39 for CN=fra-platform on fra-product-nats-1,
                        // fingerprint a66e03d58e6a… — three-occurrence sparse post-recycle
                        // reconnect twin of aae9c8a6b484… / b8e719ba13ca… / 67d134aeab25… /
                        // 669e26dad203… / eebfa17cec6b… / 639501fa4228… / 5d30a28d7f44… /
                        // 5804cb3aaf61… / 7904dd055f87… / 92ed0baffd5b… / fc4e0317d2a1… /
                        // 30e9c320e15b… / 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… (and
                        // gru 6be7ec00050d… cid 48 → 87 / gru 0401b56675fd… cid 47 → 86 / gru
                        // e962f4a49508… cid 46 → 85 / gru 3f4dc73e62f2… cid 45 → 84 → 44 → 54 /
                        // gru 5990e53d2fde… cid 44 → 83 / sfo ef71b6e32493… dual cid 45+46 →
                        // 84+85 / sfo b439248687d8… cid 44 → 83 / sfo c907c56a7c0c… cid 43 →
                        // 82 → 38 at the adjacent wall-clock 18:46:03Z / 18:46:04Z / 18:46:05Z /
                        // 18:46:06Z / 18:46:07Z / 18:46:08Z / 18:46:09Z / 18:47:03Z / 18:47:04Z /
                        // 18:47:05Z / 18:47:06Z / 18:47:07Z / 18:47:08Z / 18:47:09Z / 18:50:09Z
                        // steps) against the same 7ef9d0a4… leaf at 18:46:09Z on
                        // 127.0.0.1:38828, 18:47:09Z on 127.0.0.1:40210, and 18:50:09Z on
                        // 127.0.0.1:48084 after bare product-NATS RestartAsync reloads the same
                        // expired platform leaf;
                        // cid 48 → 87 for CN=fra-platform on fra-product-nats-1,
                        // fingerprint a87539b37de1… — two-occurrence post-recycle reconnect twin
                        // of a66e03d58e6a… / aae9c8a6b484… / b8e719ba13ca… / 67d134aeab25… /
                        // 669e26dad203… / eebfa17cec6b… / 639501fa4228… / 5d30a28d7f44… /
                        // 5804cb3aaf61… / 7904dd055f87… / 92ed0baffd5b… / fc4e0317d2a1… /
                        // 30e9c320e15b… / 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… (and
                        // gru 8a0aaf8cb1da… cid 49 → 88 → 45 → 55 / gru 6be7ec00050d… cid 48 →
                        // 87 / gru 0401b56675fd… cid 47 → 86 / gru e962f4a49508… cid 46 → 85 /
                        // gru 3f4dc73e62f2… cid 45 → 84 → 44 → 54 / gru 5990e53d2fde… cid 44 →
                        // 83 / sfo 02525de8dfa3… cid 47 → 86 → 39 / sfo ef71b6e32493… dual cid
                        // 45+46 → 84+85 / sfo b439248687d8… cid 44 → 83 / sfo c907c56a7c0c…
                        // cid 43 → 82 → 38 at the adjacent wall-clock 18:46:03Z / 18:46:04Z /
                        // 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z / 18:46:09Z /
                        // 18:46:10Z / 18:46:11Z / 18:47:03Z / 18:47:04Z / 18:47:05Z /
                        // 18:47:06Z / 18:47:07Z / 18:47:08Z / 18:47:09Z / 18:47:10Z /
                        // 18:47:11Z / 18:50:09Z steps) against the same 7ef9d0a4… leaf at
                        // 18:46:11Z on 127.0.0.1:38842 and 18:47:11Z on 127.0.0.1:40216 after
                        // bare product-NATS RestartAsync reloads the same expired platform leaf;
                        // cid 49 → 50 → 88 → 89 for CN=fra-platform on fra-product-nats-1,
                        // fingerprint d86f81358e32… — four-occurrence dual-cid post-recycle
                        // reconnect twin of a87539b37de1… / a66e03d58e6a… / aae9c8a6b484… /
                        // b8e719ba13ca… / 67d134aeab25… / 669e26dad203… / eebfa17cec6b… /
                        // 639501fa4228… / 5d30a28d7f44… / 5804cb3aaf61… / 7904dd055f87… /
                        // 92ed0baffd5b… / fc4e0317d2a1… / 30e9c320e15b… / 25ef0004168c… /
                        // dacc95d0e7ba… / 1e8b88f75d43… (and gru 897b9ff7b37e… cid 50 → 89 /
                        // gru 8a0aaf8cb1da… cid 49 → 88 → 45 → 55 / gru 6be7ec00050d… cid 48 →
                        // 87 / gru 0401b56675fd… cid 47 → 86 / gru e962f4a49508… cid 46 → 85 /
                        // gru 3f4dc73e62f2… cid 45 → 84 → 44 → 54 / gru 5990e53d2fde… cid 44 →
                        // 83 / sfo 02525de8dfa3… cid 47 → 86 → 39 / sfo ef71b6e32493… dual cid
                        // 45+46 → 84+85 / sfo b439248687d8… cid 44 → 83 / sfo c907c56a7c0c…
                        // cid 43 → 82 → 38 at the adjacent wall-clock 18:46:03Z / 18:46:04Z /
                        // 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z / 18:46:09Z /
                        // 18:46:10Z / 18:46:11Z / 18:46:12Z / 18:46:13Z / 18:47:03Z /
                        // 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z / 18:47:08Z /
                        // 18:47:09Z / 18:47:10Z / 18:47:11Z / 18:47:12Z / 18:47:13Z /
                        // 18:48:10Z / 18:49:10Z / 18:50:09Z steps) against the same 7ef9d0a4…
                        // leaf at 18:46:13Z on 127.0.0.1:38852 / 127.0.0.1:38860 (dual cid
                        // 49+50) and 18:47:13Z on 127.0.0.1:40222 / 127.0.0.1:40240 (dual cid
                        // 88+89) after bare product-NATS RestartAsync reloads the same expired
                        // platform leaf;
                        // cid 51 → 90 → 47 → 40 for CN=fra-platform on fra-product-nats-1,
                        // fingerprint bf210e609e7f… — four-occurrence sparse post-recycle
                        // reconnect twin of d86f81358e32… / a87539b37de1… / a66e03d58e6a… /
                        // aae9c8a6b484… / b8e719ba13ca… / 67d134aeab25… / 669e26dad203… /
                        // eebfa17cec6b… / 639501fa4228… / 5d30a28d7f44… / 5804cb3aaf61… /
                        // 7904dd055f87… / 92ed0baffd5b… / fc4e0317d2a1… / 30e9c320e15b… /
                        // 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… (and gru f106e39e815f…
                        // cid 52 → 91 / gru 88ff8c404d3b… cid 51 → 90 / gru 897b9ff7b37e…
                        // cid 50 → 89 / gru 8a0aaf8cb1da… cid 49 → 88 → 45 → 55 / gru
                        // 6be7ec00050d… cid 48 → 87 / gru 0401b56675fd… cid 47 → 86 / gru
                        // e962f4a49508… cid 46 → 85 / gru 3f4dc73e62f2… cid 45 → 84 → 44 → 54 /
                        // gru 5990e53d2fde… cid 44 → 83 / sfo e583d837318a… dual cid 49+50 →
                        // 88+89 / sfo 02525de8dfa3… cid 47 → 86 → 39 / sfo ef71b6e32493… dual
                        // cid 45+46 → 84+85 / sfo b439248687d8… cid 44 → 83 / sfo
                        // c907c56a7c0c… cid 43 → 82 → 38 at the adjacent wall-clock 18:46:03Z /
                        // 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z /
                        // 18:46:09Z / 18:46:10Z / 18:46:11Z / 18:46:12Z / 18:46:13Z /
                        // 18:46:14Z / 18:46:15Z / 18:47:03Z / 18:47:04Z / 18:47:05Z /
                        // 18:47:06Z / 18:47:07Z / 18:47:08Z / 18:47:09Z / 18:47:10Z /
                        // 18:47:11Z / 18:47:12Z / 18:47:13Z / 18:47:14Z / 18:47:15Z /
                        // 18:48:10Z / 18:48:15Z / 18:49:10Z / 18:50:09Z / 18:50:15Z steps)
                        // against the same 7ef9d0a4… leaf at 18:46:15Z on 127.0.0.1:47532,
                        // 18:47:15Z on 127.0.0.1:48208, 18:48:15Z on 127.0.0.1:42916, and
                        // 18:50:15Z on 127.0.0.1:56668 after bare product-NATS RestartAsync
                        // reloads the same expired platform leaf;
                        // cid 52 → 91 for CN=fra-platform on fra-product-nats-1,
                        // fingerprint ec156a1db321… — two-occurrence post-recycle reconnect twin
                        // of bf210e609e7f… / d86f81358e32… / a87539b37de1… / a66e03d58e6a… /
                        // aae9c8a6b484… / b8e719ba13ca… / 67d134aeab25… / 669e26dad203… /
                        // eebfa17cec6b… / 639501fa4228… / 5d30a28d7f44… / 5804cb3aaf61… /
                        // 7904dd055f87… / 92ed0baffd5b… / fc4e0317d2a1… / 30e9c320e15b… /
                        // 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… (and gru f106e39e815f…
                        // cid 52 → 91 / gru d0feba5039c6… cid:53 / gru 88ff8c404d3b… cid 51 →
                        // 90 / gru 897b9ff7b37e… cid 50 → 89 / gru 8a0aaf8cb1da… cid 49 → 88 →
                        // 45 → 55 / gru 6be7ec00050d… cid 48 → 87 / gru 0401b56675fd… cid 47 →
                        // 86 / gru e962f4a49508… cid 46 → 85 / gru 3f4dc73e62f2… cid 45 → 84 →
                        // 44 → 54 / gru 5990e53d2fde… cid 44 → 83 / sfo e583d837318a… dual cid
                        // 49+50 → 88+89 / sfo 02525de8dfa3… cid 47 → 86 → 39 / sfo
                        // ef71b6e32493… dual cid 45+46 → 84+85 / sfo b439248687d8… cid 44 → 83 /
                        // sfo c907c56a7c0c… cid 43 → 82 → 38 at the adjacent wall-clock
                        // 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z /
                        // 18:46:08Z / 18:46:09Z / 18:46:10Z / 18:46:11Z / 18:46:12Z /
                        // 18:46:13Z / 18:46:14Z / 18:46:15Z / 18:46:17Z / 18:47:03Z /
                        // 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z / 18:47:08Z /
                        // 18:47:09Z / 18:47:10Z / 18:47:11Z / 18:47:12Z / 18:47:13Z /
                        // 18:47:14Z / 18:47:15Z / 18:47:17Z / 18:48:10Z / 18:48:15Z /
                        // 18:49:10Z / 18:50:09Z / 18:50:15Z steps) against the same 7ef9d0a4…
                        // leaf at 18:46:17Z on 127.0.0.1:47542 and 18:47:17Z on
                        // 127.0.0.1:48210 after bare product-NATS RestartAsync reloads the same
                        // expired platform leaf;
                        // cid 53 → 54 → 92 → 93 → 31 for CN=fra-platform on fra-product-nats-1,
                        // fingerprint 59a0656971a4… — five-occurrence post-recycle reconnect twin
                        // of ec156a1db321… / bf210e609e7f… / d86f81358e32… / a87539b37de1… /
                        // a66e03d58e6a… / aae9c8a6b484… / b8e719ba13ca… / 67d134aeab25… /
                        // 669e26dad203… / eebfa17cec6b… / 639501fa4228… / 5d30a28d7f44… /
                        // 5804cb3aaf61… / 7904dd055f87… / 92ed0baffd5b… / fc4e0317d2a1… /
                        // 30e9c320e15b… / 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… (and gru
                        // 1f9106a25f41… cid 54 → 55 → 94 → 31 / gru d0feba5039c6… cid:53 / gru
                        // f106e39e815f… cid 52 → 91 / gru 88ff8c404d3b… cid 51 → 90 / gru
                        // 897b9ff7b37e… cid 50 → 89 / gru 8a0aaf8cb1da… cid 49 → 88 → 45 → 55 /
                        // gru 6be7ec00050d… cid 48 → 87 / gru 0401b56675fd… cid 47 → 86 / gru
                        // e962f4a49508… cid 46 → 85 / gru 3f4dc73e62f2… cid 45 → 84 → 44 → 54 /
                        // gru 5990e53d2fde… cid 44 → 83 / sfo e7adbe3390eb… cid 52 → 91 / sfo
                        // e583d837318a… dual cid 49+50 → 88+89 / sfo 02525de8dfa3… cid 47 → 86 →
                        // 39 / sfo ef71b6e32493… dual cid 45+46 → 84+85 / sfo b439248687d8… cid
                        // 44 → 83 / sfo c907c56a7c0c… cid 43 → 82 → 38 at the adjacent
                        // wall-clock 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z /
                        // 18:46:07Z / 18:46:08Z / 18:46:09Z / 18:46:10Z / 18:46:11Z /
                        // 18:46:12Z / 18:46:13Z / 18:46:14Z / 18:46:15Z / 18:46:17Z /
                        // 18:46:19Z / 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z /
                        // 18:47:07Z / 18:47:08Z / 18:47:09Z / 18:47:10Z / 18:47:11Z /
                        // 18:47:12Z / 18:47:13Z / 18:47:14Z / 18:47:15Z / 18:47:17Z /
                        // 18:47:19Z / 18:48:10Z / 18:48:15Z / 18:49:10Z / 18:49:19Z /
                        // 18:50:09Z / 18:50:15Z steps) against the same 7ef9d0a4… leaf at
                        // 18:46:19Z on 127.0.0.1:47548 and 127.0.0.1:47562, 18:47:19Z on
                        // 127.0.0.1:48216 and 127.0.0.1:48240, and 18:49:19Z on 127.0.0.1:33996
                        // after bare product-NATS RestartAsync reloads the same expired
                        // platform leaf;
                        // cid 55 → 94 → 48 → 41 for CN=fra-platform on fra-product-nats-1,
                        // fingerprint 8e310ea4f277… — four-occurrence post-recycle reconnect twin
                        // of 59a0656971a4… / ec156a1db321… / bf210e609e7f… / d86f81358e32… /
                        // a87539b37de1… / a66e03d58e6a… / aae9c8a6b484… / b8e719ba13ca… /
                        // 67d134aeab25… / 669e26dad203… / eebfa17cec6b… / 639501fa4228… /
                        // 5d30a28d7f44… / 5804cb3aaf61… / 7904dd055f87… / 92ed0baffd5b… /
                        // fc4e0317d2a1… / 30e9c320e15b… / 25ef0004168c… / dacc95d0e7ba… /
                        // 1e8b88f75d43… (and gru 7dae08a6f4b3… cid 56 → 47 → 41 / gru
                        // 1f9106a25f41… cid 54 → 55 → 94 → 31 / gru d0feba5039c6… cid:53 / gru
                        // f106e39e815f… cid 52 → 91 / sfo e7adbe3390eb… cid 52 → 91 / sfo
                        // e583d837318a… dual cid 49+50 → 88+89 at the adjacent wall-clock
                        // 18:46:17Z / 18:46:19Z / 18:46:21Z / 18:47:17Z / 18:47:19Z /
                        // 18:47:21Z / 18:48:21Z / 18:49:19Z / 18:50:21Z steps) against the
                        // same 7ef9d0a4… leaf at 18:46:21Z on 127.0.0.1:47568, 18:47:21Z on
                        // 127.0.0.1:48244, 18:48:21Z on 127.0.0.1:42936, and 18:50:21Z on
                        // 127.0.0.1:56688 after bare product-NATS RestartAsync reloads the same
                        // expired platform leaf (two seconds after 59a0656971a4… cid 53 → 54 →
                        // 92 → 93 → 31 on adjacent :19 steps / ports 47548/47562 → 47568 and
                        // 48216/48240 → 48244; same wall-clock :21 as gru 7dae08a6f4b3…);
                        // cid 56 → 95 for CN=fra-platform on fra-product-nats-1,
                        // fingerprint d087ae1829c6… — two-occurrence post-recycle reconnect twin
                        // of 8e310ea4f277… / 59a0656971a4… / ec156a1db321… / bf210e609e7f… /
                        // d86f81358e32… / a87539b37de1… / a66e03d58e6a… / aae9c8a6b484… /
                        // b8e719ba13ca… / 67d134aeab25… / 669e26dad203… / eebfa17cec6b… /
                        // 639501fa4228… / 5d30a28d7f44… / 5804cb3aaf61… / 7904dd055f87… /
                        // 92ed0baffd5b… / fc4e0317d2a1… / 30e9c320e15b… / 25ef0004168c… /
                        // dacc95d0e7ba… / 1e8b88f75d43… (and gru d22a1e331a57… cid 57 → 96 /
                        // sfo db61915863fe… cid 56 → 95 / gru 7dae08a6f4b3… cid 56 → 47 → 41 /
                        // gru 1f9106a25f41… cid 54 → 55 → 94 → 31 at the adjacent wall-clock
                        // 18:46:19Z / 18:46:21Z / 18:46:23Z / 18:46:24Z / 18:47:19Z /
                        // 18:47:21Z / 18:47:23Z / 18:47:24Z steps) against the same 7ef9d0a4…
                        // leaf at 18:46:23Z on 127.0.0.1:47578 and 18:47:23Z on
                        // 127.0.0.1:48248 after bare product-NATS RestartAsync reloads the same
                        // expired platform leaf (two seconds after 8e310ea4f277… cid 55 → 94 →
                        // 48 → 41 on adjacent :21 steps / ports 47568 → 47578 and 48244 →
                        // 48248; same wall-clock :23 as gru d22a1e331a57…; one second before
                        // sfo db61915863fe… cid 56 → 95 at :24);
                        // cid 57 → 96 → 97 → 32 for CN=fra-platform on fra-product-nats-1,
                        // fingerprint 86b0b173f024… — four-occurrence post-recycle reconnect twin
                        // of d087ae1829c6… / 8e310ea4f277… / 59a0656971a4… / ec156a1db321… /
                        // bf210e609e7f… / d86f81358e32… / a87539b37de1… / a66e03d58e6a… /
                        // aae9c8a6b484… / b8e719ba13ca… / 67d134aeab25… / 669e26dad203… /
                        // eebfa17cec6b… / 639501fa4228… / 5d30a28d7f44… / 5804cb3aaf61… /
                        // 7904dd055f87… / 92ed0baffd5b… / fc4e0317d2a1… / 30e9c320e15b… /
                        // 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… (and gru d26427e1c533…
                        // cid 58 → 97 → 98 → 32 / gru d22a1e331a57… cid 57 → 96 / sfo
                        // db61915863fe… cid 56 → 95 / gru 7dae08a6f4b3… cid 56 → 47 → 41 /
                        // gru 1f9106a25f41… cid 54 → 55 → 94 → 31 at the adjacent wall-clock
                        // 18:46:19Z / 18:46:21Z / 18:46:23Z / 18:46:24Z / 18:46:25Z /
                        // 18:47:19Z / 18:47:21Z / 18:47:23Z / 18:47:24Z / 18:47:25Z /
                        // 18:49:25Z steps) against the same 7ef9d0a4… leaf at 18:46:25Z on
                        // 127.0.0.1:60966, 18:47:25Z on 127.0.0.1:48826 and 127.0.0.1:48848
                        // (dual cid 96+97), and 18:49:25Z on 127.0.0.1:41430 after bare
                        // product-NATS RestartAsync reloads the same expired platform leaf
                        // (two seconds after d087ae1829c6… cid 56 → 95 on adjacent :23 steps;
                        // same wall-clock :25 as gru d26427e1c533… cid 58 → 97 → 98 → 32;
                        // same cid 57 → 96 as gru d22a1e331a57… two seconds earlier at :23);
                        // cid 14634 → 63 → 34 → 49 → 43 for CN=sfo-platform on sfo-product-nats-1,
                        // fingerprint b1723b879b59… — sfo product-plane twin of fra 25ef0004168c…:
                        // long-running sfo-platform reconnects while bare product-NATS
                        // RestartAsync reloads the same expired platform leaf;
                        // cid 14635 → 67 → 37 → 38 → 50 → 44 for CN=sfo-platform on sfo-product-nats-1,
                        // fingerprint 77220dace263… — denser six-occurrence twin of b1723b879b59…
                        // against the same a914ebca… leaf at 18:45:40Z / 18:46:40Z / 18:47:40Z
                        // (dual cid 37+38) / 18:48:40Z / 18:50:40Z: long-running sfo-platform
                        // reconnects while bare product-NATS RestartAsync reloads the same
                        // expired platform leaf;
                        // cid 14635 → 38 → 50 → 44 for CN=gru-platform on gru-product-nats-1,
                        // fingerprint 54fea6c92b78… — denser four-occurrence twin of
                        // 57ae70882ed5… against the same 6b500765… leaf at 18:45:40Z /
                        // 18:47:40Z / 18:48:40Z / 18:50:40Z: long-running gru-platform
                        // reconnects while bare product-NATS RestartAsync reloads the same
                        // expired platform leaf;
                        // cid:31 for CN=gru-platform on gru-product-nats-1,
                        // fingerprint 0b23b4fb5a75… — single post-recycle reconnect twin of
                        // 54fea6c92b78… / 57ae70882ed5… against the same 6b500765… leaf at
                        // 18:45:42Z on 127.0.0.1:39462 after bare product-NATS RestartAsync
                        // reloads the same expired platform leaf;
                        // cid 32 → 70 → 71 → 40 for CN=gru-platform on gru-product-nats-1,
                        // fingerprint 1364f1b0cdbc… — four-occurrence post-recycle reconnect twin
                        // of 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5… against the same
                        // 6b500765… leaf at 18:45:43Z on 127.0.0.1:39470, 18:46:43Z on
                        // 127.0.0.1:47014 / 47034 (dual cid 70+71), and 18:47:43Z on
                        // 127.0.0.1:38360 after bare product-NATS RestartAsync reloads the same
                        // expired platform leaf;
                        // cid 33 → 72 → 41 → 51 → 45 for CN=gru-platform on gru-product-nats-1,
                        // fingerprint 0cbc78bc3a3a… — five-occurrence post-recycle reconnect twin
                        // of 1364f1b0cdbc… / 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5… against
                        // the same 6b500765… leaf at 18:45:46Z on 127.0.0.1:48834, 18:46:46Z on
                        // 127.0.0.1:60204, 18:47:46Z on 127.0.0.1:56364, 18:48:46Z on
                        // 127.0.0.1:39346, and 18:50:46Z on 127.0.0.1:48414 after bare
                        // product-NATS RestartAsync reloads the same expired platform leaf;
                        // cid 34 → 73 for CN=gru-platform on gru-product-nats-1,
                        // fingerprint 6a1c43a93378… — two-occurrence post-recycle reconnect twin
                        // of 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75… / 54fea6c92b78… /
                        // 57ae70882ed5… against the same 6b500765… leaf at 18:45:48Z on
                        // 127.0.0.1:48846 and 18:46:48Z on 127.0.0.1:60214 after bare
                        // product-NATS RestartAsync reloads the same expired platform leaf;
                        // cid 35 → 36 → 75 → 36 for CN=gru-platform on gru-product-nats-1,
                        // fingerprint ed3f4504d5e1… — four-occurrence post-recycle reconnect twin
                        // of 6a1c43a93378… / 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75… /
                        // 54fea6c92b78… / 57ae70882ed5… (and sfo 146c64f3fc52… / operator-read
                        // twins f4f92376efda… / 62860f83eeb6… at the same wall-clock pair)
                        // against the same 6b500765… leaf at 18:45:50Z on 127.0.0.1:48870 /
                        // 48878 (dual cid 35+36), 18:46:50Z on 127.0.0.1:60244, and 18:49:50Z
                        // on 127.0.0.1:41546 after bare product-NATS RestartAsync reloads the
                        // same expired platform leaf;
                        // cid 37 → 76 → 52 → 46 for CN=gru-platform on gru-product-nats-1,
                        // fingerprint b22018f7aa7b… — four-occurrence post-recycle reconnect twin
                        // of ed3f4504d5e1… / 6a1c43a93378… / 0cbc78bc3a3a… / 1364f1b0cdbc… /
                        // 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5… (and sfo eaa27086a65c… /
                        // fra 92ed0baffd5b… / operator-read twins at adjacent wall-clock
                        // :50/:51/:52 steps) against the same 6b500765… leaf at 18:45:52Z on
                        // 127.0.0.1:48880, 18:46:52Z on 127.0.0.1:60260, 18:48:52Z on
                        // 127.0.0.1:39364, and 18:50:52Z on 127.0.0.1:48432 after bare
                        // product-NATS RestartAsync reloads the same expired platform leaf;
                        // cid 38 → 77 for CN=gru-platform on gru-product-nats-1,
                        // fingerprint 9371738eec92… — two-occurrence post-recycle reconnect twin
                        // of b22018f7aa7b… / ed3f4504d5e1… / 6a1c43a93378… / 0cbc78bc3a3a… /
                        // 1364f1b0cdbc… / 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5… (and sfo
                        // e33d87402e17… / fra 7904dd055f87… / operator-read twins at adjacent
                        // wall-clock :52/:53/:54 steps) against the same 6b500765… leaf at
                        // 18:45:54Z on 127.0.0.1:48886 and 18:46:54Z on 127.0.0.1:60264 after
                        // bare product-NATS RestartAsync reloads the same expired platform leaf;
                        // cid:78 for CN=gru-platform on gru-product-nats-1,
                        // fingerprint 02a670a12fe6… — single post-recycle reconnect twin of
                        // 9371738eec92… / b22018f7aa7b… / ed3f4504d5e1… / 6a1c43a93378… /
                        // 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75… / 54fea6c92b78… /
                        // 57ae70882ed5… against the same 6b500765… leaf at 18:46:55Z on
                        // 127.0.0.1:53194 after bare product-NATS RestartAsync reloads the same
                        // expired platform leaf;
                        // cid 39 → 40 → 79 → 37 for CN=gru-platform on gru-product-nats-1,
                        // fingerprint be7bee33b946… — four-occurrence post-recycle reconnect twin
                        // of 02a670a12fe6… / 9371738eec92… / b22018f7aa7b… / ed3f4504d5e1… /
                        // 6a1c43a93378… / 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75… /
                        // 54fea6c92b78… / 57ae70882ed5… (and gru operator-read b252d8996050… /
                        // gru-controller a9bf884a363b… / sfo operator-read 97d33257778a… /
                        // fra operator-read c74671d2c0e4… at the same wall-clock :56 steps)
                        // against the same 6b500765… leaf at 18:45:56Z on 127.0.0.1:35188 /
                        // 127.0.0.1:35204 (dual cid 39+40), 18:46:56Z on 127.0.0.1:53210, and
                        // 18:49:56Z on 127.0.0.1:49142 after bare product-NATS RestartAsync
                        // reloads the same expired platform leaf;
                        // cid 41 → 80 → 53 for CN=gru-platform on gru-product-nats-1,
                        // fingerprint a2e01c16a27c… — three-occurrence post-recycle reconnect twin
                        // of be7bee33b946… / 02a670a12fe6… / 9371738eec92… / b22018f7aa7b… /
                        // ed3f4504d5e1… / 6a1c43a93378… / 0cbc78bc3a3a… / 1364f1b0cdbc… /
                        // 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5… (and sfo 9b960cc93f83… /
                        // fra 5d30a28d7f44… / gru operator-read b252d8996050… / gru-controller
                        // a9bf884a363b… / sfo operator-read 97d33257778a… / fra operator-read
                        // c74671d2c0e4… at adjacent wall-clock :56/:57/:58 steps) against the same
                        // 6b500765… leaf at 18:45:58Z on 127.0.0.1:35206, 18:46:58Z on
                        // 127.0.0.1:53226, and 18:48:58Z on 127.0.0.1:54632 after bare
                        // product-NATS RestartAsync reloads the same expired platform leaf;
                        // cid 42 → 81 for CN=gru-platform on gru-product-nats-1,
                        // fingerprint 764b28c3439a… — two-occurrence post-recycle reconnect twin
                        // of a2e01c16a27c… / be7bee33b946… / 02a670a12fe6… / 9371738eec92… /
                        // b22018f7aa7b… / ed3f4504d5e1… / 6a1c43a93378… / 0cbc78bc3a3a… /
                        // 1364f1b0cdbc… / 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5… (and gru
                        // controller 25b92b919c66… at the same wall-clock 18:46:00Z / 18:47:00Z
                        // steps) against the same 6b500765… leaf at 18:46:00Z on
                        // 127.0.0.1:35222 and 18:47:00Z on 127.0.0.1:53234 after bare
                        // product-NATS RestartAsync reloads the same expired platform leaf;
                        // cid 43 → 82 for CN=gru-platform on gru-product-nats-1,
                        // fingerprint 6d84bda1e560… — two-occurrence post-recycle reconnect twin
                        // of 764b28c3439a… / a2e01c16a27c… / be7bee33b946… / 02a670a12fe6… /
                        // 9371738eec92… / b22018f7aa7b… / ed3f4504d5e1… / 6a1c43a93378… /
                        // 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75… / 54fea6c92b78… /
                        // 57ae70882ed5… (and sfo eacb3282ca0c… dual cid 41+42 → 80+81 / fra
                        // eebfa17cec6b… cid 41 → 80 at the same wall-clock 18:46:01Z /
                        // 18:47:01Z steps) against the same 6b500765… leaf at 18:46:01Z on
                        // 127.0.0.1:35228 and 18:47:01Z on 127.0.0.1:53246 after bare
                        // product-NATS RestartAsync reloads the same expired platform leaf;
                        // cid 44 → 83 for CN=gru-platform on gru-product-nats-1,
                        // fingerprint 5990e53d2fde… — two-occurrence post-recycle reconnect twin
                        // of 6d84bda1e560… / 764b28c3439a… / a2e01c16a27c… / be7bee33b946… /
                        // 02a670a12fe6… / 9371738eec92… / b22018f7aa7b… / ed3f4504d5e1… /
                        // 6a1c43a93378… / 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75… /
                        // 54fea6c92b78… / 57ae70882ed5… (and sfo eacb3282ca0c… dual cid 41+42 →
                        // 80+81 / fra eebfa17cec6b… cid 41 → 80 / fra 669e26dad203… cid 42 → 81
                        // at the adjacent wall-clock 18:46:01Z / 18:47:01Z steps) against the
                        // same 6b500765… leaf at 18:46:02Z on 127.0.0.1:35234 and 18:47:02Z on
                        // 127.0.0.1:53260 after bare product-NATS RestartAsync reloads the same
                        // expired platform leaf;
                        // cid 45 → 84 → 44 → 54 for CN=gru-platform on gru-product-nats-1,
                        // fingerprint 3f4dc73e62f2… — four-occurrence post-recycle reconnect twin
                        // of 5990e53d2fde… / 6d84bda1e560… / 764b28c3439a… / a2e01c16a27c… /
                        // be7bee33b946… / 02a670a12fe6… / 9371738eec92… / b22018f7aa7b… /
                        // ed3f4504d5e1… / 6a1c43a93378… / 0cbc78bc3a3a… / 1364f1b0cdbc… /
                        // 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5… (and sfo c907c56a7c0c…
                        // cid 43 → 82 → 38 / fra 67d134aeab25… cid 43 → 38 at the adjacent
                        // wall-clock 18:46:03Z / 18:47:03Z / 18:50:03Z steps) against the same
                        // 6b500765… leaf at 18:46:04Z on 127.0.0.1:44042, 18:47:04Z on
                        // 127.0.0.1:48200, 18:48:04Z on 127.0.0.1:42712, and 18:49:04Z on
                        // 127.0.0.1:48152 after bare product-NATS RestartAsync reloads the same
                        // expired platform leaf;
                        // cid 46 → 85 for CN=gru-platform on gru-product-nats-1,
                        // fingerprint e962f4a49508… — two-occurrence post-recycle reconnect twin
                        // of 3f4dc73e62f2… / 5990e53d2fde… / 6d84bda1e560… / 764b28c3439a… /
                        // a2e01c16a27c… / be7bee33b946… / 02a670a12fe6… / 9371738eec92… /
                        // b22018f7aa7b… / ed3f4504d5e1… / 6a1c43a93378… / 0cbc78bc3a3a… /
                        // 1364f1b0cdbc… / 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5… (and
                        // sfo b439248687d8… cid 44 → 83 / fra b8e719ba13ca… cid:44 / sfo
                        // c907c56a7c0c… cid 43 → 82 → 38 / fra 67d134aeab25… cid 43 → 38 at the
                        // adjacent wall-clock 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z /
                        // 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z steps) against the same
                        // 6b500765… leaf at 18:46:06Z on 127.0.0.1:44054 and 18:47:06Z on
                        // 127.0.0.1:48204 after bare product-NATS RestartAsync reloads the same
                        // expired platform leaf;
                        // cid 47 → 86 for CN=gru-platform on gru-product-nats-1,
                        // fingerprint 0401b56675fd… — two-occurrence post-recycle reconnect twin
                        // of e962f4a49508… / 3f4dc73e62f2… / 5990e53d2fde… / 6d84bda1e560… /
                        // 764b28c3439a… / a2e01c16a27c… / be7bee33b946… / 02a670a12fe6… /
                        // 9371738eec92… / b22018f7aa7b… / ed3f4504d5e1… / 6a1c43a93378… /
                        // 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75… / 54fea6c92b78… /
                        // 57ae70882ed5… (and sfo ef71b6e32493… dual cid 45+46 → 84+85 / fra
                        // aae9c8a6b484… dual cid 45+46 → 84+85 / sfo b439248687d8… cid 44 → 83 /
                        // fra b8e719ba13ca… cid:44 / sfo c907c56a7c0c… cid 43 → 82 → 38 / fra
                        // 67d134aeab25… cid 43 → 38 at the adjacent wall-clock 18:46:03Z /
                        // 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:47:03Z /
                        // 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z steps) against the same
                        // 6b500765… leaf at 18:46:07Z on 127.0.0.1:44066 and 18:47:07Z on
                        // 127.0.0.1:48220 after bare product-NATS RestartAsync reloads the same
                        // expired platform leaf;
                        // cid 48 → 87 for CN=gru-platform on gru-product-nats-1,
                        // fingerprint 6be7ec00050d… — two-occurrence post-recycle reconnect twin
                        // of 0401b56675fd… / e962f4a49508… / 3f4dc73e62f2… / 5990e53d2fde… /
                        // 6d84bda1e560… / 764b28c3439a… / a2e01c16a27c… / be7bee33b946… /
                        // 02a670a12fe6… / 9371738eec92… / b22018f7aa7b… / ed3f4504d5e1… /
                        // 6a1c43a93378… / 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75… /
                        // 54fea6c92b78… / 57ae70882ed5… (and sfo ef71b6e32493… dual cid 45+46 →
                        // 84+85 / fra aae9c8a6b484… dual cid 45+46 → 84+85 / sfo b439248687d8…
                        // cid 44 → 83 / fra b8e719ba13ca… cid:44 / sfo c907c56a7c0c… cid 43 →
                        // 82 → 38 / fra 67d134aeab25… cid 43 → 38 at the adjacent wall-clock
                        // 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z /
                        // 18:46:08Z / 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z /
                        // 18:47:07Z / 18:47:08Z steps) against the same 6b500765… leaf at
                        // 18:46:08Z on 127.0.0.1:44070 and 18:47:08Z on 127.0.0.1:48226 after
                        // bare product-NATS RestartAsync reloads the same expired platform leaf;
                        // cid 49 → 88 → 45 → 55 for CN=gru-platform on gru-product-nats-1,
                        // fingerprint 8a0aaf8cb1da… — four-occurrence post-recycle reconnect twin
                        // of 6be7ec00050d… / 0401b56675fd… / e962f4a49508… / 3f4dc73e62f2… /
                        // 5990e53d2fde… / 6d84bda1e560… / 764b28c3439a… / a2e01c16a27c… /
                        // be7bee33b946… / 02a670a12fe6… / 9371738eec92… / b22018f7aa7b… /
                        // ed3f4504d5e1… / 6a1c43a93378… / 0cbc78bc3a3a… / 1364f1b0cdbc… /
                        // 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5… (and sfo ef71b6e32493…
                        // dual cid 45+46 → 84+85 / fra aae9c8a6b484… dual cid 45+46 → 84+85 /
                        // sfo 02525de8dfa3… cid 47 → 86 → 39 / fra a66e03d58e6a… cid 47 → 86 →
                        // 39 / sfo b439248687d8… cid 44 → 83 / fra b8e719ba13ca… cid:44 / sfo
                        // c907c56a7c0c… cid 43 → 82 → 38 / fra 67d134aeab25… cid 43 → 38 at the
                        // adjacent wall-clock 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z /
                        // 18:46:07Z / 18:46:08Z / 18:46:09Z / 18:46:10Z / 18:47:03Z /
                        // 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z / 18:47:08Z /
                        // 18:47:09Z / 18:47:10Z / 18:48:10Z / 18:49:10Z steps) against the same
                        // 6b500765… leaf at 18:46:10Z on 127.0.0.1:44074, 18:47:10Z on
                        // 127.0.0.1:48238, 18:48:10Z on 127.0.0.1:52880, and 18:49:10Z on
                        // 127.0.0.1:48166 after bare product-NATS RestartAsync reloads the same
                        // expired platform leaf;
                        // cid 50 → 89 for CN=gru-platform on gru-product-nats-1,
                        // fingerprint 897b9ff7b37e… — two-occurrence post-recycle reconnect twin
                        // of 8a0aaf8cb1da… / 6be7ec00050d… / 0401b56675fd… / e962f4a49508… /
                        // 3f4dc73e62f2… / 5990e53d2fde… / 6d84bda1e560… / 764b28c3439a… /
                        // a2e01c16a27c… / be7bee33b946… / 02a670a12fe6… / 9371738eec92… /
                        // b22018f7aa7b… / ed3f4504d5e1… / 6a1c43a93378… / 0cbc78bc3a3a… /
                        // 1364f1b0cdbc… / 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5… (and sfo
                        // ef71b6e32493… dual cid 45+46 → 84+85 / fra aae9c8a6b484… dual cid
                        // 45+46 → 84+85 / sfo 02525de8dfa3… cid 47 → 86 → 39 / fra a66e03d58e6a…
                        // cid 47 → 86 → 39 / sfo b439248687d8… cid 44 → 83 / fra b8e719ba13ca…
                        // cid:44 / sfo c907c56a7c0c… cid 43 → 82 → 38 / fra 67d134aeab25… cid
                        // 43 → 38 / fra a87539b37de1… cid 48 → 87 at the adjacent wall-clock
                        // 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z /
                        // 18:46:08Z / 18:46:09Z / 18:46:10Z / 18:46:11Z / 18:46:12Z /
                        // 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z /
                        // 18:47:08Z / 18:47:09Z / 18:47:10Z / 18:47:11Z / 18:47:12Z /
                        // 18:48:10Z / 18:49:10Z steps) against the same 6b500765… leaf at
                        // 18:46:12Z on 127.0.0.1:44082 and 18:47:12Z on 127.0.0.1:48252 after
                        // bare product-NATS RestartAsync reloads the same expired platform leaf;
                        // cid 51 → 90 for CN=gru-platform on gru-product-nats-1,
                        // fingerprint 88ff8c404d3b… — two-occurrence post-recycle reconnect twin
                        // of 897b9ff7b37e… / 8a0aaf8cb1da… / 6be7ec00050d… / 0401b56675fd… /
                        // e962f4a49508… / 3f4dc73e62f2… / 5990e53d2fde… / 6d84bda1e560… /
                        // 764b28c3439a… / a2e01c16a27c… / be7bee33b946… / 02a670a12fe6… /
                        // 9371738eec92… / b22018f7aa7b… / ed3f4504d5e1… / 6a1c43a93378… /
                        // 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75… / 54fea6c92b78… /
                        // 57ae70882ed5… (and sfo e583d837318a… dual cid 49+50 → 88+89 / fra
                        // d86f81358e32… dual cid 49+50 → 88+89 / sfo ef71b6e32493… dual cid
                        // 45+46 → 84+85 / fra aae9c8a6b484… dual cid 45+46 → 84+85 / sfo
                        // 02525de8dfa3… cid 47 → 86 → 39 / fra a66e03d58e6a… cid 47 → 86 →
                        // 39 / sfo b439248687d8… cid 44 → 83 / fra b8e719ba13ca… cid:44 / sfo
                        // c907c56a7c0c… cid 43 → 82 → 38 / fra 67d134aeab25… cid 43 → 38 /
                        // fra a87539b37de1… cid 48 → 87 at the adjacent wall-clock 18:46:03Z /
                        // 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z /
                        // 18:46:09Z / 18:46:10Z / 18:46:11Z / 18:46:12Z / 18:46:13Z /
                        // 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z /
                        // 18:47:08Z / 18:47:09Z / 18:47:10Z / 18:47:11Z / 18:47:12Z /
                        // 18:47:13Z / 18:48:10Z / 18:49:10Z steps) against the same 6b500765…
                        // leaf at 18:46:13Z on 127.0.0.1:44104 and 18:47:13Z on 127.0.0.1:48274
                        // after bare product-NATS RestartAsync reloads the same expired
                        // platform leaf;
                        // cid 52 → 91 for CN=gru-platform on gru-product-nats-1,
                        // fingerprint f106e39e815f… — two-occurrence post-recycle reconnect twin
                        // of 88ff8c404d3b… / 897b9ff7b37e… / 8a0aaf8cb1da… / 6be7ec00050d… /
                        // 0401b56675fd… / e962f4a49508… / 3f4dc73e62f2… / 5990e53d2fde… /
                        // 6d84bda1e560… / 764b28c3439a… / a2e01c16a27c… / be7bee33b946… /
                        // 02a670a12fe6… / 9371738eec92… / b22018f7aa7b… / ed3f4504d5e1… /
                        // 6a1c43a93378… / 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75… /
                        // 54fea6c92b78… / 57ae70882ed5… (and sfo e583d837318a… dual cid 49+50 →
                        // 88+89 / fra d86f81358e32… dual cid 49+50 → 88+89 / sfo ef71b6e32493…
                        // dual cid 45+46 → 84+85 / fra aae9c8a6b484… dual cid 45+46 → 84+85 /
                        // sfo 02525de8dfa3… cid 47 → 86 → 39 / fra a66e03d58e6a… cid 47 → 86 →
                        // 39 / sfo b439248687d8… cid 44 → 83 / fra b8e719ba13ca… cid:44 / sfo
                        // c907c56a7c0c… cid 43 → 82 → 38 / fra 67d134aeab25… cid 43 → 38 /
                        // fra a87539b37de1… cid 48 → 87 at the adjacent wall-clock 18:46:03Z /
                        // 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z /
                        // 18:46:09Z / 18:46:10Z / 18:46:11Z / 18:46:12Z / 18:46:13Z /
                        // 18:46:14Z / 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z /
                        // 18:47:07Z / 18:47:08Z / 18:47:09Z / 18:47:10Z / 18:47:11Z /
                        // 18:47:12Z / 18:47:13Z / 18:47:14Z / 18:48:10Z / 18:49:10Z steps)
                        // against the same 6b500765… leaf at 18:46:14Z on 127.0.0.1:38738 and
                        // 18:47:14Z on 127.0.0.1:47750 after bare product-NATS RestartAsync
                        // reloads the same expired platform leaf;
                        // cid:53 for CN=gru-platform on gru-product-nats-1,
                        // fingerprint d0feba5039c6… — single post-recycle reconnect twin of
                        // f106e39e815f… / 88ff8c404d3b… / 897b9ff7b37e… / 8a0aaf8cb1da… /
                        // 6be7ec00050d… / 0401b56675fd… / e962f4a49508… / 3f4dc73e62f2… /
                        // 5990e53d2fde… / 6d84bda1e560… / 764b28c3439a… / a2e01c16a27c… /
                        // be7bee33b946… / 02a670a12fe6… / 9371738eec92… / b22018f7aa7b… /
                        // ed3f4504d5e1… / 6a1c43a93378… / 0cbc78bc3a3a… / 1364f1b0cdbc… /
                        // 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5… (and sfo e583d837318a…
                        // dual cid 49+50 → 88+89 / fra d86f81358e32… dual cid 49+50 → 88+89 /
                        // sfo ef71b6e32493… dual cid 45+46 → 84+85 / fra aae9c8a6b484… dual
                        // cid 45+46 → 84+85 / sfo 02525de8dfa3… cid 47 → 86 → 39 / fra
                        // a66e03d58e6a… cid 47 → 86 → 39 / sfo b439248687d8… cid 44 → 83 /
                        // fra b8e719ba13ca… cid:44 / sfo c907c56a7c0c… cid 43 → 82 → 38 /
                        // fra 67d134aeab25… cid 43 → 38 / fra a87539b37de1… cid 48 → 87 at
                        // the adjacent wall-clock 18:46:03Z / 18:46:04Z / 18:46:05Z /
                        // 18:46:06Z / 18:46:07Z / 18:46:08Z / 18:46:09Z / 18:46:10Z /
                        // 18:46:11Z / 18:46:12Z / 18:46:13Z / 18:46:14Z / 18:46:17Z /
                        // 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z /
                        // 18:47:08Z / 18:47:09Z / 18:47:10Z / 18:47:11Z / 18:47:12Z /
                        // 18:47:13Z / 18:47:14Z / 18:48:10Z / 18:49:10Z steps) against the
                        // same 6b500765… leaf at 18:46:17Z on 127.0.0.1:38752 after bare
                        // product-NATS RestartAsync reloads the same expired platform leaf;
                        // cid 54 → 55 → 94 → 31 for CN=gru-platform on gru-product-nats-1,
                        // fingerprint 1f9106a25f41… — four-occurrence post-recycle reconnect twin
                        // of d0feba5039c6… / f106e39e815f… / 88ff8c404d3b… / 897b9ff7b37e… /
                        // 8a0aaf8cb1da… / 6be7ec00050d… / 0401b56675fd… / e962f4a49508… /
                        // 3f4dc73e62f2… / 5990e53d2fde… / 6d84bda1e560… / 764b28c3439a… /
                        // a2e01c16a27c… / be7bee33b946… / 02a670a12fe6… / 9371738eec92… /
                        // b22018f7aa7b… / ed3f4504d5e1… / 6a1c43a93378… / 0cbc78bc3a3a… /
                        // 1364f1b0cdbc… / 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5… (and sfo
                        // e7adbe3390eb… cid 52 → 91 / sfo e583d837318a… dual cid 49+50 → 88+89 /
                        // fra d86f81358e32… dual cid 49+50 → 88+89 / sfo ef71b6e32493… dual cid
                        // 45+46 → 84+85 / fra aae9c8a6b484… dual cid 45+46 → 84+85 / sfo
                        // 02525de8dfa3… cid 47 → 86 → 39 / fra a66e03d58e6a… cid 47 → 86 → 39 /
                        // sfo b439248687d8… cid 44 → 83 / fra b8e719ba13ca… cid:44 / sfo
                        // c907c56a7c0c… cid 43 → 82 → 38 / fra 67d134aeab25… cid 43 → 38 / fra
                        // a87539b37de1… cid 48 → 87 at the adjacent wall-clock 18:46:03Z /
                        // 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z /
                        // 18:46:09Z / 18:46:10Z / 18:46:11Z / 18:46:12Z / 18:46:13Z /
                        // 18:46:14Z / 18:46:17Z / 18:46:19Z / 18:47:03Z / 18:47:04Z /
                        // 18:47:05Z / 18:47:06Z / 18:47:07Z / 18:47:08Z / 18:47:09Z /
                        // 18:47:10Z / 18:47:11Z / 18:47:12Z / 18:47:13Z / 18:47:14Z /
                        // 18:47:19Z / 18:48:10Z / 18:49:10Z / 18:49:19Z steps) against the
                        // same 6b500765… leaf at 18:46:19Z on 127.0.0.1:38766 and
                        // 127.0.0.1:38790, 18:47:19Z on 127.0.0.1:47780, and 18:49:19Z on
                        // 127.0.0.1:45348 after bare product-NATS RestartAsync reloads the same
                        // expired platform leaf;
                        // cid 56 → 47 → 41 for CN=gru-platform on gru-product-nats-1,
                        // fingerprint 7dae08a6f4b3… — three-occurrence post-recycle reconnect twin
                        // of 1f9106a25f41… / d0feba5039c6… / f106e39e815f… / 88ff8c404d3b… /
                        // 897b9ff7b37e… / 8a0aaf8cb1da… / 6be7ec00050d… / 0401b56675fd… /
                        // e962f4a49508… / 3f4dc73e62f2… / 5990e53d2fde… / 6d84bda1e560… /
                        // 764b28c3439a… / a2e01c16a27c… / be7bee33b946… / 02a670a12fe6… /
                        // 9371738eec92… / b22018f7aa7b… / ed3f4504d5e1… / 6a1c43a93378… /
                        // 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75… / 54fea6c92b78… /
                        // 57ae70882ed5… against the same 6b500765… leaf at 18:46:21Z on
                        // 127.0.0.1:38792, 18:48:21Z on 127.0.0.1:60122, and 18:50:21Z on
                        // 127.0.0.1:49552 after bare product-NATS RestartAsync reloads the same
                        // expired platform leaf (two seconds after 1f9106a25f41… cid 54 → 55 →
                        // 94 → 31 on adjacent :19 steps / ports 38766/38790 → 38792);
                        // cid 57 → 96 for CN=gru-platform on gru-product-nats-1,
                        // fingerprint d22a1e331a57… — two-occurrence post-recycle reconnect twin
                        // of 7dae08a6f4b3… / 1f9106a25f41… / d0feba5039c6… / f106e39e815f… /
                        // 88ff8c404d3b… / 897b9ff7b37e… / 8a0aaf8cb1da… / 6be7ec00050d… /
                        // 0401b56675fd… / e962f4a49508… / 3f4dc73e62f2… / 5990e53d2fde… /
                        // 6d84bda1e560… / 764b28c3439a… / a2e01c16a27c… / be7bee33b946… /
                        // 02a670a12fe6… / 9371738eec92… / b22018f7aa7b… / ed3f4504d5e1… /
                        // 6a1c43a93378… / 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75… /
                        // 54fea6c92b78… / 57ae70882ed5… against the same 6b500765… leaf at
                        // 18:46:23Z on 127.0.0.1:38800 and 18:47:23Z on 127.0.0.1:47792 after
                        // bare product-NATS RestartAsync reloads the same expired platform leaf
                        // (two seconds after 7dae08a6f4b3… cid 56 → 47 → 41 on adjacent :21
                        // steps / port 38792 → 38800; four seconds after 1f9106a25f41… cid 54 →
                        // 55 → 94 → 31 on :19 steps / ports 38766/38790 → 38800);
                        // cid 58 → 97 → 98 → 32 for CN=gru-platform on gru-product-nats-1,
                        // fingerprint d26427e1c533… — four-occurrence post-recycle reconnect twin
                        // of d22a1e331a57… / 7dae08a6f4b3… / 1f9106a25f41… / d0feba5039c6… /
                        // f106e39e815f… / 88ff8c404d3b… / 897b9ff7b37e… / 8a0aaf8cb1da… /
                        // 6be7ec00050d… / 0401b56675fd… / e962f4a49508… / 3f4dc73e62f2… /
                        // 5990e53d2fde… / 6d84bda1e560… / 764b28c3439a… / a2e01c16a27c… /
                        // be7bee33b946… / 02a670a12fe6… / 9371738eec92… / b22018f7aa7b… /
                        // ed3f4504d5e1… / 6a1c43a93378… / 0cbc78bc3a3a… / 1364f1b0cdbc… /
                        // 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5… against the same
                        // 6b500765… leaf at 18:46:25Z on 127.0.0.1:35236, 18:47:25Z on
                        // 127.0.0.1:60448 and 127.0.0.1:60464 (dual cid 97+98), and 18:49:25Z
                        // on 127.0.0.1:58424 after bare product-NATS RestartAsync reloads the
                        // same expired platform leaf (two seconds after d22a1e331a57… cid 57 →
                        // 96 on adjacent :23 steps / port 38800 → 35236; four seconds after
                        // 7dae08a6f4b3… cid 56 → 47 → 41 on :21 steps; six seconds after
                        // 1f9106a25f41… cid 54 → 55 → 94 → 31 on :19 steps);
                        // cid 31 → 70 → 40 → 35 for CN=sfo-platform on sfo-product-nats-1,
                        // fingerprint d739f8d83bed… — four-occurrence post-recycle reconnect twin
                        // of b1723b879b59… / 77220dace263… (and gru 1364f1b0cdbc… / 0b23b4fb5a75…)
                        // against the same a914ebca… leaf at 18:45:44Z on 127.0.0.1:39116,
                        // 18:46:44Z on 127.0.0.1:59792, 18:47:44Z on 127.0.0.1:47888, and
                        // 18:49:44Z on 127.0.0.1:42228 after bare product-NATS RestartAsync
                        // reloads the same expired platform leaf;
                        // cid 32 → 71 → 41 → 51 → 45 for CN=sfo-platform on sfo-product-nats-1,
                        // fingerprint a42bd88ac488… — five-occurrence post-recycle reconnect twin
                        // of d739f8d83bed… / b1723b879b59… / 77220dace263… (and gru 0cbc78bc3a3a…
                        // / 1364f1b0cdbc… / 0b23b4fb5a75…, fra 30e9c320e15b…) against the same
                        // a914ebca… leaf at 18:45:46Z on 127.0.0.1:39118, 18:46:46Z on
                        // 127.0.0.1:59808, 18:47:46Z on 127.0.0.1:47908, 18:48:46Z on
                        // 127.0.0.1:54714, and 18:50:46Z on 127.0.0.1:60650 after bare
                        // product-NATS RestartAsync reloads the same expired platform leaf;
                        // cid 33 → 72 for CN=sfo-platform on sfo-product-nats-1,
                        // fingerprint 9f8f5f2cd955… — two-occurrence post-recycle reconnect twin
                        // of a42bd88ac488… / d739f8d83bed… / b1723b879b59… / 77220dace263… (and
                        // gru 6a1c43a93378…, fra fc4e0317d2a1…) against the same a914ebca… leaf
                        // at 18:45:48Z on 127.0.0.1:39126 and 18:46:48Z on 127.0.0.1:59822 after
                        // bare product-NATS RestartAsync reloads the same expired platform leaf;
                        // cid 34 → 36 for CN=sfo-platform on sfo-product-nats-1,
                        // fingerprint 146c64f3fc52… — two-occurrence post-recycle reconnect twin
                        // of 9f8f5f2cd955… / a42bd88ac488… / d739f8d83bed… / b1723b879b59… /
                        // 77220dace263… (and operator-read twins f4f92376efda… / 62860f83eeb6…
                        // at the same wall-clock pair) against the same a914ebca… leaf at
                        // 18:45:50Z on 127.0.0.1:39142 and 18:49:50Z on 127.0.0.1:57178 after
                        // bare product-NATS RestartAsync reloads the same expired platform leaf;
                        // cid 35 → 74 → 42 for CN=sfo-platform on sfo-product-nats-1,
                        // fingerprint eaa27086a65c… — three-occurrence post-recycle reconnect twin
                        // of 146c64f3fc52… / 9f8f5f2cd955… / a42bd88ac488… / d739f8d83bed… /
                        // b1723b879b59… / 77220dace263… (and gru ed3f4504d5e1… / fra 92ed0baffd5b…
                        // / operator-read twins f4f92376efda… / 62860f83eeb6… at adjacent
                        // wall-clock :50/:51 steps) against the same a914ebca… leaf at
                        // 18:45:51Z on 127.0.0.1:39154, 18:46:51Z on 127.0.0.1:59850, and
                        // 18:47:51Z on 127.0.0.1:47938 after bare product-NATS RestartAsync
                        // reloads the same expired platform leaf;
                        // cid 36 → 75 for CN=sfo-platform on sfo-product-nats-1,
                        // fingerprint e33d87402e17… — two-occurrence post-recycle reconnect twin
                        // of eaa27086a65c… / 146c64f3fc52… / 9f8f5f2cd955… / a42bd88ac488… /
                        // d739f8d83bed… / b1723b879b59… / 77220dace263… (and fra 7904dd055f87…
                        // / gru b22018f7aa7b… at adjacent wall-clock :52/:53 steps) against the
                        // same a914ebca… leaf at 18:45:53Z on 127.0.0.1:39168 and 18:46:53Z on
                        // 127.0.0.1:59854 after bare product-NATS RestartAsync reloads the same
                        // expired platform leaf;
                        // cid 37 → 76 → 77 for CN=sfo-platform on sfo-product-nats-1,
                        // fingerprint 16f64e5cf6e5… — three-occurrence post-recycle reconnect twin
                        // of e33d87402e17… / eaa27086a65c… / 146c64f3fc52… / 9f8f5f2cd955… /
                        // a42bd88ac488… / d739f8d83bed… / b1723b879b59… / 77220dace263… (and
                        // fra 5804cb3aaf61… / gru 9371738eec92… at adjacent wall-clock :54/:55
                        // steps) against the same a914ebca… leaf at 18:45:55Z on
                        // 127.0.0.1:45918 and 18:46:55Z on 127.0.0.1:39530 / 127.0.0.1:39552
                        // (dual cid 76+77) after bare product-NATS RestartAsync reloads the same
                        // expired platform leaf;
                        // cid 38 → 37 for CN=sfo-platform on sfo-product-nats-1,
                        // fingerprint 26b95f54769c… — two-occurrence post-recycle reconnect twin
                        // of 16f64e5cf6e5… / e33d87402e17… / eaa27086a65c… / 146c64f3fc52… /
                        // 9f8f5f2cd955… / a42bd88ac488… / d739f8d83bed… / b1723b879b59… /
                        // 77220dace263… (and gru be7bee33b946… / gru operator-read b252d8996050… /
                        // gru-controller a9bf884a363b… / sfo operator-read 97d33257778a… /
                        // fra operator-read c74671d2c0e4… at the same wall-clock :56 steps)
                        // against the same a914ebca… leaf at 18:45:56Z on 127.0.0.1:45940 and
                        // 18:49:56Z on 127.0.0.1:41844 after bare product-NATS RestartAsync
                        // reloads the same expired platform leaf;
                        // cid 39 → 78 → 43 for CN=sfo-platform on sfo-product-nats-1,
                        // fingerprint 9b960cc93f83… — three-occurrence post-recycle reconnect twin
                        // of 26b95f54769c… / 16f64e5cf6e5… / e33d87402e17… / eaa27086a65c… /
                        // 146c64f3fc52… / 9f8f5f2cd955… / a42bd88ac488… / d739f8d83bed… /
                        // b1723b879b59… / 77220dace263… (and gru be7bee33b946… / fra 5d30a28d7f44…
                        // / gru operator-read b252d8996050… / gru-controller a9bf884a363b… /
                        // sfo operator-read 97d33257778a… / fra operator-read c74671d2c0e4… at
                        // adjacent wall-clock :56/:57 steps) against the same a914ebca… leaf at
                        // 18:45:57Z on 127.0.0.1:45942, 18:46:57Z on 127.0.0.1:39560, and
                        // 18:47:57Z on 127.0.0.1:52548 after bare product-NATS RestartAsync
                        // reloads the same expired platform leaf;
                        // cid 40 → 79 for CN=sfo-platform on sfo-product-nats-1,
                        // fingerprint bf521ed338de… — two-occurrence post-recycle reconnect twin
                        // of 9b960cc93f83… / 26b95f54769c… / 16f64e5cf6e5… / e33d87402e17… /
                        // eaa27086a65c… / 146c64f3fc52… / 9f8f5f2cd955… / a42bd88ac488… /
                        // d739f8d83bed… / b1723b879b59… / 77220dace263… (and gru a2e01c16a27c… /
                        // fra 639501fa4228… / gru be7bee33b946… / fra 5d30a28d7f44… / gru
                        // operator-read b252d8996050… / gru-controller a9bf884a363b… / sfo
                        // operator-read 97d33257778a… / fra operator-read c74671d2c0e4… at
                        // adjacent wall-clock :57/:58/:59 steps) against the same a914ebca…
                        // leaf at 18:45:59Z on 127.0.0.1:45954 and 18:46:59Z on
                        // 127.0.0.1:39572 after bare product-NATS RestartAsync reloads the same
                        // expired platform leaf;
                        // cid 41 → 42 → 80 → 81 for CN=sfo-platform on sfo-product-nats-1,
                        // fingerprint eacb3282ca0c… — four-occurrence dual-reconnect post-recycle
                        // twin of bf521ed338de… / 9b960cc93f83… / 26b95f54769c… / 16f64e5cf6e5… /
                        // e33d87402e17… / eaa27086a65c… / 146c64f3fc52… / 9f8f5f2cd955… /
                        // a42bd88ac488… / d739f8d83bed… / b1723b879b59… / 77220dace263… (and fra
                        // eebfa17cec6b… cid 41 → 80 / gru 764b28c3439a… cid 42 → 81 / gru
                        // a2e01c16a27c… / fra 639501fa4228… / gru be7bee33b946… / fra
                        // 5d30a28d7f44… / gru operator-read b252d8996050… / gru-controller
                        // a9bf884a363b… / 25b92b919c66… / sfo operator-read 97d33257778a… / fra
                        // operator-read c74671d2c0e4… at the same wall-clock 18:46:01Z /
                        // 18:47:01Z steps) against the same a914ebca… leaf at 18:46:01Z on
                        // 127.0.0.1:45962 / 127.0.0.1:45986 (dual cid 41+42) and 18:47:01Z on
                        // 127.0.0.1:39584 / 127.0.0.1:39598 (dual cid 80+81) after bare
                        // product-NATS RestartAsync reloads the same expired platform leaf;
                        // cid 43 → 82 → 38 for CN=sfo-platform on sfo-product-nats-1,
                        // fingerprint c907c56a7c0c… — three-occurrence post-recycle reconnect twin
                        // of eacb3282ca0c… / bf521ed338de… / 9b960cc93f83… / 26b95f54769c… /
                        // 16f64e5cf6e5… / e33d87402e17… / eaa27086a65c… / 146c64f3fc52… /
                        // 9f8f5f2cd955… / a42bd88ac488… / d739f8d83bed… / b1723b879b59… /
                        // 77220dace263… (and fra 67d134aeab25… cid 43 → 38 / gru 6d84bda1e560…
                        // cid 43 → 82 / gru 5990e53d2fde… cid 44 → 83 / gru 764b28c3439a…
                        // cid 42 → 81 / fra 669e26dad203… cid 42 → 81 at the adjacent wall-clock
                        // 18:46:01Z / 18:46:02Z / 18:46:03Z / 18:47:01Z / 18:47:02Z / 18:47:03Z /
                        // 18:50:03Z steps) against the same a914ebca… leaf at 18:46:03Z on
                        // 127.0.0.1:45990, 18:47:03Z on 127.0.0.1:39600, and 18:50:03Z on
                        // 127.0.0.1:41872 after bare product-NATS RestartAsync reloads the same
                        // expired platform leaf;
                        // cid 44 → 83 for CN=sfo-platform on sfo-product-nats-1,
                        // fingerprint b439248687d8… — two-occurrence post-recycle reconnect twin
                        // of c907c56a7c0c… / eacb3282ca0c… / bf521ed338de… / 9b960cc93f83… /
                        // 26b95f54769c… / 16f64e5cf6e5… / e33d87402e17… / eaa27086a65c… /
                        // 146c64f3fc52… / 9f8f5f2cd955… / a42bd88ac488… / d739f8d83bed… /
                        // b1723b879b59… / 77220dace263… (and gru 5990e53d2fde… cid 44 → 83 /
                        // fra b8e719ba13ca… cid:44 / gru 3f4dc73e62f2… cid 45 → 84 → 44 → 54 /
                        // gru 6d84bda1e560… cid 43 → 82 / fra 67d134aeab25… cid 43 → 38 at the
                        // adjacent wall-clock 18:46:02Z / 18:46:03Z / 18:46:04Z / 18:46:05Z /
                        // 18:47:02Z / 18:47:03Z / 18:47:05Z steps) against the same a914ebca…
                        // leaf at 18:46:05Z on 127.0.0.1:36238 and 18:47:05Z on 127.0.0.1:46560
                        // after bare product-NATS RestartAsync reloads the same expired
                        // platform leaf;
                        // cid 45 → 46 → 84 → 85 for CN=sfo-platform on sfo-product-nats-1,
                        // fingerprint ef71b6e32493… — four-occurrence dual-cid post-recycle
                        // reconnect twin of b439248687d8… / c907c56a7c0c… / eacb3282ca0c… /
                        // bf521ed338de… / 9b960cc93f83… / 26b95f54769c… / 16f64e5cf6e5… /
                        // e33d87402e17… / eaa27086a65c… / 146c64f3fc52… / 9f8f5f2cd955… /
                        // a42bd88ac488… / d739f8d83bed… / b1723b879b59… / 77220dace263… (and
                        // fra aae9c8a6b484… cid 45 → 46 → 84 → 85 / gru e962f4a49508… cid 46 →
                        // 85 / gru 3f4dc73e62f2… cid 45 → 84 → 44 → 54 / gru 5990e53d2fde…
                        // cid 44 → 83 / fra b8e719ba13ca… cid:44 / gru 6d84bda1e560… cid 43 →
                        // 82 / fra 67d134aeab25… cid 43 → 38 at the adjacent wall-clock
                        // 18:46:02Z / 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z /
                        // 18:46:07Z / 18:47:02Z / 18:47:03Z / 18:47:05Z / 18:47:06Z /
                        // 18:47:07Z steps) against the same a914ebca… leaf at 18:46:07Z on
                        // 127.0.0.1:36252 / 127.0.0.1:36270 (dual cid 45+46) and 18:47:07Z on
                        // 127.0.0.1:46566 / 127.0.0.1:46574 (dual cid 84+85) after bare
                        // product-NATS RestartAsync reloads the same expired platform leaf;
                        // cid 47 → 86 → 39 for CN=sfo-platform on sfo-product-nats-1,
                        // fingerprint 02525de8dfa3… — three-occurrence sparse post-recycle
                        // reconnect twin of ef71b6e32493… / b439248687d8… / c907c56a7c0c… /
                        // eacb3282ca0c… / bf521ed338de… / 9b960cc93f83… / 26b95f54769c… /
                        // 16f64e5cf6e5… / e33d87402e17… / eaa27086a65c… / 146c64f3fc52… /
                        // 9f8f5f2cd955… / a42bd88ac488… / d739f8d83bed… / b1723b879b59… /
                        // 77220dace263… (and fra a66e03d58e6a… cid 47 → 86 → 39 / gru
                        // 6be7ec00050d… cid 48 → 87 / gru 0401b56675fd… cid 47 → 86 / gru
                        // e962f4a49508… cid 46 → 85 / gru 3f4dc73e62f2… cid 45 → 84 → 44 → 54 /
                        // gru 5990e53d2fde… cid 44 → 83 / fra aae9c8a6b484… dual cid 45+46 →
                        // 84+85 / fra b8e719ba13ca… cid:44 / fra 67d134aeab25… cid 43 → 38 at
                        // the adjacent wall-clock 18:46:03Z / 18:46:04Z / 18:46:05Z /
                        // 18:46:06Z / 18:46:07Z / 18:46:08Z / 18:46:09Z / 18:47:03Z /
                        // 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z / 18:47:08Z /
                        // 18:47:09Z / 18:50:09Z steps) against the same a914ebca… leaf at
                        // 18:46:09Z on 127.0.0.1:36278, 18:47:09Z on 127.0.0.1:46582, and
                        // 18:50:09Z on 127.0.0.1:45784 after bare product-NATS RestartAsync
                        // reloads the same expired platform leaf;
                        // cid 48 → 87 for CN=sfo-platform on sfo-product-nats-1,
                        // fingerprint 67300e8b3fe0… — two-occurrence post-recycle reconnect twin
                        // of 02525de8dfa3… / ef71b6e32493… / b439248687d8… / c907c56a7c0c… /
                        // eacb3282ca0c… / bf521ed338de… / 9b960cc93f83… / 26b95f54769c… /
                        // 16f64e5cf6e5… / e33d87402e17… / eaa27086a65c… / 146c64f3fc52… /
                        // 9f8f5f2cd955… / a42bd88ac488… / d739f8d83bed… / b1723b879b59… /
                        // 77220dace263… (and fra a87539b37de1… cid 48 → 87 / gru 8a0aaf8cb1da…
                        // cid 49 → 88 → 45 → 55 / fra a66e03d58e6a… cid 47 → 86 → 39 / gru
                        // 6be7ec00050d… cid 48 → 87 / gru 0401b56675fd… cid 47 → 86 / gru
                        // e962f4a49508… cid 46 → 85 / gru 3f4dc73e62f2… cid 45 → 84 → 44 → 54 /
                        // gru 5990e53d2fde… cid 44 → 83 / fra aae9c8a6b484… dual cid 45+46 →
                        // 84+85 / fra b8e719ba13ca… cid:44 / fra 67d134aeab25… cid 43 → 38 at
                        // the adjacent wall-clock 18:46:03Z / 18:46:04Z / 18:46:05Z /
                        // 18:46:06Z / 18:46:07Z / 18:46:08Z / 18:46:09Z / 18:46:10Z /
                        // 18:46:11Z / 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z /
                        // 18:47:07Z / 18:47:08Z / 18:47:09Z / 18:47:10Z / 18:47:11Z /
                        // 18:50:09Z steps) against the same a914ebca… leaf at 18:46:11Z on
                        // 127.0.0.1:36290 and 18:47:11Z on 127.0.0.1:46596 after bare
                        // product-NATS RestartAsync reloads the same expired platform leaf;
                        // cid 49 → 50 → 88 → 89 for CN=sfo-platform on sfo-product-nats-1,
                        // fingerprint e583d837318a… — four-occurrence dual-cid post-recycle
                        // reconnect twin of 67300e8b3fe0… / 02525de8dfa3… / ef71b6e32493… /
                        // b439248687d8… / c907c56a7c0c… / eacb3282ca0c… / bf521ed338de… /
                        // 9b960cc93f83… / 26b95f54769c… / 16f64e5cf6e5… / e33d87402e17… /
                        // eaa27086a65c… / 146c64f3fc52… / 9f8f5f2cd955… / a42bd88ac488… /
                        // d739f8d83bed… / b1723b879b59… / 77220dace263… (and fra d86f81358e32…
                        // cid 49 → 50 → 88 → 89 / fra a87539b37de1… cid 48 → 87 / gru
                        // 897b9ff7b37e… cid 50 → 89 / gru 8a0aaf8cb1da… cid 49 → 88 → 45 → 55 /
                        // fra a66e03d58e6a… cid 47 → 86 → 39 / gru 6be7ec00050d… cid 48 → 87 /
                        // gru 0401b56675fd… cid 47 → 86 / gru e962f4a49508… cid 46 → 85 / gru
                        // 3f4dc73e62f2… cid 45 → 84 → 44 → 54 / gru 5990e53d2fde… cid 44 → 83 /
                        // fra aae9c8a6b484… dual cid 45+46 → 84+85 / fra b8e719ba13ca… cid:44 /
                        // fra 67d134aeab25… cid 43 → 38 at the adjacent wall-clock 18:46:03Z /
                        // 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z /
                        // 18:46:09Z / 18:46:10Z / 18:46:11Z / 18:46:12Z / 18:46:13Z /
                        // 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z /
                        // 18:47:08Z / 18:47:09Z / 18:47:10Z / 18:47:11Z / 18:47:12Z /
                        // 18:47:13Z / 18:50:09Z steps) against the same a914ebca… leaf at
                        // 18:46:13Z on 127.0.0.1:36302 / 127.0.0.1:36324 (dual cid 49+50) and
                        // 18:47:13Z on 127.0.0.1:46602 / 127.0.0.1:46614 (dual cid 88+89) after
                        // bare product-NATS RestartAsync reloads the same expired platform leaf;
                        // cid 51 → 90 → 46 → 40 for CN=sfo-platform on sfo-product-nats-1,
                        // fingerprint e7810573222a… — four-occurrence sparse post-recycle
                        // reconnect twin of e583d837318a… / 67300e8b3fe0… / 02525de8dfa3… /
                        // ef71b6e32493… / b439248687d8… / c907c56a7c0c… / eacb3282ca0c… /
                        // bf521ed338de… / 9b960cc93f83… / 26b95f54769c… / 16f64e5cf6e5… /
                        // e33d87402e17… / eaa27086a65c… / 146c64f3fc52… / 9f8f5f2cd955… /
                        // a42bd88ac488… / d739f8d83bed… / b1723b879b59… / 77220dace263… (and
                        // fra bf210e609e7f… cid 51 → 90 → 47 → 40 / gru f106e39e815f… cid 52 →
                        // 91 / gru 88ff8c404d3b… cid 51 → 90 / fra d86f81358e32… cid 49 → 50 →
                        // 88 → 89 / gru 897b9ff7b37e… cid 50 → 89 / gru 8a0aaf8cb1da… cid 49 →
                        // 88 → 45 → 55 / fra a87539b37de1… cid 48 → 87 / fra a66e03d58e6a…
                        // cid 47 → 86 → 39 / gru 6be7ec00050d… cid 48 → 87 / gru 0401b56675fd…
                        // cid 47 → 86 / gru e962f4a49508… cid 46 → 85 / gru 3f4dc73e62f2… cid
                        // 45 → 84 → 44 → 54 / gru 5990e53d2fde… cid 44 → 83 / fra aae9c8a6b484…
                        // dual cid 45+46 → 84+85 / fra b8e719ba13ca… cid:44 / fra
                        // 67d134aeab25… cid 43 → 38 at the adjacent wall-clock 18:46:03Z /
                        // 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z /
                        // 18:46:09Z / 18:46:10Z / 18:46:11Z / 18:46:12Z / 18:46:13Z /
                        // 18:46:14Z / 18:46:15Z / 18:47:03Z / 18:47:04Z / 18:47:05Z /
                        // 18:47:06Z / 18:47:07Z / 18:47:08Z / 18:47:09Z / 18:47:10Z /
                        // 18:47:11Z / 18:47:12Z / 18:47:13Z / 18:47:14Z / 18:47:15Z /
                        // 18:48:10Z / 18:48:15Z / 18:49:10Z / 18:50:09Z / 18:50:15Z steps)
                        // against the same a914ebca… leaf at 18:46:15Z on 127.0.0.1:59838,
                        // 18:47:15Z on 127.0.0.1:55568, 18:48:15Z on 127.0.0.1:35124, and
                        // 18:50:15Z on 127.0.0.1:42264 after bare product-NATS RestartAsync
                        // reloads the same expired platform leaf;
                        // cid 52 → 91 for CN=sfo-platform on sfo-product-nats-1,
                        // fingerprint e7adbe3390eb… — two-occurrence post-recycle reconnect twin
                        // of e7810573222a… / e583d837318a… / 67300e8b3fe0… / 02525de8dfa3… /
                        // ef71b6e32493… / b439248687d8… / c907c56a7c0c… / eacb3282ca0c… /
                        // bf521ed338de… / 9b960cc93f83… / 26b95f54769c… / 16f64e5cf6e5… /
                        // e33d87402e17… / eaa27086a65c… / 146c64f3fc52… / 9f8f5f2cd955… /
                        // a42bd88ac488… / d739f8d83bed… / b1723b879b59… / 77220dace263… (and
                        // fra ec156a1db321… cid 52 → 91 / gru d0feba5039c6… cid:53 / fra
                        // bf210e609e7f… cid 51 → 90 → 47 → 40 / gru f106e39e815f… cid 52 → 91 /
                        // gru 88ff8c404d3b… cid 51 → 90 / fra d86f81358e32… cid 49 → 50 →
                        // 88 → 89 / gru 897b9ff7b37e… cid 50 → 89 / gru 8a0aaf8cb1da… cid 49 →
                        // 88 → 45 → 55 / fra a87539b37de1… cid 48 → 87 / fra a66e03d58e6a…
                        // cid 47 → 86 → 39 / gru 6be7ec00050d… cid 48 → 87 / gru 0401b56675fd…
                        // cid 47 → 86 / gru e962f4a49508… cid 46 → 85 / gru 3f4dc73e62f2… cid
                        // 45 → 84 → 44 → 54 / gru 5990e53d2fde… cid 44 → 83 / fra aae9c8a6b484…
                        // dual cid 45+46 → 84+85 / fra b8e719ba13ca… cid:44 / fra
                        // 67d134aeab25… cid 43 → 38 at the adjacent wall-clock 18:46:03Z /
                        // 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z /
                        // 18:46:09Z / 18:46:10Z / 18:46:11Z / 18:46:12Z / 18:46:13Z /
                        // 18:46:14Z / 18:46:15Z / 18:46:17Z / 18:47:03Z / 18:47:04Z /
                        // 18:47:05Z / 18:47:06Z / 18:47:07Z / 18:47:08Z / 18:47:09Z /
                        // 18:47:10Z / 18:47:11Z / 18:47:12Z / 18:47:13Z / 18:47:14Z /
                        // 18:47:15Z / 18:47:17Z / 18:48:10Z / 18:48:15Z / 18:49:10Z /
                        // 18:50:09Z / 18:50:15Z steps) against the same a914ebca… leaf at
                        // 18:46:17Z on 127.0.0.1:59852 and 18:47:17Z on 127.0.0.1:55584 after
                        // bare product-NATS RestartAsync reloads the same expired platform leaf;
                        // cid 53 → 54 → 92 → 93 → 31 for CN=sfo-platform on sfo-product-nats-1,
                        // fingerprint 1668f8c0e10f… — five-occurrence post-recycle reconnect twin
                        // of e7adbe3390eb… / e7810573222a… / e583d837318a… / 67300e8b3fe0… /
                        // 02525de8dfa3… / ef71b6e32493… / b439248687d8… / c907c56a7c0c… /
                        // eacb3282ca0c… / bf521ed338de… / 9b960cc93f83… / 26b95f54769c… /
                        // 16f64e5cf6e5… / e33d87402e17… / eaa27086a65c… / 146c64f3fc52… /
                        // 9f8f5f2cd955… / a42bd88ac488… / d739f8d83bed… / b1723b879b59… /
                        // 77220dace263… (and fra 59a0656971a4… cid 53 → 54 → 92 → 93 → 31 /
                        // fra ec156a1db321… cid 52 → 91 / gru 1f9106a25f41… cid 54 → 55 → 94 →
                        // 31 / gru d0feba5039c6… cid:53 / fra bf210e609e7f… cid 51 → 90 → 47 →
                        // 40 / gru f106e39e815f… cid 52 → 91 / gru 88ff8c404d3b… cid 51 → 90 /
                        // fra d86f81358e32… cid 49 → 50 → 88 → 89 / gru 897b9ff7b37e… cid 50 →
                        // 89 / gru 8a0aaf8cb1da… cid 49 → 88 → 45 → 55 / fra a87539b37de1…
                        // cid 48 → 87 / fra a66e03d58e6a… cid 47 → 86 → 39 / gru 6be7ec00050d…
                        // cid 48 → 87 / gru 0401b56675fd… cid 47 → 86 / gru e962f4a49508… cid
                        // 46 → 85 / gru 3f4dc73e62f2… cid 45 → 84 → 44 → 54 / gru 5990e53d2fde…
                        // cid 44 → 83 / fra aae9c8a6b484… dual cid 45+46 → 84+85 / fra
                        // b8e719ba13ca… cid:44 / fra 67d134aeab25… cid 43 → 38 at the adjacent
                        // wall-clock 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z /
                        // 18:46:07Z / 18:46:08Z / 18:46:09Z / 18:46:10Z / 18:46:11Z /
                        // 18:46:12Z / 18:46:13Z / 18:46:14Z / 18:46:15Z / 18:46:17Z /
                        // 18:46:19Z / 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z /
                        // 18:47:07Z / 18:47:08Z / 18:47:09Z / 18:47:10Z / 18:47:11Z /
                        // 18:47:12Z / 18:47:13Z / 18:47:14Z / 18:47:15Z / 18:47:17Z /
                        // 18:47:19Z / 18:48:10Z / 18:48:15Z / 18:49:10Z / 18:49:19Z /
                        // 18:50:09Z / 18:50:15Z steps) against the same a914ebca… leaf at
                        // 18:46:19Z on 127.0.0.1:59860 and 127.0.0.1:59878, 18:47:19Z on
                        // 127.0.0.1:55608 and 127.0.0.1:55624, and 18:49:19Z on 127.0.0.1:56818
                        // after bare product-NATS RestartAsync reloads the same expired
                        // platform leaf;
                        // cid 55 → 94 → 47 → 41 for CN=sfo-platform on sfo-product-nats-1,
                        // fingerprint 230da24f64b6… — four-occurrence post-recycle reconnect twin
                        // of 1668f8c0e10f… / e7adbe3390eb… / e7810573222a… / e583d837318a… /
                        // 67300e8b3fe0… / 02525de8dfa3… / ef71b6e32493… / b439248687d8… /
                        // c907c56a7c0c… / eacb3282ca0c… / bf521ed338de… / 9b960cc93f83… /
                        // 26b95f54769c… / 16f64e5cf6e5… / e33d87402e17… / eaa27086a65c… /
                        // 146c64f3fc52… / 9f8f5f2cd955… / a42bd88ac488… / d739f8d83bed… /
                        // b1723b879b59… / 77220dace263… (and fra 8e310ea4f277… cid 55 → 94 →
                        // 48 → 41 / gru 7dae08a6f4b3… cid 56 → 47 → 41 / fra 59a0656971a4…
                        // cid 53 → 54 → 92 → 93 → 31 / fra ec156a1db321… cid 52 → 91 / gru
                        // 1f9106a25f41… cid 54 → 55 → 94 → 31 / gru d0feba5039c6… cid:53 /
                        // fra bf210e609e7f… cid 51 → 90 → 47 → 40 / gru f106e39e815f… cid 52 →
                        // 91 / gru 88ff8c404d3b… cid 51 → 90 / fra d86f81358e32… cid 49 → 50 →
                        // 88 → 89 / gru 897b9ff7b37e… cid 50 → 89 / gru 8a0aaf8cb1da… cid 49 →
                        // 88 → 45 → 55 / fra a87539b37de1… cid 48 → 87 / fra a66e03d58e6a…
                        // cid 47 → 86 → 39 / gru 6be7ec00050d… cid 48 → 87 / gru 0401b56675fd…
                        // cid 47 → 86 / gru e962f4a49508… cid 46 → 85 / gru 3f4dc73e62f2… cid
                        // 45 → 84 → 44 → 54 / gru 5990e53d2fde… cid 44 → 83 / fra aae9c8a6b484…
                        // dual cid 45+46 → 84+85 / fra b8e719ba13ca… cid:44 / fra
                        // 67d134aeab25… cid 43 → 38 at the adjacent wall-clock 18:46:03Z /
                        // 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z /
                        // 18:46:09Z / 18:46:10Z / 18:46:11Z / 18:46:12Z / 18:46:13Z /
                        // 18:46:14Z / 18:46:15Z / 18:46:17Z / 18:46:19Z / 18:46:21Z /
                        // 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z /
                        // 18:47:08Z / 18:47:09Z / 18:47:10Z / 18:47:11Z / 18:47:12Z /
                        // 18:47:13Z / 18:47:14Z / 18:47:15Z / 18:47:17Z / 18:47:19Z /
                        // 18:47:21Z / 18:48:10Z / 18:48:15Z / 18:48:21Z / 18:49:10Z /
                        // 18:49:19Z / 18:50:09Z / 18:50:15Z / 18:50:21Z steps) against the
                        // same a914ebca… leaf at 18:46:21Z on 127.0.0.1:59888, 18:47:21Z on
                        // 127.0.0.1:55626, 18:48:21Z on 127.0.0.1:35130, and 18:50:21Z on
                        // 127.0.0.1:42286 after bare product-NATS RestartAsync reloads the same
                        // expired platform leaf (two seconds after 1668f8c0e10f… cid 53 → 54 →
                        // 92 → 93 → 31 on adjacent :19 steps / ports 59860/59878 → 59888 and
                        // 55608/55624 → 55626; same wall-clock :21 as fra 8e310ea4f277… /
                        // gru 7dae08a6f4b3…);
                        // cid 56 → 95 for CN=sfo-platform on sfo-product-nats-1,
                        // fingerprint db61915863fe… — two-occurrence post-recycle reconnect twin
                        // of 230da24f64b6… / 1668f8c0e10f… / e7adbe3390eb… / e7810573222a… /
                        // e583d837318a… / 67300e8b3fe0… / 02525de8dfa3… / ef71b6e32493… /
                        // b439248687d8… / c907c56a7c0c… / eacb3282ca0c… / bf521ed338de… /
                        // 9b960cc93f83… / 26b95f54769c… / 16f64e5cf6e5… / e33d87402e17… /
                        // eaa27086a65c… / 146c64f3fc52… / 9f8f5f2cd955… / a42bd88ac488… /
                        // d739f8d83bed… / b1723b879b59… / 77220dace263… (and gru d22a1e331a57…
                        // cid 57 → 96 / gru 7dae08a6f4b3… cid 56 → 47 → 41 / fra 8e310ea4f277…
                        // cid 55 → 94 → 48 → 41 / fra 59a0656971a4… cid 53 → 54 → 92 → 93 →
                        // 31 / gru 1f9106a25f41… cid 54 → 55 → 94 → 31 at the adjacent
                        // wall-clock 18:46:19Z / 18:46:21Z / 18:46:23Z / 18:46:24Z /
                        // 18:47:19Z / 18:47:21Z / 18:47:23Z / 18:47:24Z steps) against the
                        // same a914ebca… leaf at 18:46:24Z on 127.0.0.1:59904 and 18:47:24Z
                        // on 127.0.0.1:55638 after bare product-NATS RestartAsync reloads the
                        // same expired platform leaf (three seconds after 230da24f64b6… cid
                        // 55 → 94 → 47 → 41 on adjacent :21 steps / ports 59888 → 59904 and
                        // 55626 → 55638; five seconds after 1668f8c0e10f… cid 53 → 54 → 92 →
                        // 93 → 31 on :19 steps / ports 59860/59878 → 59904).
                        //
                        // Plain "can not start to connect nats server" (fingerprint
                        // c05d3fee208c… / gru-control-nats-1 at 18:45:41Z / 18:49:11Z three
                        // bare restarts on nats://127.0.0.1:18600; fingerprint b0ca5ad6b00f…
                        // / sfo-control-nats-1 at 18:45:42Z / 18:49:12Z three bare restarts
                        // on nats://127.0.0.1:18800; fingerprint 1e57af750edb… /
                        // fra-control-nats-1 at 18:45:44Z / 18:49:13Z three bare restarts on
                        // nats://127.0.0.1:19000; fingerprint 2c66150c157c… /
                        // gru-product-nats-1 at 18:45:42Z / 18:49:12Z three bare restarts on
                        // nats://127.0.0.1:18620; fingerprint 666f072201a5… /
                        // sfo-product-nats-1 at 18:45:43Z / 18:49:13Z three bare restarts on
                        // nats://127.0.0.1:18820; fingerprint 6da1925a9038… /
                        // fra-product-nats-1 at 18:45:44Z / 18:49:14Z three bare restarts on
                        // nats://127.0.0.1:19020; fingerprint 7bead2653aa7… / gru-controller-1
                        // at 18:45:42Z / 18:49:12Z three bare restarts with the same outer
                        // text on nats://127.0.0.1:18600; fingerprint bfa083ed37ee… /
                        // sfo-controller-1 at 18:45:44Z / 18:49:13Z three bare restarts with
                        // the same outer text on nats://127.0.0.1:18800; fingerprint
                        // e1c5c64cbb9d… / fra-controller-1 at 18:45:45Z / 18:49:20Z three bare
                        // restarts with the same outer text on nats://127.0.0.1:19000; twins
                        // on every cell's control NATS, product NATS, and controller) is the
                        // client-side outer NATS.Net message when handshakes fail or the
                        // listener is mid-recycle.
                        // LooksLikeCertificateFailure is false for that outer text alone,
                        // so the cert-shaped branch above can miss it. Control/product NATS
                        // and controllers must never bare-RestartAsync on persistent
                        // unhealth: remint rewrites PEMs and restarts the full mTLS consumer
                        // set with WaitReadyAsync instead of thrashing one NATS member or
                        // controller every ~105s (90s grace + 3×5s failures).
                        if ((observationCertificateFailure ||
                             ResourceHasInvalidTlsLeaf(topology, natsSecurity, observation.Key) ||
                             RequiresForceRemintOnPersistentUnhealth(topology, observation.Key) ||
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
    /// fingerprint 9815ef5a… / sfo-control-nats CN=sfo-controller-1 cid 29240 → 34 → 35 → 66 → 73
    /// at 18:45:40Z / 18:47:40Z / 18:47:40Z / 18:48:40Z / 18:50:40Z against the same f56fe7a4…
    /// leaf — denser five-occurrence twin of f490b625…,
    /// fingerprint 4eeeee0520a1… / sfo-control-nats CN=sfo-controller-1 cid 28 → 36 at
    /// 18:45:45Z on 127.0.0.1:50552 and 18:47:45Z on 127.0.0.1:37302 against the same
    /// f56fe7a4… leaf — two-occurrence post-recycle reconnect twin of f490b625… /
    /// 9815ef5a… after bare control-NATS RestartAsync,
    /// fingerprint e8e55fe0bef9… / sfo-control-nats CN=sfo-controller-1 cid 29 → 61 at
    /// 18:45:47Z on 127.0.0.1:50560 and 18:46:47Z on 127.0.0.1:55476 against the same
    /// f56fe7a4… leaf — second two-occurrence post-recycle reconnect twin of f490b625… /
    /// 9815ef5a… / 4eeeee0520a1… after bare control-NATS RestartAsync,
    /// fingerprint 412baaa56842… / sfo-control-nats CN=sfo-controller-1 cid 31 → 39 → 47 at
    /// 18:45:50Z on 127.0.0.1:50606, 18:47:50Z on 127.0.0.1:37360, and 18:49:50Z on
    /// 127.0.0.1:34092 against the same f56fe7a4… leaf — three-occurrence post-recycle
    /// reconnect twin of f490b625… / 9815ef5a… / 4eeeee0520a1… / e8e55fe0bef9… after bare
    /// control-NATS RestartAsync,
    /// fingerprint 71cf8514f4d6… / sfo-control-nats CN=sfo-controller-1 cid 32 → 41 → 71 → 48 at
    /// 18:45:51Z on 127.0.0.1:50616, 18:47:51Z on 127.0.0.1:37414, 18:48:51Z on 127.0.0.1:58882,
    /// and 18:49:51Z on 127.0.0.1:34106 against the same f56fe7a4… leaf — four-occurrence
    /// post-recycle reconnect twin of f490b625… / 9815ef5a… / 4eeeee0520a1… / e8e55fe0bef9… /
    /// 412baaa56842… after bare control-NATS RestartAsync,
    /// fingerprint ce40d219dc90… / sfo-control-nats CN=sfo-controller-1 cid 64 → 73 → 78 → 80 at
    /// 18:46:52Z on 127.0.0.1:55524, 18:48:52Z on 127.0.0.1:58922, and 18:50:52Z on
    /// 127.0.0.1:52222 / 127.0.0.1:52258 (dual cid 78+80) against the same f56fe7a4… leaf —
    /// four-occurrence post-recycle reconnect twin of f490b625… / 9815ef5a… / 4eeeee0520a1… /
    /// e8e55fe0bef9… / 412baaa56842… / 71cf8514f4d6… after bare control-NATS RestartAsync,
    /// fingerprint fc867739e2e2… / sfo-control-nats CN=sfo-controller-1 cid 34 → 35 → 74 → 49 → 51 at
    /// 18:45:56Z on 127.0.0.1:52202 / 127.0.0.1:52218 (dual cid 34+35), 18:48:56Z on
    /// 127.0.0.1:51334, and 18:49:56Z on 127.0.0.1:36626 / 127.0.0.1:36656 (dual cid 49+51)
    /// against the same f56fe7a4… leaf — five-occurrence post-recycle reconnect twin of
    /// f490b625… / 9815ef5a… / 4eeeee0520a1… / e8e55fe0bef9… / 412baaa56842… / 71cf8514f4d6… /
    /// ce40d219dc90… after bare control-NATS RestartAsync,
    /// fingerprint 3db5efff618c… / sfo-control-nats CN=sfo-controller-1 cid 36 → 38 → 69 → 77 → 52 at
    /// 18:46:01Z on 127.0.0.1:52226 / 127.0.0.1:52264 (dual cid 36+38), 18:47:01Z on
    /// 127.0.0.1:34778, 18:49:01Z on 127.0.0.1:51374, and 18:50:01Z on 127.0.0.1:36672
    /// against the same f56fe7a4… leaf — five-occurrence post-recycle reconnect twin of
    /// f490b625… / 9815ef5a… / 4eeeee0520a1… / e8e55fe0bef9… / 412baaa56842… / 71cf8514f4d6… /
    /// ce40d219dc90… / fc867739e2e2… after bare control-NATS RestartAsync,
    /// fingerprint c9f4a06686ba… / sfo-control-nats CN=sfo-controller-1 cid 39 → 80 → 55 at
    /// 18:46:06Z on 127.0.0.1:49160, 18:49:06Z on 127.0.0.1:37578, and 18:50:06Z on
    /// 127.0.0.1:48750 against the same f56fe7a4… leaf — three-occurrence post-recycle
    /// reconnect twin of f490b625… / 9815ef5a… / 4eeeee0520a1… / e8e55fe0bef9… /
    /// 412baaa56842… / 71cf8514f4d6… / ce40d219dc90… / fc867739e2e2… / 3db5efff618c… (and
    /// gru 024cbd22bdf4… cid 39 → 71 → 80 → 55 at the same wall-clock :05/:06 steps) after
    /// bare control-NATS RestartAsync,
    /// fingerprint a5ee4c55235d… / sfo-control-nats CN=sfo-controller-1 cid 41 → 71 → 73 at
    /// 18:46:07Z on 127.0.0.1:49206 and 18:47:07Z on 127.0.0.1:53864 / 127.0.0.1:53886
    /// (dual cid 71+73) against the same f56fe7a4… leaf — three-occurrence post-recycle
    /// reconnect twin of f490b625… / 9815ef5a… / 4eeeee0520a1… / e8e55fe0bef9… /
    /// 412baaa56842… / 71cf8514f4d6… / ce40d219dc90… / fc867739e2e2… / 3db5efff618c… /
    /// c9f4a06686ba… (and gru e7ad7a71e395… cid 41 → 73 / operator-read 58dda0785551… cid
    /// 40 → 72 / gru 5c56829c01e4… / fra d26af782af24… / fra-controller 88eec19ebb94… /
    /// sfo-platform ef71b6e32493… / gru-platform 0401b56675fd… at the same wall-clock
    /// :07 steps) after bare control-NATS RestartAsync,
    /// fingerprint 914b99d5fbc6… / sfo-control-nats CN=sfo-controller-1 cid 42 → 83 → 58 at
    /// 18:46:11Z on 127.0.0.1:49220, 18:49:11Z on 127.0.0.1:37634, and 18:50:11Z on
    /// 127.0.0.1:48798 against the same f56fe7a4… leaf — three-occurrence post-recycle
    /// reconnect twin of f490b625… / 9815ef5a… / 4eeeee0520a1… / e8e55fe0bef9… /
    /// 412baaa56842… / 71cf8514f4d6… / ce40d219dc90… / fc867739e2e2… / 3db5efff618c… /
    /// c9f4a06686ba… / a5ee4c55235d… (and gru 96fe8dda09bb… cid 42 → 74 → 50 → 51 → 81 →
    /// 83 → 58 at the adjacent wall-clock :10/:11 steps, sparse without the mid-window
    /// dual-cid reconnects) after bare control-NATS RestartAsync,
    /// fingerprint 53b4362b4444… / sfo-control-nats CN=sfo-controller-1 cid 44 → 76 at
    /// 18:46:13Z on 127.0.0.1:49260 and 18:47:13Z on 127.0.0.1:53940 against the same
    /// f56fe7a4… leaf — two-occurrence post-recycle reconnect twin of f490b625… /
    /// 9815ef5a… / 4eeeee0520a1… / e8e55fe0bef9… / 412baaa56842… / 71cf8514f4d6… /
    /// ce40d219dc90… / fc867739e2e2… / 3db5efff618c… / c9f4a06686ba… / a5ee4c55235d… /
    /// 914b99d5fbc6… (and gru operator-read 9dd8feb97fa2… cid 43 → 75 / fra operator-read
    /// 424b0b6af457… cid 43 → 75 / sfo-platform e583d837318a… / fra-platform d86f81358e32…
    /// at the same wall-clock :13 steps, two seconds after 914b99d5fbc6… cid 42 on adjacent
    /// port 49220) after bare control-NATS RestartAsync,
    /// fingerprint bbdb6e0d6006… / sfo-control-nats CN=sfo-controller-1 cid 45 → 29 → 61 at
    /// 18:46:16Z on 127.0.0.1:40982, 18:49:16Z on 127.0.0.1:35628, and 18:50:16Z on
    /// 127.0.0.1:52900 against the same f56fe7a4… leaf — three-occurrence post-recycle
    /// reconnect twin of f490b625… / 9815ef5a… / 4eeeee0520a1… / e8e55fe0bef9… /
    /// 412baaa56842… / 71cf8514f4d6… / ce40d219dc90… / fc867739e2e2… / 3db5efff618c… /
    /// c9f4a06686ba… / a5ee4c55235d… / 914b99d5fbc6… / 53b4362b4444… (three seconds after
    /// 53b4362b4444… cid 44 on adjacent :13 steps, and sfo peer of gru d00ef05a1026… cid
    /// 45 → 77 → 52 → 54 → 29 → 60 → 61 at the adjacent wall-clock :15 steps) after bare
    /// control-NATS RestartAsync,
    /// fingerprint 1cdbb448aebb… / sfo-control-nats CN=sfo-controller-1 cid 47 → 79 → 31 at
    /// 18:46:19Z on 127.0.0.1:41010, 18:47:19Z on 127.0.0.1:59830, and 18:49:19Z on
    /// 127.0.0.1:35648 against the same f56fe7a4… leaf — three-occurrence post-recycle
    /// reconnect twin of f490b625… / 9815ef5a… / 4eeeee0520a1… / e8e55fe0bef9… /
    /// 412baaa56842… / 71cf8514f4d6… / ce40d219dc90… / fc867739e2e2… / 3db5efff618c… /
    /// c9f4a06686ba… / a5ee4c55235d… / 914b99d5fbc6… / 53b4362b4444… / bbdb6e0d6006…
    /// (three seconds after bbdb6e0d6006… cid 45 → 29 → 61 on adjacent :16 steps /
    /// ports 40982/35628, concurrent with sfo-platform 1668f8c0e10f… at the same
    /// wall-clock :19 steps) after bare control-NATS RestartAsync,
    /// fingerprint 2e80728c5df4… / sfo-control-nats CN=sfo-controller-1 cid 48 → 57 → 63 → 64
    /// at 18:46:21Z on 127.0.0.1:41016, 18:48:21Z on 127.0.0.1:54454, and 18:50:21Z on
    /// 127.0.0.1:52952 / 127.0.0.1:52960 (dual cid 63+64) against the same f56fe7a4… leaf —
    /// four-occurrence post-recycle reconnect twin of f490b625… / 9815ef5a… /
    /// 4eeeee0520a1… / e8e55fe0bef9… / 412baaa56842… / 71cf8514f4d6… / ce40d219dc90… /
    /// fc867739e2e2… / 3db5efff618c… / c9f4a06686ba… / a5ee4c55235d… / 914b99d5fbc6… /
    /// 53b4362b4444… / bbdb6e0d6006… / 1cdbb448aebb… (two seconds after 1cdbb448aebb… cid
    /// 47 on adjacent :19 steps / port 41010 → 41016, concurrent with gru e51d12dd4525…
    /// cid 48 → 55 → 32 → 62 at the adjacent wall-clock :20/:21 steps) after bare
    /// control-NATS RestartAsync,
    /// fingerprint 306f7d4a6890… / sfo-control-nats CN=sfo-controller-1 cid 50 → 51 → 65 at
    /// 18:46:26Z on 127.0.0.1:33714 / 127.0.0.1:33728 (dual cid 50+51) and 18:50:26Z on
    /// 127.0.0.1:55442 against the same f56fe7a4… leaf — three-occurrence post-recycle
    /// reconnect twin of f490b625… / 9815ef5a… / 4eeeee0520a1… / e8e55fe0bef9… /
    /// 412baaa56842… / 71cf8514f4d6… / ce40d219dc90… / fc867739e2e2… / 3db5efff618c… /
    /// c9f4a06686ba… / a5ee4c55235d… / 914b99d5fbc6… / 53b4362b4444… / bbdb6e0d6006… /
    /// 1cdbb448aebb… / 2e80728c5df4… (five seconds after 2e80728c5df4… cid 48 → 57 → 63 →
    /// 64 on adjacent :21 steps, concurrent with gru 1455d09f7030… cid 51 → 83 at the same
    /// wall-clock :26 steps) after bare control-NATS RestartAsync,
    /// fingerprint c2bf6b539a62… / gru-control-nats CN=gru-controller-1 cid 29238 → 32 → 63 → 70,
    /// fingerprint 782d6308… / gru-control-nats CN=gru-controller-1 cid 29240 → 58 → 35 → 65 → 67 → 42 → 73
    /// at 18:45:40Z / 18:46:40Z / 18:47:40Z / 18:48:40Z / 18:48:40Z / 18:49:40Z / 18:50:40Z against
    /// the same d467c210… leaf — denser seven-occurrence twin of c2bf6b539a62…,
    /// fingerprint 003657d51ecd… / gru-control-nats CN=gru-controller-1 cid 28 → 60 at
    /// 18:45:43Z on 127.0.0.1:49796 and 18:46:43Z on 127.0.0.1:60312 against the same
    /// d467c210… leaf — two-occurrence post-recycle reconnect twin of c2bf6b539a62… /
    /// 782d6308… after bare control-NATS RestartAsync,
    /// fingerprint b9dc4dd1a8ef… / gru-control-nats CN=gru-controller-1 cid 29 → 61 → 68 → 45 at
    /// 18:45:45Z on 127.0.0.1:56146, 18:46:45Z on 127.0.0.1:57182, 18:48:45Z on 127.0.0.1:55606,
    /// and 18:49:45Z on 127.0.0.1:45982 against the same d467c210… leaf — four-occurrence
    /// post-recycle reconnect twin of c2bf6b539a62… / 782d6308… / 003657d51ecd… after bare
    /// control-NATS RestartAsync,
    /// fingerprint 7b6a047263d8… / gru-control-nats CN=gru-controller-1 cid 30 → 32 → 64 → 71 →
    /// 47 → 48 at 18:45:50Z on 127.0.0.1:56154 / 127.0.0.1:56178 (dual cid 30+32), 18:46:50Z on
    /// 127.0.0.1:57224, 18:48:50Z on 127.0.0.1:55652, and 18:49:50Z on 127.0.0.1:46006 /
    /// 127.0.0.1:46018 (dual cid 47+48) against the same d467c210… leaf — six-occurrence
    /// post-recycle reconnect twin of c2bf6b539a62… / 782d6308… / 003657d51ecd… / b9dc4dd1a8ef…
    /// after bare control-NATS RestartAsync,
    /// fingerprint 87f7f1566c88… / gru-control-nats CN=gru-controller-1 cid 33 → 67 → 65 → 74 →
    /// 49 at 18:45:55Z on 127.0.0.1:54390, 18:46:55Z on 127.0.0.1:57284 / 127.0.0.1:57238
    /// (dual cid 67+65), 18:48:55Z on 127.0.0.1:46006, and 18:49:55Z on 127.0.0.1:35748 against
    /// the same d467c210… leaf — five-occurrence post-recycle reconnect twin of c2bf6b539a62… /
    /// 782d6308… / 003657d51ecd… / b9dc4dd1a8ef… / 7b6a047263d8… after bare control-NATS
    /// RestartAsync,
    /// fingerprint a9bf884a363b… / gru-control-nats CN=gru-controller-1 cid 35 → 50 → 81 at
    /// 18:45:56Z on 127.0.0.1:54434, 18:49:56Z on 127.0.0.1:35776, and 18:50:56Z on
    /// 127.0.0.1:34540 against the same d467c210… leaf — three-occurrence post-recycle
    /// reconnect twin of c2bf6b539a62… / 782d6308… / 003657d51ecd… / b9dc4dd1a8ef… /
    /// 7b6a047263d8… / 87f7f1566c88… after bare control-NATS RestartAsync,
    /// fingerprint 25b92b919c66… / gru-control-nats CN=gru-controller-1 cid 36 → 68 → 77 → 52 at
    /// 18:46:00Z on 127.0.0.1:54442, 18:47:00Z on 127.0.0.1:57286, 18:49:00Z on
    /// 127.0.0.1:46044, and 18:50:00Z on 127.0.0.1:35784 against the same d467c210… leaf —
    /// four-occurrence post-recycle reconnect twin of c2bf6b539a62… / 782d6308… /
    /// 003657d51ecd… / b9dc4dd1a8ef… / 7b6a047263d8… / 87f7f1566c88… / a9bf884a363b… after bare
    /// control-NATS RestartAsync,
    /// fingerprint 34c89dedb769… / gru-control-nats CN=gru-controller-1 cid 38 → 70 at
    /// 18:46:01Z on 127.0.0.1:54492 and 18:47:01Z on 127.0.0.1:57318 against the same
    /// d467c210… leaf — two-occurrence post-recycle reconnect twin of c2bf6b539a62… /
    /// 782d6308… / 003657d51ecd… / b9dc4dd1a8ef… / 7b6a047263d8… / 87f7f1566c88… /
    /// a9bf884a363b… / 25b92b919c66… (and sfo 3db5efff618c… cid 36+38 / 69 at the same
    /// wall-clock :01 steps) after bare control-NATS RestartAsync,
    /// fingerprint 024cbd22bdf4… / gru-control-nats CN=gru-controller-1 cid 39 → 71 → 80 → 55
    /// at 18:46:05Z on 127.0.0.1:48986, 18:47:05Z on 127.0.0.1:42886, 18:49:05Z on
    /// 127.0.0.1:51702, and 18:50:05Z on 127.0.0.1:35504 against the same d467c210… leaf —
    /// four-occurrence post-recycle reconnect twin of c2bf6b539a62… / 782d6308… /
    /// 003657d51ecd… / b9dc4dd1a8ef… / 7b6a047263d8… / 87f7f1566c88… / a9bf884a363b… /
    /// 25b92b919c66… / 34c89dedb769… after bare control-NATS RestartAsync,
    /// fingerprint e7ad7a71e395… / gru-control-nats CN=gru-controller-1 cid 41 → 73 at
    /// 18:46:07Z on 127.0.0.1:49008 and 18:47:07Z on 127.0.0.1:42932 against the same
    /// d467c210… leaf — two-occurrence post-recycle reconnect twin of c2bf6b539a62… /
    /// 782d6308… / 003657d51ecd… / b9dc4dd1a8ef… / 7b6a047263d8… / 87f7f1566c88… /
    /// a9bf884a363b… / 25b92b919c66… / 34c89dedb769… / 024cbd22bdf4… (and operator-read
    /// 5c56829c01e4… cid 40 → 72 / sfo 58dda0785551… / fra d26af782af24… / fra-controller
    /// 88eec19ebb94… / sfo-platform ef71b6e32493… / gru-platform 0401b56675fd… at the same
    /// wall-clock :07 steps) after bare control-NATS RestartAsync,
    /// fingerprint 96fe8dda09bb… / gru-control-nats CN=gru-controller-1 cid 42 → 74 → 50 →
    /// 51 → 81 → 83 → 58 at 18:46:10Z on 127.0.0.1:49018, 18:47:10Z on 127.0.0.1:42948,
    /// 18:48:10Z on 127.0.0.1:40182 / 127.0.0.1:40194 dual, 18:49:10Z on 127.0.0.1:51716 /
    /// 127.0.0.1:51744 dual, and 18:50:10Z on 127.0.0.1:35554 against the same d467c210…
    /// leaf — seven-occurrence post-recycle reconnect twin of c2bf6b539a62… / 782d6308… /
    /// 003657d51ecd… / b9dc4dd1a8ef… / 7b6a047263d8… / 87f7f1566c88… / a9bf884a363b… /
    /// 25b92b919c66… / 34c89dedb769… / 024cbd22bdf4… / e7ad7a71e395… after bare
    /// control-NATS RestartAsync,
    /// fingerprint d2538c612184… / gru-control-nats CN=gru-controller-1 cid 44 → 76 → 28 at
    /// 18:46:13Z on 127.0.0.1:49052, 18:47:13Z on 127.0.0.1:42988, and 18:49:13Z on
    /// 127.0.0.1:51756 against the same d467c210… leaf — three-occurrence post-recycle
    /// reconnect twin of c2bf6b539a62… / 782d6308… / 003657d51ecd… / b9dc4dd1a8ef… /
    /// 7b6a047263d8… / 87f7f1566c88… / a9bf884a363b… / 25b92b919c66… / 34c89dedb769… /
    /// 024cbd22bdf4… / e7ad7a71e395… / 96fe8dda09bb… (three-seconds-later sparse twin of
    /// 96fe8dda09bb… on adjacent ports 49018 → 49052 / 42948 → 42988 / 51716 → 51756;
    /// control-plane peer of fra-controller 7063631384a4… cid 44 → 74 → 76 → 83 and
    /// product-plane peer of gru-platform 88ff8c404d3b… cid 51 → 90 at the same wall-clock
    /// :13 steps) after bare control-NATS RestartAsync,
    /// fingerprint d00ef05a1026… / gru-control-nats CN=gru-controller-1 cid 45 → 77 → 52 →
    /// 54 → 29 → 60 → 61 at 18:46:15Z on 127.0.0.1:37246, 18:47:15Z on 127.0.0.1:34118,
    /// 18:48:15Z on 127.0.0.1:52154 / 127.0.0.1:52194 dual, 18:49:15Z on 127.0.0.1:45258,
    /// and 18:50:15Z on 127.0.0.1:57522 / 127.0.0.1:57524 dual against the same d467c210…
    /// leaf — seven-occurrence post-recycle reconnect twin of c2bf6b539a62… / 782d6308… /
    /// 003657d51ecd… / b9dc4dd1a8ef… / 7b6a047263d8… / 87f7f1566c88… / a9bf884a363b… /
    /// 25b92b919c66… / 34c89dedb769… / 024cbd22bdf4… / e7ad7a71e395… / 96fe8dda09bb… /
    /// d2538c612184… (two-seconds-later denser twin of d2538c612184… on ports 37246 /
    /// 34118 / 52154 / 52194 / 45258 / 57522 / 57524; denser seven-occurrence peer of
    /// 96fe8dda09bb… cid 42 → 74 → 50 → 51 → 81 → 83 → 58 at the adjacent wall-clock :10
    /// steps) after bare control-NATS RestartAsync,
    /// fingerprint d56bf3307e7b… / gru-control-nats CN=gru-controller-1 cid 47 → 79 → 31 at
    /// 18:46:19Z on 127.0.0.1:37282, 18:47:19Z on 127.0.0.1:34142, and 18:49:19Z on
    /// 127.0.0.1:45312 against the same d467c210… leaf — three-occurrence post-recycle
    /// reconnect twin of c2bf6b539a62… / 782d6308… / 003657d51ecd… / b9dc4dd1a8ef… /
    /// 7b6a047263d8… / 87f7f1566c88… / a9bf884a363b… / 25b92b919c66… / 34c89dedb769… /
    /// 024cbd22bdf4… / e7ad7a71e395… / 96fe8dda09bb… / d2538c612184… / d00ef05a1026…
    /// (four seconds after d00ef05a1026… cid 45 on adjacent :15 steps / ports 37246 → 37282
    /// and 34118 → 34142; gru peer of sfo 1cdbb448aebb… cid 47 → 79 → 31 and fra
    /// 4cab25065be5… cid 47 → 79 → 30 at the same wall-clock :19 steps, concurrent with
    /// gru-platform 1f9106a25f41… / sfo-platform 1668f8c0e10f… / fra-platform 59a0656971a4… /
    /// gru operator-read 5807fcff9600… at the same wall-clock :19 steps) after bare
    /// control-NATS RestartAsync,
    /// fingerprint e51d12dd4525… / gru-control-nats CN=gru-controller-1 cid 48 → 55 → 32 → 62
    /// at 18:46:20Z on 127.0.0.1:37298, 18:48:20Z on 127.0.0.1:52196, 18:49:20Z on
    /// 127.0.0.1:45314, and 18:50:20Z on 127.0.0.1:57526 against the same d467c210… leaf —
    /// four-occurrence post-recycle reconnect twin of c2bf6b539a62… / 782d6308… /
    /// 003657d51ecd… / b9dc4dd1a8ef… / 7b6a047263d8… / 87f7f1566c88… / a9bf884a363b… /
    /// 25b92b919c66… / 34c89dedb769… / 024cbd22bdf4… / e7ad7a71e395… / 96fe8dda09bb… /
    /// d2538c612184… / d00ef05a1026… / d56bf3307e7b… (one second after d56bf3307e7b… cid
    /// 47 → 79 → 31 on adjacent :19 steps / ports 37282 → 37298 and 45312 → 45314, and five
    /// seconds after d00ef05a1026… dual ports 52154/52194 → 52196 and 57522/57524 → 57526 at
    /// the :15/:20 wall-clock pair) after bare control-NATS RestartAsync,
    /// fingerprint 73ac000434f0… / gru-control-nats CN=gru-controller-1 cid 49 → 82 → 58 →
    /// 33 → 35 → 65 at 18:46:25Z on 127.0.0.1:46536, 18:47:25Z on 127.0.0.1:55148,
    /// 18:48:25Z on 127.0.0.1:44408, 18:49:25Z on 127.0.0.1:38192 / 127.0.0.1:38210 dual
    /// (cid 33+35), and 18:50:25Z on 127.0.0.1:56214 against the same d467c210… leaf —
    /// six-occurrence post-recycle reconnect twin of c2bf6b539a62… / 782d6308… /
    /// 003657d51ecd… / b9dc4dd1a8ef… / 7b6a047263d8… / 87f7f1566c88… / a9bf884a363b… /
    /// 25b92b919c66… / 34c89dedb769… / 024cbd22bdf4… / e7ad7a71e395… / 96fe8dda09bb… /
    /// d2538c612184… / d00ef05a1026… / d56bf3307e7b… / e51d12dd4525… (five seconds after
    /// e51d12dd4525… cid 48 → 55 → 32 → 62 on adjacent :20 steps) after bare control-NATS
    /// RestartAsync,
    /// fingerprint 1455d09f7030… / gru-control-nats CN=gru-controller-1 cid 51 → 83 at
    /// 18:46:26Z on 127.0.0.1:46574 and 18:47:26Z on 127.0.0.1:55160 against the same
    /// d467c210… leaf — two-occurrence post-recycle reconnect twin of c2bf6b539a62… /
    /// 782d6308… / 003657d51ecd… / b9dc4dd1a8ef… / 7b6a047263d8… / 87f7f1566c88… /
    /// a9bf884a363b… / 25b92b919c66… / 34c89dedb769… / 024cbd22bdf4… / e7ad7a71e395… /
    /// 96fe8dda09bb… / d2538c612184… / d00ef05a1026… / d56bf3307e7b… / e51d12dd4525… /
    /// 73ac000434f0… (one second after 73ac000434f0… cid 49 → 82 on adjacent :25 steps /
    /// ports 46536 → 46574 and 55148 → 55160) after bare control-NATS RestartAsync,
    /// fingerprint 91b5b852… / fra-control-nats CN=fra-controller-1 cid 29238 → 62 → 69 → 70
    /// at 18:45:34Z / 18:48:34Z / 18:50:34Z,
    /// fingerprint ffcef075c58c… / fra-control-nats CN=fra-controller-1 cid 29240 → 34 → 66 → 73
    /// at 18:45:40Z / 18:47:40Z / 18:48:40Z / 18:50:40Z against the same 8f6e801c… leaf —
    /// denser four-occurrence twin of 91b5b852…,
    /// fingerprint bca21682b315… / fra-control-nats CN=fra-controller-1 cid 28 → 37 → 69 → 76 at
    /// 18:45:46Z on 127.0.0.1:34624, 18:47:46Z on 127.0.0.1:60304, 18:48:46Z on 127.0.0.1:50796,
    /// and 18:50:46Z on 127.0.0.1:54352 against the same 8f6e801c… leaf — four-occurrence
    /// post-recycle reconnect twin of 91b5b852… / ffcef075c58c… (and gru b9dc4dd1a8ef…) after
    /// bare control-NATS RestartAsync,
    /// fingerprint 23eafce842f6… / fra-control-nats CN=fra-controller-1 cid:29 at 18:45:48Z on
    /// 127.0.0.1:34626 against the same 8f6e801c… leaf — single post-recycle reconnect twin of
    /// 91b5b852… / ffcef075c58c… / bca21682b315… (and gru b9dc4dd1a8ef… leading cid 29) after
    /// bare control-NATS RestartAsync,
    /// fingerprint 4046b92fa615… / fra-control-nats CN=fra-controller-1 cid 31 → 47 at
    /// 18:45:50Z on 127.0.0.1:34668 and 18:49:50Z on 127.0.0.1:33784 against the same
    /// 8f6e801c… leaf — two-occurrence post-recycle reconnect twin of 91b5b852… /
    /// ffcef075c58c… / bca21682b315… / 23eafce842f6… (and sfo 412baaa56842… cid 31/47 steps,
    /// operator-read twins f4f92376efda… / 62860f83eeb6… at the same wall-clock pair) after
    /// bare control-NATS RestartAsync,
    /// fingerprint 87c737a0ed10… / fra-control-nats CN=fra-controller-1 cid 32 → 64 → 41 →
    /// 72 → 73 → 48 → 79 at 18:45:52Z on 127.0.0.1:34674, 18:46:52Z on 127.0.0.1:53654,
    /// 18:47:52Z on 127.0.0.1:60380, 18:48:52Z on 127.0.0.1:50844 / 50858 (dual cid 72+73),
    /// 18:49:52Z on 127.0.0.1:33786, and 18:50:52Z on 127.0.0.1:54412 against the same
    /// 8f6e801c… leaf — seven-occurrence post-recycle reconnect twin of 91b5b852… /
    /// ffcef075c58c… / bca21682b315… / 23eafce842f6… / 4046b92fa615… (and sfo 71cf8514f4d6…
    /// cid 32/41/48 steps, gru-platform b22018f7aa7b… at adjacent wall-clock :52 steps)
    /// after bare control-NATS RestartAsync,
    /// fingerprint 5e5b835252fe… / fra-control-nats CN=fra-controller-1 cid 34 → 50 at
    /// 18:45:56Z on 127.0.0.1:43900 and 18:49:56Z on 127.0.0.1:37150 against the same
    /// 8f6e801c… leaf — two-occurrence post-recycle reconnect twin of 91b5b852… /
    /// ffcef075c58c… / bca21682b315… / 23eafce842f6… / 4046b92fa615… / 87c737a0ed10… (and
    /// gru a9bf884a363b… cid 35/50 steps at the same wall-clock :56 pair) after bare
    /// control-NATS RestartAsync,
    /// fingerprint 6e08a77cd4b6… / fra-control-nats CN=fra-controller-1 cid 35 → 42 → 44 → 51 at
    /// 18:45:57Z on 127.0.0.1:43906, 18:47:57Z on 127.0.0.1:44698 / 127.0.0.1:44730 (dual
    /// cid 42+44), and 18:49:57Z on 127.0.0.1:37152 against the same 8f6e801c… leaf —
    /// four-occurrence post-recycle reconnect twin of 91b5b852… / ffcef075c58c… /
    /// bca21682b315… / 23eafce842f6… / 4046b92fa615… / 87c737a0ed10… / 5e5b835252fe… (and
    /// gru a9bf884a363b… / sfo-platform 9b960cc93f83… at adjacent wall-clock :56/:57 steps)
    /// after bare control-NATS RestartAsync,
    /// fingerprint 876de6711801… / fra-control-nats CN=fra-controller-1 cid 37 → 69 at
    /// 18:46:01Z on 127.0.0.1:43944 and 18:47:01Z on 127.0.0.1:42784 against the same
    /// 8f6e801c… leaf — two-occurrence post-recycle reconnect twin of 91b5b852… /
    /// ffcef075c58c… / bca21682b315… / 23eafce842f6… / 4046b92fa615… / 87c737a0ed10… /
    /// 5e5b835252fe… / 6e08a77cd4b6… (and gru 34c89dedb769… cid 38 → 70 / sfo 3db5efff618c…
    /// cid 36+38 / 69 at the same wall-clock :01 steps) after bare control-NATS RestartAsync,
    /// fingerprint 52a227218acf… / fra-control-nats CN=fra-controller-1 cid 38 → 45 → 52 at
    /// 18:46:02Z on 127.0.0.1:43948, 18:48:02Z on 127.0.0.1:44744, and 18:50:02Z on
    /// 127.0.0.1:37162 against the same 8f6e801c… leaf — three-occurrence post-recycle
    /// reconnect twin of 91b5b852… / ffcef075c58c… / bca21682b315… / 23eafce842f6… /
    /// 4046b92fa615… / 87c737a0ed10… / 5e5b835252fe… / 6e08a77cd4b6… / 876de6711801…
    /// (adjacent :02 second after 876de6711801… cid 37 at 18:46:01Z on nearby 43944, with
    /// ~2 min reconnect gaps matching the denser 91b5b852… / ffcef075c58c… cadence) after
    /// bare control-NATS RestartAsync,
    /// fingerprint 88eec19ebb94… / fra-control-nats CN=fra-controller-1 cid 39 → 41 → 72 →
    /// 48 → 55 at 18:46:07Z on 127.0.0.1:48674 / 127.0.0.1:48694 (dual cid 39+41), 18:47:07Z
    /// on 127.0.0.1:46502, 18:48:07Z on 127.0.0.1:55402, and 18:50:07Z on 127.0.0.1:60620
    /// against the same 8f6e801c… leaf — five-occurrence post-recycle reconnect twin of
    /// 91b5b852… / ffcef075c58c… / bca21682b315… / 23eafce842f6… / 4046b92fa615… /
    /// 87c737a0ed10… / 5e5b835252fe… / 6e08a77cd4b6… / 876de6711801… / 52a227218acf… (fra
    /// peer of gru 024cbd22bdf4… cid 39 → 71 → 80 → 55 at adjacent wall-clock :05 steps)
    /// after bare control-NATS RestartAsync,
    /// fingerprint 49ec50da2e2a… / fra-control-nats CN=fra-controller-1 cid 42 → 51 → 58 at
    /// 18:46:12Z on 127.0.0.1:48696, 18:48:12Z on 127.0.0.1:55440, and 18:50:12Z on
    /// 127.0.0.1:60662 against the same 8f6e801c… leaf — three-occurrence post-recycle
    /// reconnect twin of 91b5b852… / ffcef075c58c… / bca21682b315… / 23eafce842f6… /
    /// 4046b92fa615… / 87c737a0ed10… / 5e5b835252fe… / 6e08a77cd4b6… / 876de6711801… /
    /// 52a227218acf… / 88eec19ebb94… (sparse five-seconds-later twin of 88eec19ebb94… on
    /// adjacent ports 48674/48694 → 48696, 55402 → 55440, 60620 → 60662; fra peer of sfo
    /// 914b99d5fbc6… cid 42 → 83 → 58 at the adjacent :11 steps and gru 96fe8dda09bb… cid
    /// 42 → 74 → 50 → 51 → 81 → 83 → 58 at the adjacent :10/:11 steps) after bare
    /// control-NATS RestartAsync,
    /// fingerprint 7063631384a4… / fra-control-nats CN=fra-controller-1 cid 44 → 74 → 76 →
    /// 83 at 18:46:13Z on 127.0.0.1:48726, 18:47:13Z on 127.0.0.1:46524 / 127.0.0.1:46564
    /// (dual cid 74+76), and 18:49:13Z on 127.0.0.1:52176 against the same 8f6e801c… leaf —
    /// four-occurrence post-recycle reconnect twin of 91b5b852… / ffcef075c58c… /
    /// bca21682b315… / 23eafce842f6… / 4046b92fa615… / 87c737a0ed10… / 5e5b835252fe… /
    /// 6e08a77cd4b6… / 876de6711801… / 52a227218acf… / 88eec19ebb94… / 49ec50da2e2a…
    /// (one-second-later twin of 49ec50da2e2a… on adjacent port 48696 → 48726; denser
    /// mid-window dual reconnect than the sparse :12 triple; product-plane peer of
    /// gru-platform 88ff8c404d3b… cid 51 → 90 at the same wall-clock :13 steps) after bare
    /// control-NATS RestartAsync,
    /// fingerprint d7de94966c92… / fra-control-nats CN=fra-controller-1 cid 45 → 54 → 61 at
    /// 18:46:17Z on 127.0.0.1:45396, 18:48:17Z on 127.0.0.1:33434, and 18:50:17Z on
    /// 127.0.0.1:58410 against the same 8f6e801c… leaf — three-occurrence post-recycle
    /// reconnect twin of 91b5b852… / ffcef075c58c… / bca21682b315… / 23eafce842f6… /
    /// 4046b92fa615… / 87c737a0ed10… / 5e5b835252fe… / 6e08a77cd4b6… / 876de6711801… /
    /// 52a227218acf… / 88eec19ebb94… / 49ec50da2e2a… / 7063631384a4… (four seconds after
    /// 7063631384a4… cid 44 on adjacent :13 steps; fra peer of sfo bbdb6e0d6006… cid 45 →
    /// 29 → 61 at the adjacent wall-clock :16 steps and gru d00ef05a1026… cid 45 → 77 → 52 →
    /// 54 → 29 → 60 → 61 at the adjacent wall-clock :15 steps; product-plane peer of
    /// fra-platform ec156a1db321… cid 52 → 91 at the same wall-clock :17 steps) after bare
    /// control-NATS RestartAsync,
    /// fingerprint 4cab25065be5… / fra-control-nats CN=fra-controller-1 cid 47 → 79 → 30 at
    /// 18:46:19Z on 127.0.0.1:45434, 18:47:19Z on 127.0.0.1:34540, and 18:49:19Z on
    /// 127.0.0.1:44862 against the same 8f6e801c… leaf — three-occurrence post-recycle
    /// reconnect twin of 91b5b852… / ffcef075c58c… / bca21682b315… / 23eafce842f6… /
    /// 4046b92fa615… / 87c737a0ed10… / 5e5b835252fe… / 6e08a77cd4b6… / 876de6711801… /
    /// 52a227218acf… / 88eec19ebb94… / 49ec50da2e2a… / 7063631384a4… / d7de94966c92…
    /// (two seconds after d7de94966c92… cid 45 on adjacent :17 steps / ports 45396 → 45434;
    /// fra peer of sfo 1cdbb448aebb… cid 47 → 79 → 31 at the same wall-clock :19 steps,
    /// concurrent with gru-platform 1f9106a25f41… / sfo-platform 1668f8c0e10f… /
    /// fra-platform 59a0656971a4… / gru operator-read 5807fcff9600… at the same wall-clock
    /// :19 steps) after bare control-NATS RestartAsync,
    /// fingerprint 4aa0ebad5b5b… / fra-control-nats CN=fra-controller-1 cid 48 → 57 at
    /// 18:46:22Z on 127.0.0.1:45440 and 18:48:22Z on 127.0.0.1:33458 against the same
    /// 8f6e801c… leaf — two-occurrence post-recycle reconnect twin of 91b5b852… /
    /// ffcef075c58c… / bca21682b315… / 23eafce842f6… / 4046b92fa615… / 87c737a0ed10… /
    /// 5e5b835252fe… / 6e08a77cd4b6… / 876de6711801… / 52a227218acf… / 88eec19ebb94… /
    /// 49ec50da2e2a… / 7063631384a4… / d7de94966c92… / 4cab25065be5… (three seconds after
    /// 4cab25065be5… cid 47 on adjacent :19 steps / ports 45434 → 45440; fra peer of sfo
    /// 2e80728c5df4… cid 48 → 57 → 63 → 64 at the adjacent wall-clock :21 steps and gru
    /// e51d12dd4525… cid 48 → 55 → 32 → 62 at the adjacent wall-clock :20 steps) after bare
    /// control-NATS RestartAsync,
    /// fingerprint c6627a56bf45… / gru-control-nats CN=operator-read cid 29237 → 62 → 69,
    /// fingerprint c48cbf142a9a… / gru-control-nats CN=operator-read cid 29239 → 34 → 66 → 72
    /// at 18:45:40Z / 18:47:40Z / 18:48:40Z / 18:50:40Z against the same 4e40db2b… leaf,
    /// fingerprint f4f92376efda… / gru-control-nats CN=operator-read cid 31 → 46 at
    /// 18:45:50Z on 127.0.0.1:56170 and 18:49:50Z on 127.0.0.1:45996 against the same
    /// 4e40db2b… leaf — two-occurrence post-recycle reconnect twin of c6627a56bf45… /
    /// c48cbf142a9a… after bare control-NATS RestartAsync,
    /// fingerprint b252d8996050… / gru-control-nats CN=operator-read cid 34 → 51 at
    /// 18:45:56Z on 127.0.0.1:54410 and 18:49:56Z on 127.0.0.1:35762 against the same
    /// 4e40db2b… leaf — second two-occurrence post-recycle reconnect twin of
    /// c6627a56bf45… / c48cbf142a9a… / f4f92376efda… after bare control-NATS RestartAsync,
    /// fingerprint 6a650c470be6… / gru-control-nats CN=operator-read cid 37 → 69 at
    /// 18:46:01Z on 127.0.0.1:54470 and 18:47:01Z on 127.0.0.1:57302 against the same
    /// 4e40db2b… leaf — third two-occurrence post-recycle reconnect twin of
    /// c6627a56bf45… / c48cbf142a9a… / f4f92376efda… / b252d8996050… (and sfo d80a6067f126…
    /// cid 37 → 68 at the same wall-clock :01 steps) after bare control-NATS RestartAsync,
    /// fingerprint 5c56829c01e4… / gru-control-nats CN=operator-read cid 40 → 72 at
    /// 18:46:07Z on 127.0.0.1:48998 and 18:47:07Z on 127.0.0.1:42902 against the same
    /// 4e40db2b… leaf — fourth two-occurrence post-recycle reconnect twin of
    /// c6627a56bf45… / c48cbf142a9a… / f4f92376efda… / b252d8996050… / 6a650c470be6… (gru
    /// peer of sfo 58dda0785551… cid 40 → 72 / fra-controller 88eec19ebb94… /
    /// sfo-platform ef71b6e32493… at the same wall-clock :07 steps) after bare
    /// control-NATS RestartAsync,
    /// fingerprint 9dd8feb97fa2… / gru-control-nats CN=operator-read cid 43 → 75 at
    /// 18:46:13Z on 127.0.0.1:49032 and 18:47:13Z on 127.0.0.1:42960 against the same
    /// 4e40db2b… leaf — fifth two-occurrence post-recycle reconnect twin of
    /// c6627a56bf45… / c48cbf142a9a… / f4f92376efda… / b252d8996050… / 6a650c470be6… /
    /// 5c56829c01e4… (gru peer of sfo-platform e583d837318a… / fra-platform d86f81358e32…
    /// at the same wall-clock :13 steps) after bare control-NATS RestartAsync,
    /// fingerprint 5807fcff9600… / gru-control-nats CN=operator-read cid 46 → 78 → 30 at
    /// 18:46:19Z on 127.0.0.1:37264, 18:47:19Z on 127.0.0.1:34126, and 18:49:19Z on
    /// 127.0.0.1:45286 against the same 4e40db2b… leaf — three-occurrence post-recycle
    /// reconnect twin of c6627a56bf45… / c48cbf142a9a… / f4f92376efda… / b252d8996050… /
    /// 6a650c470be6… / 5c56829c01e4… / 9dd8feb97fa2… (gru control-plane peer of
    /// gru-platform 1f9106a25f41… / sfo-platform 1668f8c0e10f… / fra-platform
    /// 59a0656971a4… at the same wall-clock :19 steps) after bare control-NATS
    /// RestartAsync,
    /// fingerprint e517701a… / sfo-control-nats CN=operator-read cid 29237 → 62 → 69,
    /// fingerprint f08d1c577176… / sfo-control-nats CN=operator-read cid 29239 → 33 → 65 → 72
    /// at 18:45:40Z / 18:47:40Z / 18:48:40Z / 18:50:40Z against the same aa00c1c3… leaf,
    /// fingerprint 62860f83eeb6… / sfo-control-nats CN=operator-read cid 30 → 46 at
    /// 18:45:50Z on 127.0.0.1:50596 and 18:49:50Z on 127.0.0.1:34070 against the same
    /// aa00c1c3… leaf — two-occurrence post-recycle reconnect twin of e517701a… /
    /// f08d1c577176… after bare control-NATS RestartAsync,
    /// fingerprint 97d33257778a… / sfo-control-nats CN=operator-read cid 33 → 50 at
    /// 18:45:56Z on 127.0.0.1:52196 and 18:49:56Z on 127.0.0.1:36654 against the same
    /// aa00c1c3… leaf — second two-occurrence post-recycle reconnect twin of e517701a… /
    /// f08d1c577176… / 62860f83eeb6… after bare control-NATS RestartAsync,
    /// fingerprint d80a6067f126… / sfo-control-nats CN=operator-read cid 37 → 68 at
    /// 18:46:01Z on 127.0.0.1:52246 and 18:47:01Z on 127.0.0.1:34762 against the same
    /// aa00c1c3… leaf — third two-occurrence post-recycle reconnect twin of e517701a… /
    /// f08d1c577176… / 62860f83eeb6… / 97d33257778a… after bare control-NATS RestartAsync,
    /// fingerprint 58dda0785551… / sfo-control-nats CN=operator-read cid 40 → 72 at
    /// 18:46:07Z on 127.0.0.1:49186 and 18:47:07Z on 127.0.0.1:53880 against the same
    /// aa00c1c3… leaf — fourth two-occurrence post-recycle reconnect twin of e517701a… /
    /// f08d1c577176… / 62860f83eeb6… / 97d33257778a… / d80a6067f126… (sfo peer of
    /// fra-controller 88eec19ebb94… / sfo-platform ef71b6e32493… at the same wall-clock
    /// :07 steps) after bare control-NATS RestartAsync,
    /// fingerprint 69541ea34d1d… / sfo-control-nats CN=operator-read cid 43 → 75 at
    /// 18:46:13Z on 127.0.0.1:49240 and 18:47:13Z on 127.0.0.1:53920 against the same
    /// aa00c1c3… leaf — fifth two-occurrence post-recycle reconnect twin of e517701a… /
    /// f08d1c577176… / 62860f83eeb6… / 97d33257778a… / d80a6067f126… / 58dda0785551… (sfo
    /// peer of gru 9dd8feb97fa2… cid 43 → 75 / fra 424b0b6af457… cid 43 → 75 /
    /// sfo-platform e583d837318a… / fra-platform d86f81358e32… at the same wall-clock
    /// :13 steps) after bare control-NATS RestartAsync,
    /// fingerprint 0c8da303bb67… / sfo-control-nats CN=operator-read cid 46 → 78 → 30 at
    /// 18:46:19Z on 127.0.0.1:40988, 18:47:19Z on 127.0.0.1:59820, and 18:49:19Z on
    /// 127.0.0.1:35640 against the same aa00c1c3… leaf — three-occurrence post-recycle
    /// reconnect twin of e517701a… / f08d1c577176… / 62860f83eeb6… / 97d33257778a… /
    /// d80a6067f126… / 58dda0785551… / 69541ea34d1d… (sfo control-plane peer of gru
    /// 5807fcff9600… cid 46 → 78 → 30 / fra 461d52d6f097… cid 46 → 78 → 29 /
    /// gru-platform 1f9106a25f41… / sfo-platform 1668f8c0e10f… / fra-platform
    /// 59a0656971a4… at the same wall-clock :19 steps) after bare control-NATS
    /// RestartAsync,
    /// fingerprint 9a811bb8… / fra-control-nats CN=operator-read cid 29237 → 63 → 68,
    /// fingerprint f95adc65… / fra-control-nats CN=operator-read cid 29239 → 33 → 65 → 72
    /// at 18:45:40Z / 18:47:40Z / 18:48:40Z / 18:50:40Z against the same 6477b788… leaf,
    /// fingerprint 7421834a4183… / fra-control-nats CN=operator-read cid 30 → 46 at
    /// 18:45:50Z on 127.0.0.1:34654 and 18:49:50Z on 127.0.0.1:33762 against the same
    /// 6477b788… leaf — two-occurrence post-recycle reconnect twin of 9a811bb8… /
    /// f95adc65… after bare control-NATS RestartAsync,
    /// fingerprint c74671d2c0e4… / fra-control-nats CN=operator-read cid 33 → 49 at
    /// 18:45:56Z on 127.0.0.1:43890 and 18:49:56Z on 127.0.0.1:37146 against the same
    /// 6477b788… leaf — second two-occurrence post-recycle reconnect twin of 9a811bb8… /
    /// f95adc65… / 7421834a4183… after bare control-NATS RestartAsync,
    /// fingerprint b2dec42a6166… / fra-control-nats CN=operator-read cid 36 → 68 at
    /// 18:46:01Z on 127.0.0.1:43922 and 18:47:01Z on 127.0.0.1:42774 against the same
    /// 6477b788… leaf — third two-occurrence post-recycle reconnect twin of 9a811bb8… /
    /// f95adc65… / 7421834a4183… / c74671d2c0e4… (and gru 6a650c470be6… cid 37 → 69 / sfo
    /// d80a6067f126… cid 37 → 68 at the same wall-clock :01 steps) after bare control-NATS
    /// RestartAsync,
    /// fingerprint d26af782af24… / fra-control-nats CN=operator-read cid 40 → 71 at
    /// 18:46:07Z on 127.0.0.1:48686 and 18:47:07Z on 127.0.0.1:46486 against the same
    /// 6477b788… leaf — fourth two-occurrence post-recycle reconnect twin of 9a811bb8… /
    /// f95adc65… / 7421834a4183… / c74671d2c0e4… / b2dec42a6166… (fra peer of gru
    /// 5c56829c01e4… cid 40 → 72 / sfo 58dda0785551… cid 40 → 72 / fra-controller
    /// 88eec19ebb94… / sfo-platform ef71b6e32493… / gru-platform 0401b56675fd… at the same
    /// wall-clock :07 steps) after bare control-NATS RestartAsync,
    /// fingerprint 424b0b6af457… / fra-control-nats CN=operator-read cid 43 → 75 at
    /// 18:46:13Z on 127.0.0.1:48710 and 18:47:13Z on 127.0.0.1:46544 against the same
    /// 6477b788… leaf — fifth two-occurrence post-recycle reconnect twin of 9a811bb8… /
    /// f95adc65… / 7421834a4183… / c74671d2c0e4… / b2dec42a6166… / d26af782af24… (fra peer
    /// of gru 9dd8feb97fa2… cid 43 → 75 / sfo-platform e583d837318a… / fra-platform
    /// d86f81358e32… at the same wall-clock :13 steps) after bare control-NATS
    /// RestartAsync,
    /// fingerprint 461d52d6f097… / fra-control-nats CN=operator-read cid 46 → 78 → 29 at
    /// 18:46:19Z on 127.0.0.1:45414, 18:47:19Z on 127.0.0.1:34512, and 18:49:19Z on
    /// 127.0.0.1:44846 against the same 6477b788… leaf — three-occurrence post-recycle
    /// reconnect twin of 9a811bb8… / f95adc65… / 7421834a4183… / c74671d2c0e4… /
    /// b2dec42a6166… / d26af782af24… / 424b0b6af457… (fra peer of gru 5807fcff9600…
    /// cid 46 → 78 → 30 / gru-platform 1f9106a25f41… / sfo-platform 1668f8c0e10f… /
    /// fra-platform 59a0656971a4… at the same wall-clock :19 steps) after bare
    /// control-NATS RestartAsync,
    /// fingerprint e9d264fcee49… / fra-control-nats CN=operator-read cid:49 at
    /// 18:46:26Z on 127.0.0.1:38796 against the same 6477b788… leaf — single-occurrence
    /// post-recycle reconnect twin of 9a811bb8… / f95adc65… / 7421834a4183… /
    /// c74671d2c0e4… / b2dec42a6166… / d26af782af24… / 424b0b6af457… / 461d52d6f097…
    /// (seven seconds after 461d52d6f097… cid 46 on 127.0.0.1:45414 at :19; concurrent
    /// with fra-platform 86b0b173f024… cid 57 → 96 → 97 → 32 / gru-platform
    /// d26427e1c533… cid 58 → 97 → 98 → 32 at the adjacent wall-clock :25/:26 steps)
    /// after bare control-NATS RestartAsync).
    /// Product NATS is analogous for platform leaves
    /// (fingerprint 25ef0004168c… / fra-product-nats CN=fra-platform cid 14634 → 63 → 50 → 43
    /// at 18:45:34Z / 18:46:34Z / 18:48:34Z / 18:50:34Z; gru twin 57ae70882ed5…;
    /// fingerprint dacc95d0e7ba… / fra-product-nats CN=fra-platform cid 14635 → 67 → 38 → 51 → 44
    /// at 18:45:40Z / 18:46:40Z / 18:47:40Z / 18:48:40Z / 18:50:40Z against the same
    /// 7ef9d0a4… leaf — denser five-occurrence twin of 25ef0004168c…;
    /// fingerprint 1e8b88f75d43… / fra-product-nats CN=fra-platform cid:31 at 18:45:45Z on
    /// 127.0.0.1:34466 against the same 7ef9d0a4… leaf — single post-recycle reconnect twin
    /// of 25ef0004168c… / dacc95d0e7ba… (and gru 0b23b4fb5a75… / sfo d739f8d83bed…) after bare
    /// product-NATS RestartAsync;
    /// fingerprint 30e9c320e15b… / fra-product-nats CN=fra-platform cid 32 → 71 → 41 → 42 → 52 → 45 at
    /// 18:45:46Z on 127.0.0.1:34468, 18:46:46Z on 127.0.0.1:45732, 18:47:46Z on 127.0.0.1:49922 /
    /// 49934 (dual cid 41+42), 18:48:46Z on 127.0.0.1:44248, and 18:50:46Z on 127.0.0.1:58440
    /// against the same 7ef9d0a4… leaf — six-occurrence post-recycle reconnect twin of
    /// 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… (and gru 0cbc78bc3a3a…) after bare
    /// product-NATS RestartAsync;
    /// fingerprint fc4e0317d2a1… / fra-product-nats CN=fra-platform cid 33 → 72 at
    /// 18:45:48Z on 127.0.0.1:34476 and 18:46:48Z on 127.0.0.1:45738 against the same
    /// 7ef9d0a4… leaf — two-occurrence post-recycle reconnect twin of 30e9c320e15b… /
    /// 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… (and gru 6a1c43a93378…) after bare
    /// product-NATS RestartAsync;
    /// fingerprint 92ed0baffd5b… / fra-product-nats CN=fra-platform cid 34 → 35 → 74 → 36 at
    /// 18:45:50Z on 127.0.0.1:34504 / 34506 (dual cid 34+35), 18:46:50Z on 127.0.0.1:45768,
    /// and 18:49:50Z on 127.0.0.1:59726 against the same 7ef9d0a4… leaf — four-occurrence
    /// post-recycle reconnect twin of fc4e0317d2a1… / 30e9c320e15b… / 25ef0004168c… /
    /// dacc95d0e7ba… / 1e8b88f75d43… (and gru ed3f4504d5e1… / sfo 146c64f3fc52… /
    /// operator-read twins f4f92376efda… / 62860f83eeb6… / 7421834a4183… at the same
    /// wall-clock pair) after bare product-NATS RestartAsync;
    /// fingerprint 7904dd055f87… / fra-product-nats CN=fra-platform cid 36 → 75 → 53 → 46 at
    /// 18:45:52Z on 127.0.0.1:34510, 18:46:52Z on 127.0.0.1:45778, 18:48:52Z on
    /// 127.0.0.1:44268, and 18:50:52Z on 127.0.0.1:58444 against the same 7ef9d0a4… leaf —
    /// four-occurrence post-recycle reconnect twin of 92ed0baffd5b… / fc4e0317d2a1… /
    /// 30e9c320e15b… / 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… (and gru b22018f7aa7b…
    /// at the same wall-clock :52 steps) after bare product-NATS RestartAsync;
    /// fingerprint 5804cb3aaf61… / fra-product-nats CN=fra-platform cid 37 → 76 at
    /// 18:45:54Z on 127.0.0.1:50978 and 18:46:54Z on 127.0.0.1:38754 against the same
    /// 7ef9d0a4… leaf — two-occurrence post-recycle reconnect twin of 7904dd055f87… /
    /// 92ed0baffd5b… / fc4e0317d2a1… / 30e9c320e15b… / 25ef0004168c… / dacc95d0e7ba… /
    /// 1e8b88f75d43… (and gru 9371738eec92… / b22018f7aa7b… / sfo e33d87402e17… /
    /// operator-read twins at adjacent wall-clock :52/:53/:54 steps) after bare
    /// product-NATS RestartAsync;
    /// fingerprint 5d30a28d7f44… / fra-product-nats CN=fra-platform cid 38 → 39 → 78 → 37 at
    /// 18:45:56Z on 127.0.0.1:51008 / 127.0.0.1:51016 (dual cid 38+39), 18:46:56Z on
    /// 127.0.0.1:38782, and 18:49:56Z on 127.0.0.1:52794 against the same 7ef9d0a4… leaf —
    /// four-occurrence post-recycle reconnect twin of 5804cb3aaf61… / 7904dd055f87… /
    /// 92ed0baffd5b… / fc4e0317d2a1… / 30e9c320e15b… / 25ef0004168c… / dacc95d0e7ba… /
    /// 1e8b88f75d43… (and gru be7bee33b946… / sfo 26b95f54769c… / gru operator-read
    /// b252d8996050… / gru-controller a9bf884a363b… / sfo operator-read 97d33257778a… /
    /// fra operator-read c74671d2c0e4… / fra-controller 5e5b835252fe… at the same wall-clock
    /// :56 steps) after bare product-NATS RestartAsync;
    /// fingerprint 639501fa4228… / fra-product-nats CN=fra-platform cid 40 → 79 → 54 at
    /// 18:45:58Z on 127.0.0.1:51030, 18:46:58Z on 127.0.0.1:38798, and 18:48:58Z on
    /// 127.0.0.1:38302 against the same 7ef9d0a4… leaf — three-occurrence post-recycle
    /// reconnect twin of 5d30a28d7f44… / 5804cb3aaf61… / 7904dd055f87… / 92ed0baffd5b… /
    /// fc4e0317d2a1… / 30e9c320e15b… / 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… (and
    /// gru a2e01c16a27c… / sfo 9b960cc93f83… / gru operator-read b252d8996050… /
    /// gru-controller a9bf884a363b… / sfo operator-read 97d33257778a… / fra operator-read
    /// c74671d2c0e4… at adjacent wall-clock :56/:57/:58 steps) after bare product-NATS
    /// RestartAsync;
    /// fingerprint eebfa17cec6b… / fra-product-nats CN=fra-platform cid 41 → 80 at
    /// 18:46:00Z on 127.0.0.1:51046 and 18:47:00Z on 127.0.0.1:38810 against the same
    /// 7ef9d0a4… leaf — two-occurrence post-recycle reconnect twin of 639501fa4228… /
    /// 5d30a28d7f44… / 5804cb3aaf61… / 7904dd055f87… / 92ed0baffd5b… / fc4e0317d2a1… /
    /// 30e9c320e15b… / 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… (and gru
    /// 764b28c3439a… / gru a2e01c16a27c… / sfo 9b960cc93f83… / gru operator-read
    /// b252d8996050… / gru-controller a9bf884a363b… / 25b92b919c66… / sfo operator-read
    /// 97d33257778a… / fra operator-read c74671d2c0e4… at the same wall-clock 18:46:00Z /
    /// 18:47:00Z steps) after bare product-NATS RestartAsync;
    /// fingerprint 669e26dad203… / fra-product-nats CN=fra-platform cid 42 → 81 at
    /// 18:46:01Z on 127.0.0.1:51068 and 18:47:01Z on 127.0.0.1:38828 against the same
    /// 7ef9d0a4… leaf — two-occurrence post-recycle reconnect twin of eebfa17cec6b… /
    /// 639501fa4228… / 5d30a28d7f44… / 5804cb3aaf61… / 7904dd055f87… / 92ed0baffd5b… /
    /// fc4e0317d2a1… / 30e9c320e15b… / 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… (and
    /// gru 6d84bda1e560… cid 43 → 82 / gru 764b28c3439a… cid 42 → 81 / sfo eacb3282ca0c…
    /// dual cid 41+42 → 80+81 at the same wall-clock 18:46:01Z / 18:47:01Z steps) after
    /// bare product-NATS RestartAsync;
    /// fingerprint 67d134aeab25… / fra-product-nats CN=fra-platform cid 43 → 38 at
    /// 18:46:03Z on 127.0.0.1:51072 and 18:50:03Z on 127.0.0.1:52810 against the same
    /// 7ef9d0a4… leaf — two-occurrence sparse post-recycle reconnect twin of 669e26dad203… /
    /// eebfa17cec6b… / 639501fa4228… / 5d30a28d7f44… / 5804cb3aaf61… / 7904dd055f87… /
    /// 92ed0baffd5b… / fc4e0317d2a1… / 30e9c320e15b… / 25ef0004168c… / dacc95d0e7ba… /
    /// 1e8b88f75d43… (and gru 6d84bda1e560… cid 43 → 82 / gru 764b28c3439a… cid 42 → 81 /
    /// sfo eacb3282ca0c… dual cid 41+42 → 80+81 at the adjacent wall-clock 18:46:01Z /
    /// 18:47:01Z steps) after bare product-NATS RestartAsync;
    /// fingerprint b8e719ba13ca… / fra-product-nats CN=fra-platform cid:44 at
    /// 18:46:05Z on 127.0.0.1:38810 against the same 7ef9d0a4… leaf — single-occurrence
    /// post-recycle reconnect twin of 67d134aeab25… / 669e26dad203… / eebfa17cec6b… /
    /// 639501fa4228… / 5d30a28d7f44… / 5804cb3aaf61… / 7904dd055f87… / 92ed0baffd5b… /
    /// fc4e0317d2a1… / 30e9c320e15b… / 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… (and
    /// gru 3f4dc73e62f2… cid 45 → 84 → 44 → 54 / gru 5990e53d2fde… cid 44 → 83 / sfo
    /// c907c56a7c0c… cid 43 → 82 → 38 at the adjacent wall-clock 18:46:02Z / 18:46:03Z /
    /// 18:46:04Z / 18:46:05Z steps) after bare product-NATS RestartAsync;
    /// fingerprint aae9c8a6b484… / fra-product-nats CN=fra-platform cid 45 → 46 → 84 → 85 at
    /// 18:46:07Z on 127.0.0.1:38812 / 127.0.0.1:38824 (dual cid 45+46) and 18:47:07Z on
    /// 127.0.0.1:40184 / 127.0.0.1:40196 (dual cid 84+85) against the same 7ef9d0a4… leaf —
    /// four-occurrence dual-cid post-recycle reconnect twin of b8e719ba13ca… /
    /// 67d134aeab25… / 669e26dad203… / eebfa17cec6b… / 639501fa4228… / 5d30a28d7f44… /
    /// 5804cb3aaf61… / 7904dd055f87… / 92ed0baffd5b… / fc4e0317d2a1… / 30e9c320e15b… /
    /// 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… (and gru e962f4a49508… cid 46 → 85 /
    /// gru 3f4dc73e62f2… cid 45 → 84 → 44 → 54 / gru 5990e53d2fde… cid 44 → 83 / sfo
    /// b439248687d8… cid 44 → 83 / sfo c907c56a7c0c… cid 43 → 82 → 38 at the adjacent
    /// wall-clock 18:46:02Z / 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z /
    /// 18:47:02Z / 18:47:05Z / 18:47:06Z / 18:47:07Z steps) after bare product-NATS
    /// RestartAsync;
    /// fingerprint a66e03d58e6a… / fra-product-nats CN=fra-platform cid 47 → 86 → 39 at
    /// 18:46:09Z on 127.0.0.1:38828, 18:47:09Z on 127.0.0.1:40210, and 18:50:09Z on
    /// 127.0.0.1:48084 against the same 7ef9d0a4… leaf — three-occurrence sparse
    /// post-recycle reconnect twin of aae9c8a6b484… / b8e719ba13ca… / 67d134aeab25… /
    /// 669e26dad203… / eebfa17cec6b… / 639501fa4228… / 5d30a28d7f44… / 5804cb3aaf61… /
    /// 7904dd055f87… / 92ed0baffd5b… / fc4e0317d2a1… / 30e9c320e15b… / 25ef0004168c… /
    /// dacc95d0e7ba… / 1e8b88f75d43… (and gru 6be7ec00050d… cid 48 → 87 / gru
    /// 0401b56675fd… cid 47 → 86 / gru e962f4a49508… cid 46 → 85 / gru 3f4dc73e62f2…
    /// cid 45 → 84 → 44 → 54 / gru 5990e53d2fde… cid 44 → 83 / sfo ef71b6e32493… dual
    /// cid 45+46 → 84+85 / sfo b439248687d8… cid 44 → 83 / sfo c907c56a7c0c… cid 43 →
    /// 82 → 38 at the adjacent wall-clock 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z /
    /// 18:46:07Z / 18:46:08Z / 18:46:09Z / 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z /
    /// 18:47:07Z / 18:47:08Z / 18:47:09Z / 18:50:09Z steps) after bare product-NATS
    /// RestartAsync;
    /// fingerprint a87539b37de1… / fra-product-nats CN=fra-platform cid 48 → 87 at
    /// 18:46:11Z on 127.0.0.1:38842 and 18:47:11Z on 127.0.0.1:40216 against the same
    /// 7ef9d0a4… leaf — two-occurrence post-recycle reconnect twin of a66e03d58e6a… /
    /// aae9c8a6b484… / b8e719ba13ca… / 67d134aeab25… / 669e26dad203… / eebfa17cec6b… /
    /// 639501fa4228… / 5d30a28d7f44… / 5804cb3aaf61… / 7904dd055f87… / 92ed0baffd5b… /
    /// fc4e0317d2a1… / 30e9c320e15b… / 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… (and
    /// gru 8a0aaf8cb1da… cid 49 → 88 → 45 → 55 / gru 6be7ec00050d… cid 48 → 87 / gru
    /// 0401b56675fd… cid 47 → 86 / gru e962f4a49508… cid 46 → 85 / gru 3f4dc73e62f2…
    /// cid 45 → 84 → 44 → 54 / gru 5990e53d2fde… cid 44 → 83 / sfo 02525de8dfa3… cid
    /// 47 → 86 → 39 / sfo ef71b6e32493… dual cid 45+46 → 84+85 / sfo b439248687d8…
    /// cid 44 → 83 / sfo c907c56a7c0c… cid 43 → 82 → 38 at the adjacent wall-clock
    /// 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z /
    /// 18:46:09Z / 18:46:10Z / 18:46:11Z / 18:47:03Z / 18:47:04Z / 18:47:05Z /
    /// 18:47:06Z / 18:47:07Z / 18:47:08Z / 18:47:09Z / 18:47:10Z / 18:47:11Z /
    /// 18:50:09Z steps) after bare product-NATS RestartAsync;
    /// fingerprint d86f81358e32… / fra-product-nats CN=fra-platform cid 49 → 50 → 88 → 89 at
    /// 18:46:13Z on 127.0.0.1:38852 / 127.0.0.1:38860 (dual cid 49+50) and 18:47:13Z on
    /// 127.0.0.1:40222 / 127.0.0.1:40240 (dual cid 88+89) against the same 7ef9d0a4… leaf —
    /// four-occurrence dual-cid post-recycle reconnect twin of a87539b37de1… /
    /// a66e03d58e6a… / aae9c8a6b484… / b8e719ba13ca… / 67d134aeab25… / 669e26dad203… /
    /// eebfa17cec6b… / 639501fa4228… / 5d30a28d7f44… / 5804cb3aaf61… / 7904dd055f87… /
    /// 92ed0baffd5b… / fc4e0317d2a1… / 30e9c320e15b… / 25ef0004168c… / dacc95d0e7ba… /
    /// 1e8b88f75d43… (and gru 897b9ff7b37e… cid 50 → 89 / gru 8a0aaf8cb1da… cid 49 → 88 →
    /// 45 → 55 / gru 6be7ec00050d… cid 48 → 87 / gru 0401b56675fd… cid 47 → 86 / gru
    /// e962f4a49508… cid 46 → 85 / gru 3f4dc73e62f2… cid 45 → 84 → 44 → 54 / gru
    /// 5990e53d2fde… cid 44 → 83 / sfo 02525de8dfa3… cid 47 → 86 → 39 / sfo
    /// ef71b6e32493… dual cid 45+46 → 84+85 / sfo b439248687d8… cid 44 → 83 / sfo
    /// c907c56a7c0c… cid 43 → 82 → 38 at the adjacent wall-clock 18:46:03Z / 18:46:04Z /
    /// 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z / 18:46:09Z / 18:46:10Z /
    /// 18:46:11Z / 18:46:12Z / 18:46:13Z / 18:47:03Z / 18:47:04Z / 18:47:05Z /
    /// 18:47:06Z / 18:47:07Z / 18:47:08Z / 18:47:09Z / 18:47:10Z / 18:47:11Z /
    /// 18:47:12Z / 18:47:13Z / 18:48:10Z / 18:49:10Z / 18:50:09Z steps) after bare
    /// product-NATS RestartAsync;
    /// fingerprint bf210e609e7f… / fra-product-nats CN=fra-platform cid 51 → 90 → 47 → 40 at
    /// 18:46:15Z on 127.0.0.1:47532, 18:47:15Z on 127.0.0.1:48208, 18:48:15Z on
    /// 127.0.0.1:42916, and 18:50:15Z on 127.0.0.1:56668 against the same 7ef9d0a4… leaf —
    /// four-occurrence sparse post-recycle reconnect twin of d86f81358e32… /
    /// a87539b37de1… / a66e03d58e6a… / aae9c8a6b484… / b8e719ba13ca… / 67d134aeab25… /
    /// 669e26dad203… / eebfa17cec6b… / 639501fa4228… / 5d30a28d7f44… / 5804cb3aaf61… /
    /// 7904dd055f87… / 92ed0baffd5b… / fc4e0317d2a1… / 30e9c320e15b… / 25ef0004168c… /
    /// dacc95d0e7ba… / 1e8b88f75d43… (and gru f106e39e815f… cid 52 → 91 / gru
    /// 88ff8c404d3b… cid 51 → 90 / gru 897b9ff7b37e… cid 50 → 89 / gru 8a0aaf8cb1da…
    /// cid 49 → 88 → 45 → 55 / gru 6be7ec00050d… cid 48 → 87 / gru 0401b56675fd… cid 47 →
    /// 86 / gru e962f4a49508… cid 46 → 85 / gru 3f4dc73e62f2… cid 45 → 84 → 44 → 54 / gru
    /// 5990e53d2fde… cid 44 → 83 / sfo e583d837318a… dual cid 49+50 → 88+89 / sfo
    /// 02525de8dfa3… cid 47 → 86 → 39 / sfo ef71b6e32493… dual cid 45+46 → 84+85 / sfo
    /// b439248687d8… cid 44 → 83 / sfo c907c56a7c0c… cid 43 → 82 → 38 at the adjacent
    /// wall-clock 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z /
    /// 18:46:09Z / 18:46:10Z / 18:46:11Z / 18:46:12Z / 18:46:13Z / 18:46:14Z /
    /// 18:46:15Z / 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z /
    /// 18:47:08Z / 18:47:09Z / 18:47:10Z / 18:47:11Z / 18:47:12Z / 18:47:13Z /
    /// 18:47:14Z / 18:47:15Z / 18:48:10Z / 18:48:15Z / 18:49:10Z / 18:50:09Z /
    /// 18:50:15Z steps) after bare product-NATS RestartAsync;
    /// fingerprint ec156a1db321… / fra-product-nats CN=fra-platform cid 52 → 91 at
    /// 18:46:17Z on 127.0.0.1:47542 and 18:47:17Z on 127.0.0.1:48210 against the same
    /// 7ef9d0a4… leaf — two-occurrence post-recycle reconnect twin of bf210e609e7f… /
    /// d86f81358e32… / a87539b37de1… / a66e03d58e6a… / aae9c8a6b484… / b8e719ba13ca… /
    /// 67d134aeab25… / 669e26dad203… / eebfa17cec6b… / 639501fa4228… / 5d30a28d7f44… /
    /// 5804cb3aaf61… / 7904dd055f87… / 92ed0baffd5b… / fc4e0317d2a1… / 30e9c320e15b… /
    /// 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… (and gru f106e39e815f… cid 52 → 91 /
    /// gru d0feba5039c6… cid:53 / gru 88ff8c404d3b… cid 51 → 90 / gru 897b9ff7b37e… cid
    /// 50 → 89 / gru 8a0aaf8cb1da… cid 49 → 88 → 45 → 55 / gru 6be7ec00050d… cid 48 → 87 /
    /// gru 0401b56675fd… cid 47 → 86 / gru e962f4a49508… cid 46 → 85 / gru 3f4dc73e62f2…
    /// cid 45 → 84 → 44 → 54 / gru 5990e53d2fde… cid 44 → 83 / sfo e583d837318a… dual cid
    /// 49+50 → 88+89 / sfo 02525de8dfa3… cid 47 → 86 → 39 / sfo ef71b6e32493… dual cid
    /// 45+46 → 84+85 / sfo b439248687d8… cid 44 → 83 / sfo c907c56a7c0c… cid 43 → 82 → 38
    /// at the adjacent wall-clock 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z /
    /// 18:46:07Z / 18:46:08Z / 18:46:09Z / 18:46:10Z / 18:46:11Z / 18:46:12Z /
    /// 18:46:13Z / 18:46:14Z / 18:46:15Z / 18:46:17Z / 18:47:03Z / 18:47:04Z /
    /// 18:47:05Z / 18:47:06Z / 18:47:07Z / 18:47:08Z / 18:47:09Z / 18:47:10Z /
    /// 18:47:11Z / 18:47:12Z / 18:47:13Z / 18:47:14Z / 18:47:15Z / 18:47:17Z /
    /// 18:48:10Z / 18:48:15Z / 18:49:10Z / 18:50:09Z / 18:50:15Z steps) after bare
    /// product-NATS RestartAsync;
    /// fingerprint 59a0656971a4… / fra-product-nats CN=fra-platform cid 53 → 54 → 92 → 93 → 31
    /// at 18:46:19Z on 127.0.0.1:47548 and 127.0.0.1:47562, 18:47:19Z on 127.0.0.1:48216
    /// and 127.0.0.1:48240, and 18:49:19Z on 127.0.0.1:33996 against the same 7ef9d0a4…
    /// leaf — five-occurrence post-recycle reconnect twin of ec156a1db321… /
    /// bf210e609e7f… / d86f81358e32… / a87539b37de1… / a66e03d58e6a… / aae9c8a6b484… /
    /// b8e719ba13ca… / 67d134aeab25… / 669e26dad203… / eebfa17cec6b… / 639501fa4228… /
    /// 5d30a28d7f44… / 5804cb3aaf61… / 7904dd055f87… / 92ed0baffd5b… / fc4e0317d2a1… /
    /// 30e9c320e15b… / 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… (and gru
    /// 1f9106a25f41… cid 54 → 55 → 94 → 31 / gru d0feba5039c6… cid:53 / gru f106e39e815f…
    /// cid 52 → 91 / gru 88ff8c404d3b… cid 51 → 90 / gru 897b9ff7b37e… cid 50 → 89 / gru
    /// 8a0aaf8cb1da… cid 49 → 88 → 45 → 55 / gru 6be7ec00050d… cid 48 → 87 / gru
    /// 0401b56675fd… cid 47 → 86 / gru e962f4a49508… cid 46 → 85 / gru 3f4dc73e62f2… cid
    /// 45 → 84 → 44 → 54 / gru 5990e53d2fde… cid 44 → 83 / sfo e7adbe3390eb… cid 52 → 91 /
    /// sfo e583d837318a… dual cid 49+50 → 88+89 / sfo 02525de8dfa3… cid 47 → 86 → 39 / sfo
    /// ef71b6e32493… dual cid 45+46 → 84+85 / sfo b439248687d8… cid 44 → 83 / sfo
    /// c907c56a7c0c… cid 43 → 82 → 38 at the adjacent wall-clock 18:46:03Z / 18:46:04Z /
    /// 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z / 18:46:09Z / 18:46:10Z /
    /// 18:46:11Z / 18:46:12Z / 18:46:13Z / 18:46:14Z / 18:46:15Z / 18:46:17Z /
    /// 18:46:19Z / 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z /
    /// 18:47:08Z / 18:47:09Z / 18:47:10Z / 18:47:11Z / 18:47:12Z / 18:47:13Z /
    /// 18:47:14Z / 18:47:15Z / 18:47:17Z / 18:47:19Z / 18:48:10Z / 18:48:15Z /
    /// 18:49:10Z / 18:49:19Z / 18:50:09Z / 18:50:15Z steps) after bare product-NATS
    /// RestartAsync;
    /// fingerprint 8e310ea4f277… / fra-product-nats CN=fra-platform cid 55 → 94 → 48 → 41 at
    /// 18:46:21Z on 127.0.0.1:47568, 18:47:21Z on 127.0.0.1:48244, 18:48:21Z on
    /// 127.0.0.1:42936, and 18:50:21Z on 127.0.0.1:56688 against the same 7ef9d0a4…
    /// leaf — four-occurrence post-recycle reconnect twin of 59a0656971a4… /
    /// ec156a1db321… / bf210e609e7f… / d86f81358e32… / a87539b37de1… / a66e03d58e6a… /
    /// aae9c8a6b484… / b8e719ba13ca… / 67d134aeab25… / 669e26dad203… / eebfa17cec6b… /
    /// 639501fa4228… / 5d30a28d7f44… / 5804cb3aaf61… / 7904dd055f87… / 92ed0baffd5b… /
    /// fc4e0317d2a1… / 30e9c320e15b… / 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43…
    /// (and gru 7dae08a6f4b3… cid 56 → 47 → 41 / gru 1f9106a25f41… cid 54 → 55 → 94 → 31 /
    /// gru d0feba5039c6… cid:53 / gru f106e39e815f… cid 52 → 91 / sfo e7adbe3390eb… cid
    /// 52 → 91 / sfo e583d837318a… dual cid 49+50 → 88+89 at the adjacent wall-clock
    /// 18:46:17Z / 18:46:19Z / 18:46:21Z / 18:47:17Z / 18:47:19Z / 18:47:21Z /
    /// 18:48:21Z / 18:49:19Z / 18:50:21Z steps; two seconds after 59a0656971a4… cid 53 →
    /// 54 → 92 → 93 → 31 on adjacent :19 steps / ports 47548/47562 → 47568 and
    /// 48216/48240 → 48244; same wall-clock :21 as gru 7dae08a6f4b3…) after bare
    /// product-NATS RestartAsync;
    /// fingerprint d087ae1829c6… / fra-product-nats CN=fra-platform cid 56 → 95 at
    /// 18:46:23Z on 127.0.0.1:47578 and 18:47:23Z on 127.0.0.1:48248 against the same
    /// 7ef9d0a4… leaf — two-occurrence post-recycle reconnect twin of 8e310ea4f277… /
    /// 59a0656971a4… / ec156a1db321… / bf210e609e7f… / d86f81358e32… / a87539b37de1… /
    /// a66e03d58e6a… / aae9c8a6b484… / b8e719ba13ca… / 67d134aeab25… / 669e26dad203… /
    /// eebfa17cec6b… / 639501fa4228… / 5d30a28d7f44… / 5804cb3aaf61… / 7904dd055f87… /
    /// 92ed0baffd5b… / fc4e0317d2a1… / 30e9c320e15b… / 25ef0004168c… / dacc95d0e7ba… /
    /// 1e8b88f75d43… (and gru d22a1e331a57… cid 57 → 96 / sfo db61915863fe… cid 56 → 95 /
    /// gru 7dae08a6f4b3… cid 56 → 47 → 41 / gru 1f9106a25f41… cid 54 → 55 → 94 → 31 at
    /// the adjacent wall-clock 18:46:19Z / 18:46:21Z / 18:46:23Z / 18:46:24Z /
    /// 18:47:19Z / 18:47:21Z / 18:47:23Z / 18:47:24Z steps; two seconds after
    /// 8e310ea4f277… cid 55 → 94 → 48 → 41 on adjacent :21 steps / ports 47568 → 47578
    /// and 48244 → 48248; same wall-clock :23 as gru d22a1e331a57…; one second before
    /// sfo db61915863fe… cid 56 → 95 at :24) after bare product-NATS RestartAsync;
    /// fingerprint 86b0b173f024… / fra-product-nats CN=fra-platform cid 57 → 96 → 97 → 32 at
    /// 18:46:25Z on 127.0.0.1:60966, 18:47:25Z on 127.0.0.1:48826 and 127.0.0.1:48848 (dual
    /// cid 96+97), and 18:49:25Z on 127.0.0.1:41430 against the same 7ef9d0a4… leaf —
    /// four-occurrence post-recycle reconnect twin of d087ae1829c6… / 8e310ea4f277… /
    /// 59a0656971a4… / ec156a1db321… / bf210e609e7f… / d86f81358e32… / a87539b37de1… /
    /// a66e03d58e6a… / aae9c8a6b484… / b8e719ba13ca… / 67d134aeab25… / 669e26dad203… /
    /// eebfa17cec6b… / 639501fa4228… / 5d30a28d7f44… / 5804cb3aaf61… / 7904dd055f87… /
    /// 92ed0baffd5b… / fc4e0317d2a1… / 30e9c320e15b… / 25ef0004168c… / dacc95d0e7ba… /
    /// 1e8b88f75d43… (and gru d26427e1c533… cid 58 → 97 → 98 → 32 / gru d22a1e331a57…
    /// cid 57 → 96 / sfo db61915863fe… cid 56 → 95 / gru 7dae08a6f4b3… cid 56 → 47 → 41 /
    /// gru 1f9106a25f41… cid 54 → 55 → 94 → 31 at the adjacent wall-clock 18:46:19Z /
    /// 18:46:21Z / 18:46:23Z / 18:46:24Z / 18:46:25Z / 18:47:19Z / 18:47:21Z /
    /// 18:47:23Z / 18:47:24Z / 18:47:25Z / 18:49:25Z steps; two seconds after
    /// d087ae1829c6… cid 56 → 95 on adjacent :23 steps; same wall-clock :25 as gru
    /// d26427e1c533… cid 58 → 97 → 98 → 32; same cid 57 → 96 as gru d22a1e331a57… two
    /// seconds earlier at :23) after bare product-NATS RestartAsync;
    /// fingerprint 54fea6c92b78… / gru-product-nats CN=gru-platform cid 14635 → 38 → 50 → 44
    /// at 18:45:40Z / 18:47:40Z / 18:48:40Z / 18:50:40Z against the same 6b500765… leaf
    /// — denser four-occurrence twin of 57ae70882ed5…;
    /// fingerprint 0b23b4fb5a75… / gru-product-nats CN=gru-platform cid:31 at 18:45:42Z on
    /// 127.0.0.1:39462 against the same 6b500765… leaf — single post-recycle reconnect twin
    /// of 54fea6c92b78… / 57ae70882ed5… after bare product-NATS RestartAsync;
    /// fingerprint 1364f1b0cdbc… / gru-product-nats CN=gru-platform cid 32 → 70 → 71 → 40 at
    /// 18:45:43Z on 127.0.0.1:39470, 18:46:43Z on 127.0.0.1:47014 / 47034 (dual), and 18:47:43Z
    /// on 127.0.0.1:38360 against the same 6b500765… leaf — four-occurrence post-recycle
    /// reconnect twin of 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5… after bare product-NATS
    /// RestartAsync;
    /// fingerprint 0cbc78bc3a3a… / gru-product-nats CN=gru-platform cid 33 → 72 → 41 → 51 → 45 at
    /// 18:45:46Z on 127.0.0.1:48834, 18:46:46Z on 127.0.0.1:60204, 18:47:46Z on 127.0.0.1:56364,
    /// 18:48:46Z on 127.0.0.1:39346, and 18:50:46Z on 127.0.0.1:48414 against the same
    /// 6b500765… leaf — five-occurrence post-recycle reconnect twin of 1364f1b0cdbc… /
    /// 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5… after bare product-NATS RestartAsync;
    /// fingerprint 6a1c43a93378… / gru-product-nats CN=gru-platform cid 34 → 73 at
    /// 18:45:48Z on 127.0.0.1:48846 and 18:46:48Z on 127.0.0.1:60214 against the same
    /// 6b500765… leaf — two-occurrence post-recycle reconnect twin of 0cbc78bc3a3a… /
    /// 1364f1b0cdbc… / 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5… after bare product-NATS
    /// RestartAsync;
    /// fingerprint ed3f4504d5e1… / gru-product-nats CN=gru-platform cid 35 → 36 → 75 → 36 at
    /// 18:45:50Z on 127.0.0.1:48870 / 48878 (dual cid 35+36), 18:46:50Z on 127.0.0.1:60244,
    /// and 18:49:50Z on 127.0.0.1:41546 against the same 6b500765… leaf — four-occurrence
    /// post-recycle reconnect twin of 6a1c43a93378… / 0cbc78bc3a3a… / 1364f1b0cdbc… /
    /// 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5… (and sfo 146c64f3fc52… / operator-read
    /// twins f4f92376efda… / 62860f83eeb6… at the same wall-clock pair) after bare
    /// product-NATS RestartAsync;
    /// fingerprint b22018f7aa7b… / gru-product-nats CN=gru-platform cid 37 → 76 → 52 → 46 at
    /// 18:45:52Z on 127.0.0.1:48880, 18:46:52Z on 127.0.0.1:60260, 18:48:52Z on
    /// 127.0.0.1:39364, and 18:50:52Z on 127.0.0.1:48432 against the same 6b500765… leaf —
    /// four-occurrence post-recycle reconnect twin of ed3f4504d5e1… / 6a1c43a93378… /
    /// 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5… (and sfo
    /// eaa27086a65c… / fra 92ed0baffd5b… / operator-read twins at adjacent wall-clock
    /// :50/:51/:52 steps) after bare product-NATS RestartAsync;
    /// fingerprint 9371738eec92… / gru-product-nats CN=gru-platform cid 38 → 77 at
    /// 18:45:54Z on 127.0.0.1:48886 and 18:46:54Z on 127.0.0.1:60264 against the same
    /// 6b500765… leaf — two-occurrence post-recycle reconnect twin of b22018f7aa7b… /
    /// ed3f4504d5e1… / 6a1c43a93378… / 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75… /
    /// 54fea6c92b78… / 57ae70882ed5… (and sfo e33d87402e17… / fra 7904dd055f87… /
    /// operator-read twins at adjacent wall-clock :52/:53/:54 steps) after bare
    /// product-NATS RestartAsync;
    /// fingerprint 02a670a12fe6… / gru-product-nats CN=gru-platform cid:78 at 18:46:55Z on
    /// 127.0.0.1:53194 against the same 6b500765… leaf — single post-recycle reconnect twin
    /// of 9371738eec92… / b22018f7aa7b… / ed3f4504d5e1… / 6a1c43a93378… / 0cbc78bc3a3a… /
    /// 1364f1b0cdbc… / 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5… after bare
    /// product-NATS RestartAsync;
    /// fingerprint be7bee33b946… / gru-product-nats CN=gru-platform cid 39 → 40 → 79 → 37 at
    /// 18:45:56Z on 127.0.0.1:35188 / 127.0.0.1:35204 (dual cid 39+40), 18:46:56Z on
    /// 127.0.0.1:53210, and 18:49:56Z on 127.0.0.1:49142 against the same 6b500765… leaf —
    /// four-occurrence post-recycle reconnect twin of 02a670a12fe6… / 9371738eec92… /
    /// b22018f7aa7b… / ed3f4504d5e1… / 6a1c43a93378… / 0cbc78bc3a3a… / 1364f1b0cdbc… /
    /// 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5… (and gru operator-read b252d8996050… /
    /// gru-controller a9bf884a363b… / sfo operator-read 97d33257778a… / fra operator-read
    /// c74671d2c0e4… at the same wall-clock :56 steps) after bare product-NATS RestartAsync;
    /// fingerprint a2e01c16a27c… / gru-product-nats CN=gru-platform cid 41 → 80 → 53 at
    /// 18:45:58Z on 127.0.0.1:35206, 18:46:58Z on 127.0.0.1:53226, and 18:48:58Z on
    /// 127.0.0.1:54632 against the same 6b500765… leaf — three-occurrence post-recycle
    /// reconnect twin of be7bee33b946… / 02a670a12fe6… / 9371738eec92… / b22018f7aa7b… /
    /// ed3f4504d5e1… / 6a1c43a93378… / 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75… /
    /// 54fea6c92b78… / 57ae70882ed5… (and sfo 9b960cc93f83… / fra 5d30a28d7f44… / gru
    /// operator-read b252d8996050… / gru-controller a9bf884a363b… / sfo operator-read
    /// 97d33257778a… / fra operator-read c74671d2c0e4… at adjacent wall-clock :56/:57/:58
    /// steps) after bare product-NATS RestartAsync;
    /// fingerprint 764b28c3439a… / gru-product-nats CN=gru-platform cid 42 → 81 at
    /// 18:46:00Z on 127.0.0.1:35222 and 18:47:00Z on 127.0.0.1:53234 against the same
    /// 6b500765… leaf — two-occurrence post-recycle reconnect twin of a2e01c16a27c… /
    /// be7bee33b946… / 02a670a12fe6… / 9371738eec92… / b22018f7aa7b… / ed3f4504d5e1… /
    /// 6a1c43a93378… / 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75… / 54fea6c92b78… /
    /// 57ae70882ed5… (and gru controller 25b92b919c66… at the same wall-clock 18:46:00Z /
    /// 18:47:00Z steps) after bare product-NATS RestartAsync;
    /// fingerprint 6d84bda1e560… / gru-product-nats CN=gru-platform cid 43 → 82 at
    /// 18:46:01Z on 127.0.0.1:35228 and 18:47:01Z on 127.0.0.1:53246 against the same
    /// 6b500765… leaf — two-occurrence post-recycle reconnect twin of 764b28c3439a… /
    /// a2e01c16a27c… / be7bee33b946… / 02a670a12fe6… / 9371738eec92… / b22018f7aa7b… /
    /// ed3f4504d5e1… / 6a1c43a93378… / 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75… /
    /// 54fea6c92b78… / 57ae70882ed5… (and sfo eacb3282ca0c… dual cid 41+42 → 80+81 / fra
    /// eebfa17cec6b… cid 41 → 80 at the same wall-clock 18:46:01Z / 18:47:01Z steps) after
    /// bare product-NATS RestartAsync;
    /// fingerprint 5990e53d2fde… / gru-product-nats CN=gru-platform cid 44 → 83 at
    /// 18:46:02Z on 127.0.0.1:35234 and 18:47:02Z on 127.0.0.1:53260 against the same
    /// 6b500765… leaf — two-occurrence post-recycle reconnect twin of 6d84bda1e560… /
    /// 764b28c3439a… / a2e01c16a27c… / be7bee33b946… / 02a670a12fe6… / 9371738eec92… /
    /// b22018f7aa7b… / ed3f4504d5e1… / 6a1c43a93378… / 0cbc78bc3a3a… / 1364f1b0cdbc… /
    /// 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5… (and sfo eacb3282ca0c… dual cid 41+42 →
    /// 80+81 / fra eebfa17cec6b… cid 41 → 80 / fra 669e26dad203… cid 42 → 81 at the adjacent
    /// wall-clock 18:46:01Z / 18:47:01Z steps) after bare product-NATS RestartAsync;
    /// fingerprint 3f4dc73e62f2… / gru-product-nats CN=gru-platform cid 45 → 84 → 44 → 54 at
    /// 18:46:04Z on 127.0.0.1:44042, 18:47:04Z on 127.0.0.1:48200, 18:48:04Z on
    /// 127.0.0.1:42712, and 18:49:04Z on 127.0.0.1:48152 against the same 6b500765… leaf —
    /// four-occurrence post-recycle reconnect twin of 5990e53d2fde… / 6d84bda1e560… /
    /// 764b28c3439a… / a2e01c16a27c… / be7bee33b946… / 02a670a12fe6… / 9371738eec92… /
    /// b22018f7aa7b… / ed3f4504d5e1… / 6a1c43a93378… / 0cbc78bc3a3a… / 1364f1b0cdbc… /
    /// 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5… (and sfo c907c56a7c0c… cid 43 → 82 → 38 /
    /// fra 67d134aeab25… cid 43 → 38 at the adjacent wall-clock 18:46:03Z / 18:47:03Z /
    /// 18:50:03Z steps) after bare product-NATS RestartAsync;
    /// fingerprint e962f4a49508… / gru-product-nats CN=gru-platform cid 46 → 85 at
    /// 18:46:06Z on 127.0.0.1:44054 and 18:47:06Z on 127.0.0.1:48204 against the same
    /// 6b500765… leaf — two-occurrence post-recycle reconnect twin of 3f4dc73e62f2… /
    /// 5990e53d2fde… / 6d84bda1e560… / 764b28c3439a… / a2e01c16a27c… / be7bee33b946… /
    /// 02a670a12fe6… / 9371738eec92… / b22018f7aa7b… / ed3f4504d5e1… / 6a1c43a93378… /
    /// 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5… (and
    /// sfo b439248687d8… cid 44 → 83 / fra b8e719ba13ca… cid:44 / sfo c907c56a7c0c… cid 43 →
    /// 82 → 38 / fra 67d134aeab25… cid 43 → 38 at the adjacent wall-clock 18:46:03Z /
    /// 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z
    /// steps) after bare product-NATS RestartAsync;
    /// fingerprint 0401b56675fd… / gru-product-nats CN=gru-platform cid 47 → 86 at
    /// 18:46:07Z on 127.0.0.1:44066 and 18:47:07Z on 127.0.0.1:48220 against the same
    /// 6b500765… leaf — two-occurrence post-recycle reconnect twin of e962f4a49508… /
    /// 3f4dc73e62f2… / 5990e53d2fde… / 6d84bda1e560… / 764b28c3439a… / a2e01c16a27c… /
    /// be7bee33b946… / 02a670a12fe6… / 9371738eec92… / b22018f7aa7b… / ed3f4504d5e1… /
    /// 6a1c43a93378… / 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75… / 54fea6c92b78… /
    /// 57ae70882ed5… (and sfo ef71b6e32493… dual cid 45+46 → 84+85 / fra aae9c8a6b484…
    /// dual cid 45+46 → 84+85 / sfo b439248687d8… cid 44 → 83 / fra b8e719ba13ca… cid:44 /
    /// sfo c907c56a7c0c… cid 43 → 82 → 38 / fra 67d134aeab25… cid 43 → 38 at the adjacent
    /// wall-clock 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:47:03Z /
    /// 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z steps) after bare product-NATS
    /// RestartAsync;
    /// fingerprint 6be7ec00050d… / gru-product-nats CN=gru-platform cid 48 → 87 at
    /// 18:46:08Z on 127.0.0.1:44070 and 18:47:08Z on 127.0.0.1:48226 against the same
    /// 6b500765… leaf — two-occurrence post-recycle reconnect twin of 0401b56675fd… /
    /// e962f4a49508… / 3f4dc73e62f2… / 5990e53d2fde… / 6d84bda1e560… / 764b28c3439a… /
    /// a2e01c16a27c… / be7bee33b946… / 02a670a12fe6… / 9371738eec92… / b22018f7aa7b… /
    /// ed3f4504d5e1… / 6a1c43a93378… / 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75… /
    /// 54fea6c92b78… / 57ae70882ed5… (and sfo ef71b6e32493… dual cid 45+46 → 84+85 / fra
    /// aae9c8a6b484… dual cid 45+46 → 84+85 / sfo b439248687d8… cid 44 → 83 / fra
    /// b8e719ba13ca… cid:44 / sfo c907c56a7c0c… cid 43 → 82 → 38 / fra 67d134aeab25…
    /// cid 43 → 38 at the adjacent wall-clock 18:46:03Z / 18:46:04Z / 18:46:05Z /
    /// 18:46:06Z / 18:46:07Z / 18:46:08Z / 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z /
    /// 18:47:07Z / 18:47:08Z steps) after bare product-NATS RestartAsync;
    /// fingerprint 8a0aaf8cb1da… / gru-product-nats CN=gru-platform cid 49 → 88 → 45 → 55 at
    /// 18:46:10Z on 127.0.0.1:44074, 18:47:10Z on 127.0.0.1:48238, 18:48:10Z on
    /// 127.0.0.1:52880, and 18:49:10Z on 127.0.0.1:48166 against the same 6b500765… leaf —
    /// four-occurrence post-recycle reconnect twin of 6be7ec00050d… / 0401b56675fd… /
    /// e962f4a49508… / 3f4dc73e62f2… / 5990e53d2fde… / 6d84bda1e560… / 764b28c3439a… /
    /// a2e01c16a27c… / be7bee33b946… / 02a670a12fe6… / 9371738eec92… / b22018f7aa7b… /
    /// ed3f4504d5e1… / 6a1c43a93378… / 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75… /
    /// 54fea6c92b78… / 57ae70882ed5… (and sfo ef71b6e32493… dual cid 45+46 → 84+85 / fra
    /// aae9c8a6b484… dual cid 45+46 → 84+85 / sfo 02525de8dfa3… cid 47 → 86 → 39 / fra
    /// a66e03d58e6a… cid 47 → 86 → 39 / sfo b439248687d8… cid 44 → 83 / fra b8e719ba13ca…
    /// cid:44 / sfo c907c56a7c0c… cid 43 → 82 → 38 / fra 67d134aeab25… cid 43 → 38 at the
    /// adjacent wall-clock 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z /
    /// 18:46:08Z / 18:46:09Z / 18:46:10Z / 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z /
    /// 18:47:07Z / 18:47:08Z / 18:47:09Z / 18:47:10Z / 18:48:10Z / 18:49:10Z steps) after
    /// bare product-NATS RestartAsync;
    /// fingerprint 897b9ff7b37e… / gru-product-nats CN=gru-platform cid 50 → 89 at
    /// 18:46:12Z on 127.0.0.1:44082 and 18:47:12Z on 127.0.0.1:48252 against the same
    /// 6b500765… leaf — two-occurrence post-recycle reconnect twin of 8a0aaf8cb1da… /
    /// 6be7ec00050d… / 0401b56675fd… / e962f4a49508… / 3f4dc73e62f2… / 5990e53d2fde… /
    /// 6d84bda1e560… / 764b28c3439a… / a2e01c16a27c… / be7bee33b946… / 02a670a12fe6… /
    /// 9371738eec92… / b22018f7aa7b… / ed3f4504d5e1… / 6a1c43a93378… / 0cbc78bc3a3a… /
    /// 1364f1b0cdbc… / 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5… (and sfo
    /// ef71b6e32493… dual cid 45+46 → 84+85 / fra aae9c8a6b484… dual cid 45+46 → 84+85 /
    /// sfo 02525de8dfa3… cid 47 → 86 → 39 / fra a66e03d58e6a… cid 47 → 86 → 39 / sfo
    /// b439248687d8… cid 44 → 83 / fra b8e719ba13ca… cid:44 / sfo c907c56a7c0c… cid 43 →
    /// 82 → 38 / fra 67d134aeab25… cid 43 → 38 / fra a87539b37de1… cid 48 → 87 at the
    /// adjacent wall-clock 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z /
    /// 18:46:08Z / 18:46:09Z / 18:46:10Z / 18:46:11Z / 18:46:12Z / 18:47:03Z / 18:47:04Z /
    /// 18:47:05Z / 18:47:06Z / 18:47:07Z / 18:47:08Z / 18:47:09Z / 18:47:10Z / 18:47:11Z /
    /// 18:47:12Z / 18:48:10Z / 18:49:10Z steps) after bare product-NATS RestartAsync;
    /// fingerprint 88ff8c404d3b… / gru-product-nats CN=gru-platform cid 51 → 90 at
    /// 18:46:13Z on 127.0.0.1:44104 and 18:47:13Z on 127.0.0.1:48274 against the same
    /// 6b500765… leaf — two-occurrence post-recycle reconnect twin of 897b9ff7b37e… /
    /// 8a0aaf8cb1da… / 6be7ec00050d… / 0401b56675fd… / e962f4a49508… / 3f4dc73e62f2… /
    /// 5990e53d2fde… / 6d84bda1e560… / 764b28c3439a… / a2e01c16a27c… / be7bee33b946… /
    /// 02a670a12fe6… / 9371738eec92… / b22018f7aa7b… / ed3f4504d5e1… / 6a1c43a93378… /
    /// 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5… (and
    /// sfo e583d837318a… dual cid 49+50 → 88+89 / fra d86f81358e32… dual cid 49+50 → 88+89 /
    /// sfo ef71b6e32493… dual cid 45+46 → 84+85 / fra aae9c8a6b484… dual cid 45+46 → 84+85 /
    /// sfo 02525de8dfa3… cid 47 → 86 → 39 / fra a66e03d58e6a… cid 47 → 86 → 39 / sfo
    /// b439248687d8… cid 44 → 83 / fra b8e719ba13ca… cid:44 / sfo c907c56a7c0c… cid 43 →
    /// 82 → 38 / fra 67d134aeab25… cid 43 → 38 / fra a87539b37de1… cid 48 → 87 at the
    /// adjacent wall-clock 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z /
    /// 18:46:08Z / 18:46:09Z / 18:46:10Z / 18:46:11Z / 18:46:12Z / 18:46:13Z / 18:47:03Z /
    /// 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z / 18:47:08Z / 18:47:09Z / 18:47:10Z /
    /// 18:47:11Z / 18:47:12Z / 18:47:13Z / 18:48:10Z / 18:49:10Z steps) after bare
    /// product-NATS RestartAsync;
    /// fingerprint f106e39e815f… / gru-product-nats CN=gru-platform cid 52 → 91 at
    /// 18:46:14Z on 127.0.0.1:38738 and 18:47:14Z on 127.0.0.1:47750 against the same
    /// 6b500765… leaf — two-occurrence post-recycle reconnect twin of 88ff8c404d3b… /
    /// 897b9ff7b37e… / 8a0aaf8cb1da… / 6be7ec00050d… / 0401b56675fd… / e962f4a49508… /
    /// 3f4dc73e62f2… / 5990e53d2fde… / 6d84bda1e560… / 764b28c3439a… / a2e01c16a27c… /
    /// be7bee33b946… / 02a670a12fe6… / 9371738eec92… / b22018f7aa7b… / ed3f4504d5e1… /
    /// 6a1c43a93378… / 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75… / 54fea6c92b78… /
    /// 57ae70882ed5… (and sfo e583d837318a… dual cid 49+50 → 88+89 / fra d86f81358e32…
    /// dual cid 49+50 → 88+89 / sfo ef71b6e32493… dual cid 45+46 → 84+85 / fra
    /// aae9c8a6b484… dual cid 45+46 → 84+85 / sfo 02525de8dfa3… cid 47 → 86 → 39 / fra
    /// a66e03d58e6a… cid 47 → 86 → 39 / sfo b439248687d8… cid 44 → 83 / fra b8e719ba13ca…
    /// cid:44 / sfo c907c56a7c0c… cid 43 → 82 → 38 / fra 67d134aeab25… cid 43 → 38 / fra
    /// a87539b37de1… cid 48 → 87 at the adjacent wall-clock 18:46:03Z / 18:46:04Z /
    /// 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z / 18:46:09Z / 18:46:10Z /
    /// 18:46:11Z / 18:46:12Z / 18:46:13Z / 18:46:14Z / 18:47:03Z / 18:47:04Z /
    /// 18:47:05Z / 18:47:06Z / 18:47:07Z / 18:47:08Z / 18:47:09Z / 18:47:10Z /
    /// 18:47:11Z / 18:47:12Z / 18:47:13Z / 18:47:14Z / 18:48:10Z / 18:49:10Z steps) after
    /// bare product-NATS RestartAsync;
    /// fingerprint d0feba5039c6… / gru-product-nats CN=gru-platform cid:53 at
    /// 18:46:17Z on 127.0.0.1:38752 against the same 6b500765… leaf — single post-recycle
    /// reconnect twin of f106e39e815f… / 88ff8c404d3b… / 897b9ff7b37e… / 8a0aaf8cb1da… /
    /// 6be7ec00050d… / 0401b56675fd… / e962f4a49508… / 3f4dc73e62f2… / 5990e53d2fde… /
    /// 6d84bda1e560… / 764b28c3439a… / a2e01c16a27c… / be7bee33b946… / 02a670a12fe6… /
    /// 9371738eec92… / b22018f7aa7b… / ed3f4504d5e1… / 6a1c43a93378… / 0cbc78bc3a3a… /
    /// 1364f1b0cdbc… / 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5… (and sfo
    /// e583d837318a… dual cid 49+50 → 88+89 / fra d86f81358e32… dual cid 49+50 → 88+89 /
    /// sfo ef71b6e32493… dual cid 45+46 → 84+85 / fra aae9c8a6b484… dual cid 45+46 → 84+85 /
    /// sfo 02525de8dfa3… cid 47 → 86 → 39 / fra a66e03d58e6a… cid 47 → 86 → 39 / sfo
    /// b439248687d8… cid 44 → 83 / fra b8e719ba13ca… cid:44 / sfo c907c56a7c0c… cid 43 →
    /// 82 → 38 / fra 67d134aeab25… cid 43 → 38 / fra a87539b37de1… cid 48 → 87 at the
    /// adjacent wall-clock 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z /
    /// 18:46:08Z / 18:46:09Z / 18:46:10Z / 18:46:11Z / 18:46:12Z / 18:46:13Z /
    /// 18:46:14Z / 18:46:17Z / 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z /
    /// 18:47:07Z / 18:47:08Z / 18:47:09Z / 18:47:10Z / 18:47:11Z / 18:47:12Z /
    /// 18:47:13Z / 18:47:14Z / 18:48:10Z / 18:49:10Z steps) after bare product-NATS
    /// RestartAsync;
    /// fingerprint 1f9106a25f41… / gru-product-nats CN=gru-platform cid 54 → 55 → 94 → 31 at
    /// 18:46:19Z on 127.0.0.1:38766 and 127.0.0.1:38790, 18:47:19Z on 127.0.0.1:47780, and
    /// 18:49:19Z on 127.0.0.1:45348 against the same 6b500765… leaf — four-occurrence
    /// post-recycle reconnect twin of d0feba5039c6… / f106e39e815f… / 88ff8c404d3b… /
    /// 897b9ff7b37e… / 8a0aaf8cb1da… / 6be7ec00050d… / 0401b56675fd… / e962f4a49508… /
    /// 3f4dc73e62f2… / 5990e53d2fde… / 6d84bda1e560… / 764b28c3439a… / a2e01c16a27c… /
    /// be7bee33b946… / 02a670a12fe6… / 9371738eec92… / b22018f7aa7b… / ed3f4504d5e1… /
    /// 6a1c43a93378… / 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75… / 54fea6c92b78… /
    /// 57ae70882ed5… (and sfo e7adbe3390eb… cid 52 → 91 / sfo e583d837318a… dual cid 49+50 →
    /// 88+89 / fra d86f81358e32… dual cid 49+50 → 88+89 / sfo ef71b6e32493… dual cid 45+46 →
    /// 84+85 / fra aae9c8a6b484… dual cid 45+46 → 84+85 / sfo 02525de8dfa3… cid 47 → 86 → 39 /
    /// fra a66e03d58e6a… cid 47 → 86 → 39 / sfo b439248687d8… cid 44 → 83 / fra
    /// b8e719ba13ca… cid:44 / sfo c907c56a7c0c… cid 43 → 82 → 38 / fra 67d134aeab25… cid 43 →
    /// 38 / fra a87539b37de1… cid 48 → 87 at the adjacent wall-clock 18:46:03Z / 18:46:04Z /
    /// 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z / 18:46:09Z / 18:46:10Z /
    /// 18:46:11Z / 18:46:12Z / 18:46:13Z / 18:46:14Z / 18:46:17Z / 18:46:19Z /
    /// 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z / 18:47:08Z /
    /// 18:47:09Z / 18:47:10Z / 18:47:11Z / 18:47:12Z / 18:47:13Z / 18:47:14Z /
    /// 18:47:19Z / 18:48:10Z / 18:49:10Z / 18:49:19Z steps) after bare product-NATS
    /// RestartAsync;
    /// fingerprint 7dae08a6f4b3… / gru-product-nats CN=gru-platform cid 56 → 47 → 41 at
    /// 18:46:21Z on 127.0.0.1:38792, 18:48:21Z on 127.0.0.1:60122, and 18:50:21Z on
    /// 127.0.0.1:49552 against the same 6b500765… leaf — three-occurrence post-recycle
    /// reconnect twin of 1f9106a25f41… / d0feba5039c6… / f106e39e815f… / 88ff8c404d3b… /
    /// 897b9ff7b37e… / 8a0aaf8cb1da… / 6be7ec00050d… / 0401b56675fd… / e962f4a49508… /
    /// 3f4dc73e62f2… / 5990e53d2fde… / 6d84bda1e560… / 764b28c3439a… / a2e01c16a27c… /
    /// be7bee33b946… / 02a670a12fe6… / 9371738eec92… / b22018f7aa7b… / ed3f4504d5e1… /
    /// 6a1c43a93378… / 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75… / 54fea6c92b78… /
    /// 57ae70882ed5… (two seconds after 1f9106a25f41… cid 54 → 55 → 94 → 31 on adjacent
    /// :19 steps / ports 38766/38790 → 38792) after bare product-NATS RestartAsync;
    /// fingerprint d22a1e331a57… / gru-product-nats CN=gru-platform cid 57 → 96 at
    /// 18:46:23Z on 127.0.0.1:38800 and 18:47:23Z on 127.0.0.1:47792 against the same
    /// 6b500765… leaf — two-occurrence post-recycle reconnect twin of 7dae08a6f4b3… /
    /// 1f9106a25f41… / d0feba5039c6… / f106e39e815f… / 88ff8c404d3b… / 897b9ff7b37e… /
    /// 8a0aaf8cb1da… / 6be7ec00050d… / 0401b56675fd… / e962f4a49508… / 3f4dc73e62f2… /
    /// 5990e53d2fde… / 6d84bda1e560… / 764b28c3439a… / a2e01c16a27c… / be7bee33b946… /
    /// 02a670a12fe6… / 9371738eec92… / b22018f7aa7b… / ed3f4504d5e1… / 6a1c43a93378… /
    /// 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5…
    /// (two seconds after 7dae08a6f4b3… cid 56 → 47 → 41 on adjacent :21 steps / port
    /// 38792 → 38800; four seconds after 1f9106a25f41… cid 54 → 55 → 94 → 31 on :19 steps
    /// / ports 38766/38790 → 38800) after bare product-NATS RestartAsync;
    /// fingerprint d26427e1c533… / gru-product-nats CN=gru-platform cid 58 → 97 → 98 → 32 at
    /// 18:46:25Z on 127.0.0.1:35236, 18:47:25Z on 127.0.0.1:60448 and 127.0.0.1:60464 (dual
    /// cid 97+98), and 18:49:25Z on 127.0.0.1:58424 against the same 6b500765… leaf —
    /// four-occurrence post-recycle reconnect twin of d22a1e331a57… / 7dae08a6f4b3… /
    /// 1f9106a25f41… / d0feba5039c6… / f106e39e815f… / 88ff8c404d3b… / 897b9ff7b37e… /
    /// 8a0aaf8cb1da… / 6be7ec00050d… / 0401b56675fd… / e962f4a49508… / 3f4dc73e62f2… /
    /// 5990e53d2fde… / 6d84bda1e560… / 764b28c3439a… / a2e01c16a27c… / be7bee33b946… /
    /// 02a670a12fe6… / 9371738eec92… / b22018f7aa7b… / ed3f4504d5e1… / 6a1c43a93378… /
    /// 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5…
    /// (two seconds after d22a1e331a57… cid 57 → 96 on adjacent :23 steps / port 38800 →
    /// 35236; four seconds after 7dae08a6f4b3… cid 56 → 47 → 41 on :21 steps; six seconds
    /// after 1f9106a25f41… cid 54 → 55 → 94 → 31 on :19 steps) after bare product-NATS
    /// RestartAsync;
    /// fingerprint b1723b879b59… / sfo-product-nats CN=sfo-platform cid 14634 → 63 → 34 → 49 → 43
    /// at 18:45:34Z / 18:46:34Z / 18:47:34Z / 18:48:34Z / 18:50:34Z;
    /// fingerprint 77220dace263… / sfo-product-nats CN=sfo-platform cid 14635 → 67 → 37 → 38 → 50 → 44
    /// at 18:45:40Z / 18:46:40Z / 18:47:40Z / 18:47:40Z / 18:48:40Z / 18:50:40Z against the same
    /// a914ebca… leaf — denser six-occurrence twin of b1723b879b59…;
    /// fingerprint d739f8d83bed… / sfo-product-nats CN=sfo-platform cid 31 → 70 → 40 → 35 at
    /// 18:45:44Z on 127.0.0.1:39116, 18:46:44Z on 127.0.0.1:59792, 18:47:44Z on 127.0.0.1:47888,
    /// and 18:49:44Z on 127.0.0.1:42228 against the same a914ebca… leaf — four-occurrence
    /// post-recycle reconnect twin of b1723b879b59… / 77220dace263… (and gru 1364f1b0cdbc… /
    /// 0b23b4fb5a75…) after bare product-NATS RestartAsync;
    /// fingerprint a42bd88ac488… / sfo-product-nats CN=sfo-platform cid 32 → 71 → 41 → 51 → 45 at
    /// 18:45:46Z on 127.0.0.1:39118, 18:46:46Z on 127.0.0.1:59808, 18:47:46Z on 127.0.0.1:47908,
    /// 18:48:46Z on 127.0.0.1:54714, and 18:50:46Z on 127.0.0.1:60650 against the same
    /// a914ebca… leaf — five-occurrence post-recycle reconnect twin of d739f8d83bed… /
    /// b1723b879b59… / 77220dace263… (and gru 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75…,
    /// fra 30e9c320e15b…) after bare product-NATS RestartAsync;
    /// fingerprint 9f8f5f2cd955… / sfo-product-nats CN=sfo-platform cid 33 → 72 at
    /// 18:45:48Z on 127.0.0.1:39126 and 18:46:48Z on 127.0.0.1:59822 against the same
    /// a914ebca… leaf — two-occurrence post-recycle reconnect twin of a42bd88ac488… /
    /// d739f8d83bed… / b1723b879b59… / 77220dace263… (and gru 6a1c43a93378…, fra fc4e0317d2a1…)
    /// after bare product-NATS RestartAsync;
    /// fingerprint 146c64f3fc52… / sfo-product-nats CN=sfo-platform cid 34 → 36 at
    /// 18:45:50Z on 127.0.0.1:39142 and 18:49:50Z on 127.0.0.1:57178 against the same
    /// a914ebca… leaf — two-occurrence post-recycle reconnect twin of 9f8f5f2cd955… /
    /// a42bd88ac488… / d739f8d83bed… / b1723b879b59… / 77220dace263… (and operator-read twins
    /// f4f92376efda… / 62860f83eeb6… at the same wall-clock pair) after bare product-NATS
    /// RestartAsync;
    /// fingerprint eaa27086a65c… / sfo-product-nats CN=sfo-platform cid 35 → 74 → 42 at
    /// 18:45:51Z on 127.0.0.1:39154, 18:46:51Z on 127.0.0.1:59850, and 18:47:51Z on
    /// 127.0.0.1:47938 against the same a914ebca… leaf — three-occurrence post-recycle
    /// reconnect twin of 146c64f3fc52… / 9f8f5f2cd955… / a42bd88ac488… / d739f8d83bed… /
    /// b1723b879b59… / 77220dace263… (and gru ed3f4504d5e1… / fra 92ed0baffd5b… /
    /// operator-read twins f4f92376efda… / 62860f83eeb6… at adjacent wall-clock :50/:51
    /// steps) after bare product-NATS RestartAsync;
    /// fingerprint e33d87402e17… / sfo-product-nats CN=sfo-platform cid 36 → 75 at
    /// 18:45:53Z on 127.0.0.1:39168 and 18:46:53Z on 127.0.0.1:59854 against the same
    /// a914ebca… leaf — two-occurrence post-recycle reconnect twin of eaa27086a65c… /
    /// 146c64f3fc52… / 9f8f5f2cd955… / a42bd88ac488… / d739f8d83bed… / b1723b879b59… /
    /// 77220dace263… (and fra 7904dd055f87… / gru b22018f7aa7b… at adjacent wall-clock
    /// :52/:53 steps) after bare product-NATS RestartAsync;
    /// fingerprint 16f64e5cf6e5… / sfo-product-nats CN=sfo-platform cid 37 → 76 → 77 at
    /// 18:45:55Z on 127.0.0.1:45918 and 18:46:55Z on 127.0.0.1:39530 / 127.0.0.1:39552
    /// (dual cid 76+77) against the same a914ebca… leaf — three-occurrence post-recycle
    /// reconnect twin of e33d87402e17… / eaa27086a65c… / 146c64f3fc52… / 9f8f5f2cd955… /
    /// a42bd88ac488… / d739f8d83bed… / b1723b879b59… / 77220dace263… (and fra 5804cb3aaf61… /
    /// gru 9371738eec92… at adjacent wall-clock :54/:55 steps) after bare product-NATS
    /// RestartAsync;
    /// fingerprint 26b95f54769c… / sfo-product-nats CN=sfo-platform cid 38 → 37 at
    /// 18:45:56Z on 127.0.0.1:45940 and 18:49:56Z on 127.0.0.1:41844 against the same
    /// a914ebca… leaf — two-occurrence post-recycle reconnect twin of 16f64e5cf6e5… /
    /// e33d87402e17… / eaa27086a65c… / 146c64f3fc52… / 9f8f5f2cd955… / a42bd88ac488… /
    /// d739f8d83bed… / b1723b879b59… / 77220dace263… (and gru be7bee33b946… / gru operator-read
    /// b252d8996050… / gru-controller a9bf884a363b… / sfo operator-read 97d33257778a… /
    /// fra operator-read c74671d2c0e4… at the same wall-clock :56 steps) after bare
    /// product-NATS RestartAsync;
    /// fingerprint 9b960cc93f83… / sfo-product-nats CN=sfo-platform cid 39 → 78 → 43 at
    /// 18:45:57Z on 127.0.0.1:45942, 18:46:57Z on 127.0.0.1:39560, and 18:47:57Z on
    /// 127.0.0.1:52548 against the same a914ebca… leaf — three-occurrence post-recycle
    /// reconnect twin of 26b95f54769c… / 16f64e5cf6e5… / e33d87402e17… / eaa27086a65c… /
    /// 146c64f3fc52… / 9f8f5f2cd955… / a42bd88ac488… / d739f8d83bed… / b1723b879b59… /
    /// 77220dace263… (and gru be7bee33b946… / fra 5d30a28d7f44… / gru operator-read
    /// b252d8996050… / gru-controller a9bf884a363b… / sfo operator-read 97d33257778a… /
    /// fra operator-read c74671d2c0e4… at adjacent wall-clock :56/:57 steps) after bare
    /// product-NATS RestartAsync;
    /// fingerprint bf521ed338de… / sfo-product-nats CN=sfo-platform cid 40 → 79 at
    /// 18:45:59Z on 127.0.0.1:45954 and 18:46:59Z on 127.0.0.1:39572 against the same
    /// a914ebca… leaf — two-occurrence post-recycle reconnect twin of 9b960cc93f83… /
    /// 26b95f54769c… / 16f64e5cf6e5… / e33d87402e17… / eaa27086a65c… / 146c64f3fc52… /
    /// 9f8f5f2cd955… / a42bd88ac488… / d739f8d83bed… / b1723b879b59… / 77220dace263… (and
    /// gru a2e01c16a27c… / fra 639501fa4228… / gru be7bee33b946… / fra 5d30a28d7f44… / gru
    /// operator-read b252d8996050… / gru-controller a9bf884a363b… / sfo operator-read
    /// 97d33257778a… / fra operator-read c74671d2c0e4… at adjacent wall-clock :57/:58/:59
    /// steps) after bare product-NATS RestartAsync;
    /// fingerprint eacb3282ca0c… / sfo-product-nats CN=sfo-platform cid 41 → 42 → 80 → 81 at
    /// 18:46:01Z on 127.0.0.1:45962 / 127.0.0.1:45986 (dual cid 41+42) and 18:47:01Z on
    /// 127.0.0.1:39584 / 127.0.0.1:39598 (dual cid 80+81) against the same a914ebca… leaf —
    /// four-occurrence dual-reconnect post-recycle twin of bf521ed338de… / 9b960cc93f83… /
    /// 26b95f54769c… / 16f64e5cf6e5… / e33d87402e17… / eaa27086a65c… / 146c64f3fc52… /
    /// 9f8f5f2cd955… / a42bd88ac488… / d739f8d83bed… / b1723b879b59… / 77220dace263… (and fra
    /// eebfa17cec6b… cid 41 → 80 / gru 764b28c3439a… cid 42 → 81 / gru a2e01c16a27c… / fra
    /// 639501fa4228… / gru be7bee33b946… / fra 5d30a28d7f44… / gru operator-read b252d8996050… /
    /// gru-controller a9bf884a363b… / 25b92b919c66… / sfo operator-read 97d33257778a… / fra
    /// operator-read c74671d2c0e4… at the same wall-clock 18:46:01Z / 18:47:01Z steps) after
    /// bare product-NATS RestartAsync;
    /// fingerprint c907c56a7c0c… / sfo-product-nats CN=sfo-platform cid 43 → 82 → 38 at
    /// 18:46:03Z on 127.0.0.1:45990, 18:47:03Z on 127.0.0.1:39600, and 18:50:03Z on
    /// 127.0.0.1:41872 against the same a914ebca… leaf — three-occurrence post-recycle
    /// reconnect twin of eacb3282ca0c… / bf521ed338de… / 9b960cc93f83… / 26b95f54769c… /
    /// 16f64e5cf6e5… / e33d87402e17… / eaa27086a65c… / 146c64f3fc52… / 9f8f5f2cd955… /
    /// a42bd88ac488… / d739f8d83bed… / b1723b879b59… / 77220dace263… (and fra 67d134aeab25…
    /// cid 43 → 38 / gru 6d84bda1e560… cid 43 → 82 / gru 5990e53d2fde… cid 44 → 83 / gru
    /// 764b28c3439a… cid 42 → 81 / fra 669e26dad203… cid 42 → 81 at the adjacent wall-clock
    /// 18:46:01Z / 18:46:02Z / 18:46:03Z / 18:47:01Z / 18:47:02Z / 18:47:03Z / 18:50:03Z
    /// steps) after bare product-NATS RestartAsync;
    /// fingerprint b439248687d8… / sfo-product-nats CN=sfo-platform cid 44 → 83 at
    /// 18:46:05Z on 127.0.0.1:36238 and 18:47:05Z on 127.0.0.1:46560 against the same
    /// a914ebca… leaf — two-occurrence post-recycle reconnect twin of c907c56a7c0c… /
    /// eacb3282ca0c… / bf521ed338de… / 9b960cc93f83… / 26b95f54769c… / 16f64e5cf6e5… /
    /// e33d87402e17… / eaa27086a65c… / 146c64f3fc52… / 9f8f5f2cd955… / a42bd88ac488… /
    /// d739f8d83bed… / b1723b879b59… / 77220dace263… (and gru 5990e53d2fde… cid 44 → 83 /
    /// fra b8e719ba13ca… cid:44 / gru 3f4dc73e62f2… cid 45 → 84 → 44 → 54 / gru 6d84bda1e560…
    /// cid 43 → 82 / fra 67d134aeab25… cid 43 → 38 at the adjacent wall-clock 18:46:02Z /
    /// 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:47:02Z / 18:47:03Z / 18:47:05Z steps) after
    /// bare product-NATS RestartAsync;
    /// fingerprint ef71b6e32493… / sfo-product-nats CN=sfo-platform cid 45 → 46 → 84 → 85 at
    /// 18:46:07Z on 127.0.0.1:36252 / 127.0.0.1:36270 (dual cid 45+46) and 18:47:07Z on
    /// 127.0.0.1:46566 / 127.0.0.1:46574 (dual cid 84+85) against the same a914ebca… leaf —
    /// four-occurrence dual-cid post-recycle reconnect twin of b439248687d8… /
    /// c907c56a7c0c… / eacb3282ca0c… / bf521ed338de… / 9b960cc93f83… / 26b95f54769c… /
    /// 16f64e5cf6e5… / e33d87402e17… / eaa27086a65c… / 146c64f3fc52… / 9f8f5f2cd955… /
    /// a42bd88ac488… / d739f8d83bed… / b1723b879b59… / 77220dace263… (and fra aae9c8a6b484…
    /// cid 45 → 46 → 84 → 85 / gru e962f4a49508… cid 46 → 85 / gru 3f4dc73e62f2… cid 45 →
    /// 84 → 44 → 54 / gru 5990e53d2fde… cid 44 → 83 / fra b8e719ba13ca… cid:44 / gru
    /// 6d84bda1e560… cid 43 → 82 / fra 67d134aeab25… cid 43 → 38 at the adjacent wall-clock
    /// 18:46:02Z / 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:47:02Z /
    /// 18:47:03Z / 18:47:05Z / 18:47:06Z / 18:47:07Z steps) after bare product-NATS
    /// RestartAsync;
    /// fingerprint 02525de8dfa3… / sfo-product-nats CN=sfo-platform cid 47 → 86 → 39 at
    /// 18:46:09Z on 127.0.0.1:36278, 18:47:09Z on 127.0.0.1:46582, and 18:50:09Z on
    /// 127.0.0.1:45784 against the same a914ebca… leaf — three-occurrence sparse
    /// post-recycle reconnect twin of ef71b6e32493… / b439248687d8… / c907c56a7c0c… /
    /// eacb3282ca0c… / bf521ed338de… / 9b960cc93f83… / 26b95f54769c… / 16f64e5cf6e5… /
    /// e33d87402e17… / eaa27086a65c… / 146c64f3fc52… / 9f8f5f2cd955… / a42bd88ac488… /
    /// d739f8d83bed… / b1723b879b59… / 77220dace263… (and fra a66e03d58e6a… cid 47 → 86 →
    /// 39 / gru 6be7ec00050d… cid 48 → 87 / gru 0401b56675fd… cid 47 → 86 / gru
    /// e962f4a49508… cid 46 → 85 / gru 3f4dc73e62f2… cid 45 → 84 → 44 → 54 / gru
    /// 5990e53d2fde… cid 44 → 83 / fra aae9c8a6b484… dual cid 45+46 → 84+85 / fra
    /// b8e719ba13ca… cid:44 / fra 67d134aeab25… cid 43 → 38 at the adjacent wall-clock
    /// 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z / 18:46:09Z /
    /// 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z / 18:47:08Z / 18:47:09Z /
    /// 18:50:09Z steps) after bare product-NATS RestartAsync;
    /// fingerprint 67300e8b3fe0… / sfo-product-nats CN=sfo-platform cid 48 → 87 at
    /// 18:46:11Z on 127.0.0.1:36290 and 18:47:11Z on 127.0.0.1:46596 against the same
    /// a914ebca… leaf — two-occurrence post-recycle reconnect twin of 02525de8dfa3… /
    /// ef71b6e32493… / b439248687d8… / c907c56a7c0c… / eacb3282ca0c… / bf521ed338de… /
    /// 9b960cc93f83… / 26b95f54769c… / 16f64e5cf6e5… / e33d87402e17… / eaa27086a65c… /
    /// 146c64f3fc52… / 9f8f5f2cd955… / a42bd88ac488… / d739f8d83bed… / b1723b879b59… /
    /// 77220dace263… (and fra a87539b37de1… cid 48 → 87 / gru 8a0aaf8cb1da… cid 49 → 88 →
    /// 45 → 55 / fra a66e03d58e6a… cid 47 → 86 → 39 / gru 6be7ec00050d… cid 48 → 87 / gru
    /// 0401b56675fd… cid 47 → 86 / gru e962f4a49508… cid 46 → 85 / gru 3f4dc73e62f2… cid
    /// 45 → 84 → 44 → 54 / gru 5990e53d2fde… cid 44 → 83 / fra aae9c8a6b484… dual cid
    /// 45+46 → 84+85 / fra b8e719ba13ca… cid:44 / fra 67d134aeab25… cid 43 → 38 at the
    /// adjacent wall-clock 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z /
    /// 18:46:08Z / 18:46:09Z / 18:46:10Z / 18:46:11Z / 18:47:03Z / 18:47:04Z / 18:47:05Z /
    /// 18:47:06Z / 18:47:07Z / 18:47:08Z / 18:47:09Z / 18:47:10Z / 18:47:11Z / 18:50:09Z
    /// steps) after bare product-NATS RestartAsync;
    /// fingerprint e583d837318a… / sfo-product-nats CN=sfo-platform cid 49 → 50 → 88 → 89 at
    /// 18:46:13Z on 127.0.0.1:36302 / 127.0.0.1:36324 (dual cid 49+50) and 18:47:13Z on
    /// 127.0.0.1:46602 / 127.0.0.1:46614 (dual cid 88+89) against the same a914ebca… leaf —
    /// four-occurrence dual-cid post-recycle reconnect twin of 67300e8b3fe0… /
    /// 02525de8dfa3… / ef71b6e32493… / b439248687d8… / c907c56a7c0c… / eacb3282ca0c… /
    /// bf521ed338de… / 9b960cc93f83… / 26b95f54769c… / 16f64e5cf6e5… / e33d87402e17… /
    /// eaa27086a65c… / 146c64f3fc52… / 9f8f5f2cd955… / a42bd88ac488… / d739f8d83bed… /
    /// b1723b879b59… / 77220dace263… (and fra d86f81358e32… cid 49 → 50 → 88 → 89 / fra
    /// a87539b37de1… cid 48 → 87 / gru 897b9ff7b37e… cid 50 → 89 / gru 8a0aaf8cb1da… cid
    /// 49 → 88 → 45 → 55 / fra a66e03d58e6a… cid 47 → 86 → 39 / gru 6be7ec00050d… cid 48 →
    /// 87 / gru 0401b56675fd… cid 47 → 86 / gru e962f4a49508… cid 46 → 85 / gru 3f4dc73e62f2…
    /// cid 45 → 84 → 44 → 54 / gru 5990e53d2fde… cid 44 → 83 / fra aae9c8a6b484… dual cid
    /// 45+46 → 84+85 / fra b8e719ba13ca… cid:44 / fra 67d134aeab25… cid 43 → 38 at the
    /// adjacent wall-clock 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z /
    /// 18:46:08Z / 18:46:09Z / 18:46:10Z / 18:46:11Z / 18:46:12Z / 18:46:13Z / 18:47:03Z /
    /// 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z / 18:47:08Z / 18:47:09Z / 18:47:10Z /
    /// 18:47:11Z / 18:47:12Z / 18:47:13Z / 18:50:09Z steps) after bare product-NATS
    /// RestartAsync;
    /// fingerprint e7810573222a… / sfo-product-nats CN=sfo-platform cid 51 → 90 → 46 → 40 at
    /// 18:46:15Z on 127.0.0.1:59838, 18:47:15Z on 127.0.0.1:55568, 18:48:15Z on
    /// 127.0.0.1:35124, and 18:50:15Z on 127.0.0.1:42264 against the same a914ebca… leaf —
    /// four-occurrence sparse post-recycle reconnect twin of e583d837318a… /
    /// 67300e8b3fe0… / 02525de8dfa3… / ef71b6e32493… / b439248687d8… / c907c56a7c0c… /
    /// eacb3282ca0c… / bf521ed338de… / 9b960cc93f83… / 26b95f54769c… / 16f64e5cf6e5… /
    /// e33d87402e17… / eaa27086a65c… / 146c64f3fc52… / 9f8f5f2cd955… / a42bd88ac488… /
    /// d739f8d83bed… / b1723b879b59… / 77220dace263… (and fra bf210e609e7f… cid 51 → 90 →
    /// 47 → 40 / gru f106e39e815f… cid 52 → 91 / gru 88ff8c404d3b… cid 51 → 90 / fra
    /// d86f81358e32… cid 49 → 50 → 88 → 89 / gru 897b9ff7b37e… cid 50 → 89 / gru
    /// 8a0aaf8cb1da… cid 49 → 88 → 45 → 55 / fra a87539b37de1… cid 48 → 87 / fra
    /// a66e03d58e6a… cid 47 → 86 → 39 / gru 6be7ec00050d… cid 48 → 87 / gru 0401b56675fd…
    /// cid 47 → 86 / gru e962f4a49508… cid 46 → 85 / gru 3f4dc73e62f2… cid 45 → 84 → 44 →
    /// 54 / gru 5990e53d2fde… cid 44 → 83 / fra aae9c8a6b484… dual cid 45+46 → 84+85 / fra
    /// b8e719ba13ca… cid:44 / fra 67d134aeab25… cid 43 → 38 at the adjacent wall-clock
    /// 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z /
    /// 18:46:09Z / 18:46:10Z / 18:46:11Z / 18:46:12Z / 18:46:13Z / 18:46:14Z /
    /// 18:46:15Z / 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z /
    /// 18:47:08Z / 18:47:09Z / 18:47:10Z / 18:47:11Z / 18:47:12Z / 18:47:13Z /
    /// 18:47:14Z / 18:47:15Z / 18:48:10Z / 18:48:15Z / 18:49:10Z / 18:50:09Z /
    /// 18:50:15Z steps) after bare product-NATS RestartAsync;
    /// fingerprint e7adbe3390eb… / sfo-product-nats CN=sfo-platform cid 52 → 91 at
    /// 18:46:17Z on 127.0.0.1:59852 and 18:47:17Z on 127.0.0.1:55584 against the same
    /// a914ebca… leaf — two-occurrence post-recycle reconnect twin of e7810573222a… /
    /// e583d837318a… / 67300e8b3fe0… / 02525de8dfa3… / ef71b6e32493… / b439248687d8… /
    /// c907c56a7c0c… / eacb3282ca0c… / bf521ed338de… / 9b960cc93f83… / 26b95f54769c… /
    /// 16f64e5cf6e5… / e33d87402e17… / eaa27086a65c… / 146c64f3fc52… / 9f8f5f2cd955… /
    /// a42bd88ac488… / d739f8d83bed… / b1723b879b59… / 77220dace263… (and fra
    /// ec156a1db321… cid 52 → 91 / gru d0feba5039c6… cid:53 / fra bf210e609e7f… cid 51 →
    /// 90 → 47 → 40 / gru f106e39e815f… cid 52 → 91 / gru 88ff8c404d3b… cid 51 → 90 / fra
    /// d86f81358e32… cid 49 → 50 → 88 → 89 / gru 897b9ff7b37e… cid 50 → 89 / gru
    /// 8a0aaf8cb1da… cid 49 → 88 → 45 → 55 / fra a87539b37de1… cid 48 → 87 / fra
    /// a66e03d58e6a… cid 47 → 86 → 39 / gru 6be7ec00050d… cid 48 → 87 / gru 0401b56675fd…
    /// cid 47 → 86 / gru e962f4a49508… cid 46 → 85 / gru 3f4dc73e62f2… cid 45 → 84 → 44 →
    /// 54 / gru 5990e53d2fde… cid 44 → 83 / fra aae9c8a6b484… dual cid 45+46 → 84+85 / fra
    /// b8e719ba13ca… cid:44 / fra 67d134aeab25… cid 43 → 38 at the adjacent wall-clock
    /// 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z /
    /// 18:46:09Z / 18:46:10Z / 18:46:11Z / 18:46:12Z / 18:46:13Z / 18:46:14Z /
    /// 18:46:15Z / 18:46:17Z / 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z /
    /// 18:47:07Z / 18:47:08Z / 18:47:09Z / 18:47:10Z / 18:47:11Z / 18:47:12Z /
    /// 18:47:13Z / 18:47:14Z / 18:47:15Z / 18:47:17Z / 18:48:10Z / 18:48:15Z /
    /// 18:49:10Z / 18:50:09Z / 18:50:15Z steps) after bare product-NATS RestartAsync;
    /// fingerprint 1668f8c0e10f… / sfo-product-nats CN=sfo-platform cid 53 → 54 → 92 → 93 → 31
    /// at 18:46:19Z on 127.0.0.1:59860 and 127.0.0.1:59878, 18:47:19Z on 127.0.0.1:55608
    /// and 127.0.0.1:55624, and 18:49:19Z on 127.0.0.1:56818 against the same a914ebca…
    /// leaf — five-occurrence post-recycle reconnect twin of e7adbe3390eb… /
    /// e7810573222a… / e583d837318a… / 67300e8b3fe0… / 02525de8dfa3… / ef71b6e32493… /
    /// b439248687d8… / c907c56a7c0c… / eacb3282ca0c… / bf521ed338de… / 9b960cc93f83… /
    /// 26b95f54769c… / 16f64e5cf6e5… / e33d87402e17… / eaa27086a65c… / 146c64f3fc52… /
    /// 9f8f5f2cd955… / a42bd88ac488… / d739f8d83bed… / b1723b879b59… / 77220dace263… (and
    /// fra 59a0656971a4… cid 53 → 54 → 92 → 93 → 31 / fra ec156a1db321… cid 52 → 91 / gru
    /// 1f9106a25f41… cid 54 → 55 → 94 → 31 / gru d0feba5039c6… cid:53 / fra bf210e609e7f…
    /// cid 51 → 90 → 47 → 40 / gru f106e39e815f… cid 52 → 91 / gru 88ff8c404d3b… cid 51 →
    /// 90 / fra d86f81358e32… cid 49 → 50 → 88 → 89 / gru 897b9ff7b37e… cid 50 → 89 / gru
    /// 8a0aaf8cb1da… cid 49 → 88 → 45 → 55 / fra a87539b37de1… cid 48 → 87 / fra
    /// a66e03d58e6a… cid 47 → 86 → 39 / gru 6be7ec00050d… cid 48 → 87 / gru 0401b56675fd…
    /// cid 47 → 86 / gru e962f4a49508… cid 46 → 85 / gru 3f4dc73e62f2… cid 45 → 84 → 44 →
    /// 54 / gru 5990e53d2fde… cid 44 → 83 / fra aae9c8a6b484… dual cid 45+46 → 84+85 / fra
    /// b8e719ba13ca… cid:44 / fra 67d134aeab25… cid 43 → 38 at the adjacent wall-clock
    /// 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z /
    /// 18:46:09Z / 18:46:10Z / 18:46:11Z / 18:46:12Z / 18:46:13Z / 18:46:14Z /
    /// 18:46:15Z / 18:46:17Z / 18:46:19Z / 18:47:03Z / 18:47:04Z / 18:47:05Z /
    /// 18:47:06Z / 18:47:07Z / 18:47:08Z / 18:47:09Z / 18:47:10Z / 18:47:11Z /
    /// 18:47:12Z / 18:47:13Z / 18:47:14Z / 18:47:15Z / 18:47:17Z / 18:47:19Z /
    /// 18:48:10Z / 18:48:15Z / 18:49:10Z / 18:49:19Z / 18:50:09Z / 18:50:15Z steps)
    /// after bare product-NATS RestartAsync;
    /// fingerprint 230da24f64b6… / sfo-product-nats CN=sfo-platform cid 55 → 94 → 47 → 41 at
    /// 18:46:21Z on 127.0.0.1:59888, 18:47:21Z on 127.0.0.1:55626, 18:48:21Z on
    /// 127.0.0.1:35130, and 18:50:21Z on 127.0.0.1:42286 against the same a914ebca…
    /// leaf — four-occurrence post-recycle reconnect twin of 1668f8c0e10f… /
    /// e7adbe3390eb… / e7810573222a… / e583d837318a… / 67300e8b3fe0… / 02525de8dfa3… /
    /// ef71b6e32493… / b439248687d8… / c907c56a7c0c… / eacb3282ca0c… / bf521ed338de… /
    /// 9b960cc93f83… / 26b95f54769c… / 16f64e5cf6e5… / e33d87402e17… / eaa27086a65c… /
    /// 146c64f3fc52… / 9f8f5f2cd955… / a42bd88ac488… / d739f8d83bed… / b1723b879b59… /
    /// 77220dace263… (and fra 8e310ea4f277… cid 55 → 94 → 48 → 41 / gru 7dae08a6f4b3…
    /// cid 56 → 47 → 41 / fra 59a0656971a4… cid 53 → 54 → 92 → 93 → 31 / fra
    /// ec156a1db321… cid 52 → 91 / gru 1f9106a25f41… cid 54 → 55 → 94 → 31 / gru
    /// d0feba5039c6… cid:53 / fra bf210e609e7f… cid 51 → 90 → 47 → 40 / gru f106e39e815f…
    /// cid 52 → 91 / gru 88ff8c404d3b… cid 51 → 90 / fra d86f81358e32… cid 49 → 50 → 88 →
    /// 89 / gru 897b9ff7b37e… cid 50 → 89 / gru 8a0aaf8cb1da… cid 49 → 88 → 45 → 55 / fra
    /// a87539b37de1… cid 48 → 87 / fra a66e03d58e6a… cid 47 → 86 → 39 / gru 6be7ec00050d…
    /// cid 48 → 87 / gru 0401b56675fd… cid 47 → 86 / gru e962f4a49508… cid 46 → 85 / gru
    /// 3f4dc73e62f2… cid 45 → 84 → 44 → 54 / gru 5990e53d2fde… cid 44 → 83 / fra
    /// aae9c8a6b484… dual cid 45+46 → 84+85 / fra b8e719ba13ca… cid:44 / fra
    /// 67d134aeab25… cid 43 → 38 at the adjacent wall-clock 18:46:03Z / 18:46:04Z /
    /// 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z / 18:46:09Z / 18:46:10Z /
    /// 18:46:11Z / 18:46:12Z / 18:46:13Z / 18:46:14Z / 18:46:15Z / 18:46:17Z /
    /// 18:46:19Z / 18:46:21Z / 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z /
    /// 18:47:07Z / 18:47:08Z / 18:47:09Z / 18:47:10Z / 18:47:11Z / 18:47:12Z /
    /// 18:47:13Z / 18:47:14Z / 18:47:15Z / 18:47:17Z / 18:47:19Z / 18:47:21Z /
    /// 18:48:10Z / 18:48:15Z / 18:48:21Z / 18:49:10Z / 18:49:19Z / 18:50:09Z /
    /// 18:50:15Z / 18:50:21Z steps; two seconds after 1668f8c0e10f… cid 53 → 54 → 92 →
    /// 93 → 31 on adjacent :19 steps / ports 59860/59878 → 59888 and 55608/55624 →
    /// 55626; same wall-clock :21 as fra 8e310ea4f277… / gru 7dae08a6f4b3…) after bare
    /// product-NATS RestartAsync;
    /// fingerprint db61915863fe… / sfo-product-nats CN=sfo-platform cid 56 → 95 at
    /// 18:46:24Z on 127.0.0.1:59904 and 18:47:24Z on 127.0.0.1:55638 against the same
    /// a914ebca… leaf — two-occurrence post-recycle reconnect twin of 230da24f64b6… /
    /// 1668f8c0e10f… / e7adbe3390eb… / e7810573222a… / e583d837318a… / 67300e8b3fe0… /
    /// 02525de8dfa3… / ef71b6e32493… / b439248687d8… / c907c56a7c0c… / eacb3282ca0c… /
    /// bf521ed338de… / 9b960cc93f83… / 26b95f54769c… / 16f64e5cf6e5… / e33d87402e17… /
    /// eaa27086a65c… / 146c64f3fc52… / 9f8f5f2cd955… / a42bd88ac488… / d739f8d83bed… /
    /// b1723b879b59… / 77220dace263… (and gru d22a1e331a57… cid 57 → 96 / gru
    /// 7dae08a6f4b3… cid 56 → 47 → 41 / fra 8e310ea4f277… cid 55 → 94 → 48 → 41 / fra
    /// 59a0656971a4… cid 53 → 54 → 92 → 93 → 31 / gru 1f9106a25f41… cid 54 → 55 → 94 →
    /// 31 at the adjacent wall-clock 18:46:19Z / 18:46:21Z / 18:46:23Z / 18:46:24Z /
    /// 18:47:19Z / 18:47:21Z / 18:47:23Z / 18:47:24Z steps; three seconds after
    /// 230da24f64b6… cid 55 → 94 → 47 → 41 on adjacent :21 steps / ports 59888 → 59904
    /// and 55626 → 55638; five seconds after 1668f8c0e10f… cid 53 → 54 → 92 → 93 → 31 on
    /// :19 steps / ports 59860/59878 → 59904) after bare product-NATS RestartAsync).
    /// Cell-agnostic: every control-plane client in the NATS resource's cell is surveyed so
    /// gru/sfo/fra controller-only or operator-read expiry cannot fall through to bare NATS
    /// recycle; product plane surveys every product client (platforms) the same way.
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
    /// Control/product NATS and controllers must force remint on persistent unhealth even
    /// when the probe detail is only the outer NATS.Net text
    /// <c>can not start to connect nats server: nats://…</c> (fingerprint c05d3fee208c… /
    /// gru-control-nats-1 three bare restarts on :18600; fingerprint b0ca5ad6b00f… /
    /// sfo-control-nats-1 three bare restarts on :18800; fingerprint 1e57af750edb… /
    /// fra-control-nats-1 three bare restarts on :19000; fingerprint 2c66150c157c… /
    /// gru-product-nats-1 three bare restarts on :18620; fingerprint 666f072201a5… /
    /// sfo-product-nats-1 three bare restarts on :18820; fingerprint 6da1925a9038… /
    /// fra-product-nats-1 three bare restarts on :19020; fingerprint 7bead2653aa7… /
    /// gru-controller-1 three bare restarts with the same outer text on :18600; fingerprint
    /// bfa083ed37ee… / sfo-controller-1 three bare restarts with the same outer text on
    /// :18800; fingerprint e1c5c64cbb9d… / fra-controller-1 three bare restarts with the
    /// same outer text on :19000; every cell's controller twins). Bare RestartAsync of a
    /// single NATS member or controller reloads the same PEMs and does not WaitReadyAsync
    /// for dependents, producing multi-minute thrash. Platforms keep HTTP bare-restart for
    /// non-TLS app failures; their product-leaf expiry is already covered by
    /// <see cref="ResourceHasInvalidTlsLeaf"/>.
    /// </summary>
    internal static bool RequiresForceRemintOnPersistentUnhealth(
        DevelopmentTopology topology,
        string resourceName)
    {
        var resource = FindResource(topology, resourceName);
        return resource?.Kind is DevelopmentResourceKind.ControlNats
            or DevelopmentResourceKind.ProductNats
            or DevelopmentResourceKind.ControllerAgent;
    }

    /// <summary>
    /// Every client leaf that would re-handshake against <paramref name="resourceName"/> after a
    /// bare RestartAsync, plus the resource's own client leaf when it is a controller/platform,
    /// plus the NATS server's client-facing and route leaves so an expired server PEM alone
    /// still force-remints (plain connect failures otherwise look non-cert shaped —
    /// c05d3fee208c… / b0ca5ad6b00f… / 1e57af750edb… control, 2c66150c157c… /
    /// 666f072201a5… / 6da1925a9038… product, 7bead2653aa7… / bfa083ed37ee… /
    /// e1c5c64cbb9d… controller).
    /// Control NATS includes operator-read and every controller in the cell so an expired
    /// CN=*-controller-1 leaf (sfo f490b625… and denser twin 9815ef5a… and two-occurrence
    /// post-recycle twins 4eeeee0520a1… / e8e55fe0bef9… and three-occurrence post-recycle
    /// twin 412baaa56842… and four-occurrence post-recycle twins 71cf8514f4d6… /
    /// ce40d219dc90… and five-occurrence post-recycle twins fc867739e2e2… / 3db5efff618c…
    /// and three-occurrence post-recycle twin c9f4a06686ba… and three-occurrence
    /// post-recycle twin a5ee4c55235d… and three-occurrence post-recycle twin
    /// 914b99d5fbc6… and two-occurrence post-recycle twin 53b4362b4444… and
    /// three-occurrence post-recycle twin bbdb6e0d6006… and three-occurrence
    /// post-recycle twin 1cdbb448aebb… and four-occurrence post-recycle twin
    /// 2e80728c5df4… and three-occurrence post-recycle twin 306f7d4a6890…, gru
    /// c2bf6b539a62… and denser twin
    /// 782d6308… and two-occurrence post-recycle twin 003657d51ecd… and four-occurrence
    /// post-recycle twin b9dc4dd1a8ef… and six-occurrence post-recycle twin 7b6a047263d8…
    /// and five-occurrence post-recycle twin 87f7f1566c88… and three-occurrence
    /// post-recycle twin a9bf884a363b… and four-occurrence post-recycle twin 25b92b919c66…
    /// and two-occurrence post-recycle twin 34c89dedb769… and four-occurrence post-recycle
    /// twin 024cbd22bdf4… and two-occurrence post-recycle twin e7ad7a71e395… and
    /// seven-occurrence post-recycle twin 96fe8dda09bb… and three-occurrence
    /// post-recycle twin d2538c612184… and seven-occurrence post-recycle twin
    /// d00ef05a1026… and three-occurrence post-recycle twin d56bf3307e7b… and
    /// four-occurrence post-recycle twin e51d12dd4525… and six-occurrence
    /// post-recycle twin 73ac000434f0… and two-occurrence post-recycle twin
    /// 1455d09f7030…,
    /// fra 91b5b852… and denser twin
    /// ffcef075c58c… and four-occurrence post-recycle twin bca21682b315… and single
    /// post-recycle twin 23eafce842f6… and two-occurrence post-recycle twins
    /// 4046b92fa615… / 5e5b835252fe… and seven-occurrence post-recycle twin
    /// 87c737a0ed10… and four-occurrence post-recycle twin 6e08a77cd4b6… and
    /// two-occurrence post-recycle twin 876de6711801… and three-occurrence
    /// post-recycle twin 52a227218acf… and five-occurrence post-recycle twin
    /// 88eec19ebb94… and three-occurrence post-recycle twin 49ec50da2e2a… and
    /// four-occurrence post-recycle twin 7063631384a4… and three-occurrence
    /// post-recycle twin d7de94966c92… and three-occurrence post-recycle twin
    /// 4cab25065be5… and two-occurrence post-recycle twin 4aa0ebad5b5b…) alone still
    /// forces remint instead of NATS recycle. Product NATS surveys every platform client
    /// plus product server Client/Route leaves the same way. Controllers survey their own
    /// leaf plus every control-NATS server Client/Route leaf in the cell so an expired
    /// server PEM alone (fingerprint 7bead2653aa7… / bfa083ed37ee… / e1c5c64cbb9d… outer
    /// connect text on the controller health probe) cannot fall through to bare controller
    /// RestartAsync.
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
                if (cellSecurity.Tls.Control.Servers.TryGetValue(resource.Name, out var controlServer))
                {
                    yield return controlServer.Client;
                    yield return controlServer.Route;
                }
                yield break;
            case DevelopmentResourceKind.ProductNats:
                foreach (var client in cellSecurity.Tls.Product.Clients.Values)
                {
                    yield return client;
                }
                if (cellSecurity.Tls.Product.Servers.TryGetValue(resource.Name, out var productServer))
                {
                    yield return productServer.Client;
                    yield return productServer.Route;
                }
                yield break;
            case DevelopmentResourceKind.ControllerAgent:
                yield return cellSecurity.Tls.Control.Clients[resource.Name];
                // Controller health probes ConnectAsync to control NATS. An expired server
                // PEM alone yields the outer "can not start to connect nats server" text
                // (fingerprint 7bead2653aa7… / bfa083ed37ee… / e1c5c64cbb9d…) while the
                // controller leaf is still valid.
                foreach (var server in cellSecurity.Tls.Control.Servers.Values)
                {
                    yield return server.Client;
                    yield return server.Route;
                }
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
