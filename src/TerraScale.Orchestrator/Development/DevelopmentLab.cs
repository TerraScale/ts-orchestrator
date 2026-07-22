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
                    // 18:45:56Z on 127.0.0.1:54410 and 18:49:56Z on 127.0.0.1:35762 against
                    // the same 4e40db2b… leaf; fingerprint e517701a… / sfo-control-nats multi-
                    // occurrence and denser twin f08d1c577176… cid 29239 → 33 → 65 → 72 and
                    // two-occurrence post-recycle twin 62860f83eeb6… cid 30 → 46 at
                    // 18:45:50Z on 127.0.0.1:50596 and 18:49:50Z on 127.0.0.1:34070 and
                    // second two-occurrence post-recycle twin 97d33257778a… cid 33 → 50 at
                    // 18:45:56Z on 127.0.0.1:52196 and 18:49:56Z on 127.0.0.1:36654 against
                    // the same aa00c1c3… leaf; fingerprint 9a811bb8… / fra-control-nats multi-
                    // occurrence and denser twin f95adc65… cid 29239 → 33 → 65 → 72 and
                    // two-occurrence post-recycle twin 7421834a4183… cid 30 → 46 at
                    // 18:45:50Z on 127.0.0.1:34654 and 18:49:50Z on 127.0.0.1:33762 and second
                    // two-occurrence post-recycle twin c74671d2c0e4… cid 33 → 49 at
                    // 18:45:56Z on 127.0.0.1:43890 and 18:49:56Z on 127.0.0.1:37146 against
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
                        // fingerprint f95adc65… / fra-control-nats four-occurrence twin
                        // cid 29239 → 33 → 65 → 72 at 18:45:40Z / 18:47:40Z / 18:48:40Z /
                        // 18:50:40Z against the same 6477b788… leaf, fingerprint
                        // 7421834a4183… / fra-control-nats two-occurrence post-recycle twin
                        // cid 30 → 46 at 18:45:50Z on 127.0.0.1:34654 and 18:49:50Z on
                        // 127.0.0.1:33762 against the same 6477b788… leaf, and fingerprint
                        // c74671d2c0e4… / fra-control-nats second two-occurrence
                        // post-recycle twin cid 33 → 49 at 18:45:56Z on 127.0.0.1:43890 and
                        // 18:49:56Z on 127.0.0.1:37146 against the same 6477b788… leaf).
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
                        // reloads the same expired operator-read PEM; cid 29237 → 63 → 68 for
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
                        // operator-read PEM; cid 29238 → 63 → 70 for
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
                        // reloads the same expired platform leaf).
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
    /// f95adc65… / 7421834a4183… after bare control-NATS RestartAsync).
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
    /// product-NATS RestartAsync).
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
    /// ce40d219dc90… and five-occurrence post-recycle twin fc867739e2e2…, gru
    /// c2bf6b539a62… and denser twin
    /// 782d6308… and two-occurrence post-recycle twin 003657d51ecd… and four-occurrence
    /// post-recycle twin b9dc4dd1a8ef… and six-occurrence post-recycle twin 7b6a047263d8…
    /// and five-occurrence post-recycle twin 87f7f1566c88… and three-occurrence
    /// post-recycle twin a9bf884a363b…,
    /// fra 91b5b852… and denser twin
    /// ffcef075c58c… and four-occurrence post-recycle twin bca21682b315… and single
    /// post-recycle twin 23eafce842f6… and two-occurrence post-recycle twins
    /// 4046b92fa615… / 5e5b835252fe… and seven-occurrence post-recycle twin
    /// 87c737a0ed10… and four-occurrence post-recycle twin 6e08a77cd4b6…) alone still
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
