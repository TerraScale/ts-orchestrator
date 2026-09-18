using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NATS.Client.KeyValueStore;
using NATS.Client.Core;
using NATS.Net;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Runtime;
using HostRole = TerraScale.Orchestrator.Runtime.AdmittedRole;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Leaderless host convergence against a real NATS server: desired digest in, verified
/// artifact installed, systemd plan converged, observation reported — with rollback on a
/// failed post-converge observation and replace-lease serialization for stateful roles.
/// </summary>
public sealed class HostConvergenceRuntimeTests
{
    [Test]
    public async Task ConvergesDesiredDigestInstallsVerifiedArtifactAndReportsObservation()
    {
        await using var server = await ConvergenceNatsServer.StartAsync();
        var (delivery, runtimeStore, client) = server.Stores();
        var installRoot = Path.Combine(server.Directory, "artifacts");
        var artifact = Encoding.UTF8.GetBytes("terrabase-binary-v2");
        var hex = Convert.ToHexStringLower(SHA256.HashData(artifact));
        await server.PutDesiredDigest("terrabase-server", "production", "gru", $"sha256:{hex}");

        var converger = new FakeConverger();
        await using var convergence = StartConvergence(
            delivery, runtimeStore, client, installRoot,
            source: new MemoryArtifactSource(("sha256-" + hex, artifact)), converger: converger);

        await convergence.ReconcileOnceAsync(
            HostRole.TerraBaseMember, AdmittedRoleCatalog.Get(HostRole.TerraBaseMember), CancellationToken.None);

        var installed = Path.Combine(installRoot, "terrabase-server", $"sha256-{hex}", "terrabase-server");
        await Assert.That(await File.ReadAllBytesAsync(installed)).IsEquivalentTo(artifact);
        await Assert.That(converger.ConvergedPlans.Count).IsEqualTo(1);
        await Assert.That(converger.ConvergedPlans[0].Systemd!.Executable).IsEqualTo(installed);
        await Assert.That(converger.ConvergedPlans[0].ArtifactDigest!.Value).IsEqualTo(hex);

        var observation = await ReadObservationAsync(runtimeStore, "terrabase-server");
        await Assert.That(observation!.State).IsEqualTo("converged");
        await Assert.That(observation.Digest).IsEqualTo($"sha256:{hex}");
        var marker = JsonSerializer.Deserialize<JsonElement>(
            await File.ReadAllTextAsync(Path.Combine(installRoot, "terrabase-server", "current.json")));
        await Assert.That(marker.GetProperty("digest").GetString()).IsEqualTo($"sha256:{hex}");
    }

    [Test]
    public async Task SameDigestWhileServingReconcilesToNoOp()
    {
        await using var server = await ConvergenceNatsServer.StartAsync();
        var (delivery, runtimeStore, client) = server.Stores();
        var installRoot = Path.Combine(server.Directory, "artifacts");
        var artifact = Encoding.UTF8.GetBytes("same-binary");
        var hex = Convert.ToHexStringLower(SHA256.HashData(artifact));
        await server.PutDesiredDigest("terrabase-server", "production", "gru", $"sha256:{hex}");

        var converger = new FakeConverger();
        await using var convergence = StartConvergence(
            delivery, runtimeStore, client, installRoot,
            source: new MemoryArtifactSource(("sha256-" + hex, artifact)), converger: converger);
        await convergence.ReconcileOnceAsync(
            HostRole.TerraBaseMember, AdmittedRoleCatalog.Get(HostRole.TerraBaseMember), CancellationToken.None);
        var converged = converger.ConvergedPlans.Count;
        await Assert.That(converged).IsGreaterThan(0);

        await convergence.ReconcileOnceAsync(
            HostRole.TerraBaseMember, AdmittedRoleCatalog.Get(HostRole.TerraBaseMember), CancellationToken.None);

        await Assert.That(converger.ConvergedPlans.Count).IsEqualTo(converged);
    }

    [Test]
    public async Task FailedObservationAfterReplacementRollsBackToTheExactPreviousDigest()
    {
        await using var server = await ConvergenceNatsServer.StartAsync();
        var (delivery, runtimeStore, client) = server.Stores();
        var installRoot = Path.Combine(server.Directory, "artifacts");
        var good = Encoding.UTF8.GetBytes("known-good-binary");
        var broken = Encoding.UTF8.GetBytes("crash-looping-binary");
        var goodHex = Convert.ToHexStringLower(SHA256.HashData(good));
        var brokenHex = Convert.ToHexStringLower(SHA256.HashData(broken));
        var source = new MemoryArtifactSource(
            ("sha256-" + goodHex, good),
            ("sha256-" + brokenHex, broken));

        await server.PutDesiredDigest("terrabase-server", "production", "gru", $"sha256:{goodHex}");
        var converger = new FakeConverger();
        await using var convergence = StartConvergence(
            delivery, runtimeStore, client, installRoot, source, converger);
        await convergence.ReconcileOnceAsync(
            HostRole.TerraBaseMember, AdmittedRoleCatalog.Get(HostRole.TerraBaseMember), CancellationToken.None);
        await Assert.That(converger.ConvergedPlans.Single().ArtifactDigest!.Value).IsEqualTo(goodHex);

        converger.FailWhenRunning(brokenHex);
        await server.PutDesiredDigest("terrabase-server", "production", "gru", $"sha256:{brokenHex}");
        await convergence.ReconcileOnceAsync(
            HostRole.TerraBaseMember, AdmittedRoleCatalog.Get(HostRole.TerraBaseMember), CancellationToken.None);

        var observation = await ReadObservationAsync(runtimeStore, "terrabase-server");
        await Assert.That(observation!.State).IsEqualTo("rolled-back");
        await Assert.That(observation.Digest).IsEqualTo($"sha256:{goodHex}");
        // The final converged plan is the restored previous version, never the broken one.
        await Assert.That(converger.ConvergedPlans.Last().ArtifactDigest!.Value).IsEqualTo(goodHex);
    }

    [Test]
    public async Task CorruptedArtifactFailsClosedWithoutTouchingTheRunningVersion()
    {
        await using var server = await ConvergenceNatsServer.StartAsync();
        var (delivery, runtimeStore, client) = server.Stores();
        var installRoot = Path.Combine(server.Directory, "artifacts");
        var good = Encoding.UTF8.GetBytes("still-running");
        var tampered = Encoding.UTF8.GetBytes("tampered-bytes");
        var goodHex = Convert.ToHexStringLower(SHA256.HashData(good));
        var tamperedHex = Convert.ToHexStringLower(SHA256.HashData(tampered));
        await server.PutDesiredDigest("terrabase-server", "production", "gru", $"sha256:{goodHex}");
        var converger = new FakeConverger();
        await using var first = StartConvergence(
            delivery, runtimeStore, client, installRoot,
            source: new MemoryArtifactSource(("sha256-" + goodHex, good)), converger: converger);
        await first.ReconcileOnceAsync(
            HostRole.TerraBaseMember, AdmittedRoleCatalog.Get(HostRole.TerraBaseMember), CancellationToken.None);

        // The store object named for the desired digest returns different bytes.
        await server.PutDesiredDigest("terrabase-server", "production", "gru", $"sha256:{tamperedHex}");
        await using var second = StartConvergence(
            delivery, runtimeStore, client, installRoot,
            source: new MemoryArtifactSource(("sha256-" + tamperedHex, good), ("sha256-" + goodHex, good)),
            converger: converger);
        await second.ReconcileOnceAsync(
            HostRole.TerraBaseMember, AdmittedRoleCatalog.Get(HostRole.TerraBaseMember), CancellationToken.None);

        // The host stays on the exact previous digest and never executes unverified bytes.
        var observation = await ReadObservationAsync(runtimeStore, "terrabase-server");
        await Assert.That(observation!.Digest).IsEqualTo($"sha256:{goodHex}");
        await Assert.That(
            File.Exists(Path.Combine(installRoot, "terrabase-server", $"sha256-{tamperedHex}", "terrabase-server")))
            .IsFalse();
        await Assert.That(converger.ConvergedPlans.All(plan =>
            plan.ArtifactDigest!.Value != tamperedHex)).IsTrue();
    }

    [Test]
    public async Task StatefulReplaceLeaseSerializesAndExpires()
    {
        await using var server = await ConvergenceNatsServer.StartAsync();
        var (_, runtimeStore, _) = server.Stores();
        var descriptor = AdmittedRoleCatalog.Get(HostRole.TerraBaseMember);
        var convergenceA = StartConvergence(server);
        var convergenceB = StartConvergence(server);

        var leaseA = await convergenceA.AcquireReplaceLeaseAsync(descriptor, CancellationToken.None);
        await Assert.That(leaseA).IsNotNull();
        var leaseB = await convergenceB.AcquireReplaceLeaseAsync(descriptor, CancellationToken.None);
        await Assert.That(leaseB).IsNull();

        await leaseA!.DisposeAsync();
        var leaseB2 = await convergenceB.AcquireReplaceLeaseAsync(descriptor, CancellationToken.None);
        await Assert.That(leaseB2).IsNotNull();
        await leaseB2!.DisposeAsync();
        await Assert.That(async () =>
        {
            var released = await runtimeStore.GetEntryAsync<string>("host.replace.terrabase-server");
            released.EnsureSuccess();
        }).Throws<Exception>();
    }

    private static HostConvergenceRuntime StartConvergence(ConvergenceNatsServer server) =>
        StartConvergence(server.Stores().Item1, server.Stores().Item2, server.Stores().Item3,
            Path.Combine(server.Directory, "artifacts"), new MemoryArtifactSource(), new FakeConverger());

    private static HostConvergenceRuntime StartConvergence(
        INatsKVStore delivery,
        INatsKVStore runtimeStore,
        NATS.Client.Core.INatsConnection connection,
        string installRoot,
        IHostArtifactSource source,
        IHostRuntimeConverger converger) =>
        HostConvergenceRuntime.Create(
            delivery,
            runtimeStore,
            connection,
            source,
            converger,
            new HostConvergenceConfiguration(
                [HostRole.TerraBaseMember],
                "production",
                installRoot,
                HostArchitecture.Arm64),
            "gru",
            "test-1",
            observationTimeout: TimeSpan.FromSeconds(3));

    internal static async Task<HostConvergenceObservation?> ReadObservationAsync(
        INatsKVStore runtimeStore,
        string artifactKey)
    {
        try
        {
            var entry = await runtimeStore.GetEntryAsync<string>($"host.test-1.{artifactKey}");
            entry.EnsureSuccess();
            return JsonSerializer.Deserialize<HostConvergenceObservation>(
                entry.Value!, HostConvergenceJsonContext.Default.HostConvergenceObservation);
        }
        catch (NatsKVException)
        {
            return null;
        }
    }

    private sealed class FakeConverger : IHostRuntimeConverger
    {
        private readonly List<HostRuntimePlan> plans = [];
        private string? failingHex;

        public IReadOnlyList<HostRuntimePlan> ConvergedPlans => plans;

        public void FailWhenRunning(string hex) => failingHex = hex;

        public Task ConvergeAsync(HostRuntimePlan plan, CancellationToken cancellationToken)
        {
            plans.Add(plan);
            return Task.CompletedTask;
        }

        public Task<SystemdAllocationObservation> ObserveAsync(
            HostRuntimePlan plan,
            CancellationToken cancellationToken)
        {
            var failed = failingHex is not null && plan.ArtifactDigest!.Value == failingHex;
            return Task.FromResult(new SystemdAllocationObservation(
                plan.Systemd!.UnitName,
                failed ? SystemdAllocationState.Failed : SystemdAllocationState.Running,
                failed ? null : 4242,
                failed ? "exit-code" : "success"));
        }
    }

    private sealed class MemoryArtifactSource(params (string Name, byte[] Bytes)[] objects) : IHostArtifactSource
    {
        private readonly Dictionary<string, byte[]> stored =
            objects.ToDictionary(static value => value.Name, static value => value.Bytes, StringComparer.Ordinal);

        public Task CopyIntoAsync(string objectName, Stream destination, CancellationToken cancellationToken)
        {
            if (!stored.TryGetValue(objectName, out var bytes))
                throw new NATS.Client.ObjectStore.NatsObjNotFoundException("object");
            destination.Write(bytes, 0, bytes.Length);
            return Task.CompletedTask;
        }
    }

    private sealed class ConvergenceNatsServer : IAsyncDisposable
    {
        private readonly LocalNatsServerLease.Handle lease;
        private Process? nats;
        private NatsClient? client;
        private NATS.Client.KeyValueStore.INatsKVStore? delivery;
        private NATS.Client.KeyValueStore.INatsKVStore? runtimeStore;

        private ConvergenceNatsServer(string directory, LocalNatsServerLease.Handle lease)
        {
            this.lease = lease;
            Directory = directory;
        }

        public string Directory { get; }

        public static async Task<ConvergenceNatsServer> StartAsync()
        {
            var lease = await LocalNatsServerLease.AcquireAsync();
            var directory = Path.Combine(Path.GetTempPath(), $"ts-orch-host-convergence-{Guid.NewGuid():N}");
            ConvergenceNatsServer? server = null;
            try
            {
                System.IO.Directory.CreateDirectory(directory);
                var listener = new TcpListener(IPAddress.Loopback, 0);
                listener.Start();
                var port = ((IPEndPoint)listener.LocalEndpoint).Port;
                listener.Stop();
                var configuration = Path.Combine(directory, "nats.conf");
                await File.WriteAllTextAsync(
                    configuration,
                    $"port: {port}\njetstream {{ store_dir: \"{Path.Combine(directory, "store")}\" }}\n");
                var containers = await ContainerizedNatsCluster.CreateAsync(directory, [port]);
                server = new ConvergenceNatsServer(directory, lease) { Containers = containers };
                server.nats = containers.Start(configuration);
                server.client = new NatsClient(new NatsOpts
                {
                    Url = $"nats://127.0.0.1:{port}",
                    ConnectTimeout = TimeSpan.FromSeconds(5),
                    RequestTimeout = TimeSpan.FromSeconds(5)
                });
                for (var attempt = 1; ; attempt++)
                {
                    try
                    {
                        await server.client.ConnectAsync();
                        break;
                    }
                    catch (NatsException) when (attempt < 20)
                    {
                        await Task.Delay(200);
                    }
                }
                await NatsOperationJournalProvisioner.ProvisionControllerTopologyAsync(
                    server.client, new NatsTopology("gru", 1, "test-1"), CancellationToken.None);
                var keyValue = server.client.CreateJetStreamContext().CreateKeyValueStoreContext();
                server.delivery = await keyValue.GetStoreAsync("ORCH_DELIVERY");
                server.runtimeStore = await keyValue.GetStoreAsync("ORCH_RUNTIME");
                return server;
            }
            catch
            {
                if (server is not null)
                    await server.DisposeAsync();
                else
                    await new LocalNatsServerLease.DirectoryCleanupOwner(directory, lease).DisposeAsync();
                throw;
            }
        }

        private ContainerizedNatsCluster? Containers { get; set; }

        public (INatsKVStore, INatsKVStore, NATS.Client.Core.INatsConnection) Stores()
        {
            if (delivery is null || runtimeStore is null || client is null)
                throw new InvalidOperationException("The convergence NATS server is not started.");
            return (delivery, runtimeStore, client.Connection);
        }

        public async Task PutDesiredDigest(string service, string environment, string region, string digest) =>
            await delivery!.PutAsync(
                DirectDeliveryTargetKey.For(service, environment, region),
                JsonSerializer.Serialize(new
                {
                    artifactDigest = digest,
                    manifestDigest = "sha256:" + new string('a', 64),
                    kind = "service"
                }));

        public async ValueTask DisposeAsync()
        {
            if (client is not null) await client.DisposeAsync();
            if (nats is not null && Containers is not null) await Containers.StopAsync(nats);
            if (Containers is not null) await Containers.DisposeAsync();
            await new LocalNatsServerLease.DirectoryCleanupOwner(Directory, lease).DisposeAsync();
        }
    }
}
