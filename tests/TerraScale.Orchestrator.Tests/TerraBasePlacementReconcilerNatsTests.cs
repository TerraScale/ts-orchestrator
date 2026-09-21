using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using NATS.Client.Core;
using System.Text.Json;
using NATS.Client.KeyValueStore;
using NATS.Net;
using TerraScale.Orchestrator.ControlPlane.TerraBase;
using TerraScale.Orchestrator.Messaging;
using TUnit.Core;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// End-to-end placement reconciliation against a real containerized NATS: durable
/// intent in, one member action per tick out, through the scripted fake fleet.
/// </summary>
[NotInParallel(LocalNatsServerLease.SchedulingConstraint)]
public sealed class TerraBasePlacementReconcilerNatsTests
{
    [Test]
    public async Task ScaleUpConvergesTheFullFleetEndToEnd()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var server = await PlacementNatsServer.StartAsync();
        var fleet = new FakeMemberHostFleet();
        var authority = new PlacementAuthorityHolder();
        var reconciler = PlacementTestHarness.Reconciler(server, fleet, authority);

        await PlacementTestHarness.ApplyIntentAsync(server.Delivery, "prod-db", 1, "GRU", "SFO", "FRA");
        var status = await PlacementTestHarness.TickUntilAsync(
            () => reconciler.TickAsync(CancellationToken.None),
            result => result.State == PlacementTickObservation.StateIdle);

        await Assert.That(status.State).IsEqualTo(PlacementTickObservation.StateIdle);
        await Assert.That(fleet.Instances.Count).IsEqualTo(6);
        var members = await PlacementTestHarness.MemberStatesAsync(server.Delivery, "prod-db");
        await Assert.That(members.Count).IsEqualTo(6);
        await Assert.That(members.All(static member =>
            member.Stage == PlacementMemberStateDocument.StageServing)).IsTrue();
        foreach (var member in members)
        {
            var volume = await TerraBasePlacementReconciler.ReadVolumeAsync(
                server.Delivery, "prod-db", member.MemberId, CancellationToken.None);
            await Assert.That(volume!.Document.WriterEpoch).IsEqualTo(1UL);
            await Assert.That(volume.Document.Disposition)
                .IsEqualTo(PlacementVolumeStateDocument.RetainedStateful);
        }
        var observed = await PlacementTestHarness.ReadStatusAsync(server.Runtime);
        await Assert.That(observed!.Cell).IsEqualTo("gru");
    }

    [Test]
    public async Task Missing_volume_holds_healthy_member_without_fabricating_storage()
    {
        if (!OperatingSystem.IsLinux()) return;
        await using var server = await PlacementNatsServer.StartAsync();
        var fleet = new FakeMemberHostFleet();
        var authority = new PlacementAuthorityHolder();
        var reconciler = PlacementTestHarness.Reconciler(server, fleet, authority);
        await PlacementTestHarness.ApplyIntentAsync(server.Delivery, "prod-db", 1, "GRU");
        await PlacementTestHarness.TickUntilAsync(() => reconciler.TickAsync(CancellationToken.None), result => result.Action == "provision");
        var member = (await PlacementTestHarness.MemberStatesAsync(server.Delivery, "prod-db")).Single();
        fleet.SetVolume(member.InstanceId!, null);
        for (var tick = 0; tick < 3; tick++)
        {
            var held = await reconciler.TickAsync(CancellationToken.None);
            await Assert.That(held.State).IsEqualTo(PlacementTickObservation.StateHeld);
            await Assert.That(held.Error).IsEqualTo("provider-volume-missing-or-mismatched");
        }
        await Assert.That(await TerraBasePlacementReconciler.ReadVolumeAsync(
            server.Delivery, "prod-db", member.MemberId, CancellationToken.None)).IsNull();
        fleet.SetVolume(member.InstanceId!, "provider-data-volume-1");
        await Assert.That((await reconciler.TickAsync(CancellationToken.None)).Action).IsEqualTo("healthy");
        await Assert.That((await TerraBasePlacementReconciler.ReadVolumeAsync(
            server.Delivery, "prod-db", member.MemberId, CancellationToken.None))!.Document.ProviderVolumeId)
            .IsEqualTo("provider-data-volume-1");
    }

    [Test]
    public async Task Wrong_replacement_disk_never_overwrites_the_retained_volume_or_becomes_serving()
    {
        if (!OperatingSystem.IsLinux()) return;
        await using var server = await PlacementNatsServer.StartAsync();
        var fleet = new FakeMemberHostFleet();
        var authority = new PlacementAuthorityHolder();
        var reconciler = PlacementTestHarness.Reconciler(server, fleet, authority);
        await PlacementTestHarness.ConvergeAsync(server, fleet, authority, reconciler, "prod-db", 1, "GRU");
        fleet.RemoveHost(fleet.Instances.Single(instance => instance.EndsWith(".2")));
        await PlacementTestHarness.TickUntilAsync(() => reconciler.TickAsync(CancellationToken.None),
            result => result.Action == "provision" && result.Member == "elastic-gru");
        var member = (await PlacementTestHarness.MemberStatesAsync(server.Delivery, "prod-db"))
            .Single(candidate => candidate.MemberId == "elastic-gru");
        fleet.SetVolume(member.InstanceId!, "wrong-disk");
        var held = await reconciler.TickAsync(CancellationToken.None);
        await Assert.That(held.State).IsEqualTo(PlacementTickObservation.StateHeld);
        await Assert.That(held.Error).IsEqualTo("provider-volume-missing-or-mismatched");
        await Assert.That((await TerraBasePlacementReconciler.ReadVolumeAsync(
            server.Delivery, "prod-db", member.MemberId, CancellationToken.None))!.Document.ProviderVolumeId)
            .IsEqualTo("vol-elastic-gru");
    }

    [Test]
    public async Task ScaleDownRefusesOnLagThenCompletesOnCaughtUpEndToEnd()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var server = await PlacementNatsServer.StartAsync();
        var fleet = new FakeMemberHostFleet();
        var authority = new PlacementAuthorityHolder();
        var reconciler = PlacementTestHarness.Reconciler(server, fleet, authority);

        await PlacementTestHarness.ConvergeAsync(server, fleet, authority, reconciler, "prod-db", 1, "GRU", "SFO", "FRA");
        var elasticFra = fleet.Instances.Single(instance => instance.EndsWith(".6"));
        fleet.SetHealth(elasticFra, up: true, lag: 9_000);
        await PlacementTestHarness.ApplyIntentAsync(server.Delivery, "prod-db", 2, "GRU", "SFO");

        // A lagging victim never reaches the fleet: the topology gate holds every tick.
        for (var tick = 0; tick < 3; tick++)
        {
            var result = await reconciler.TickAsync(CancellationToken.None);
            await Assert.That(result.State).IsEqualTo(PlacementTickObservation.StateHeld);
            await Assert.That(result.Member).IsEqualTo("elastic-fra");
        }
        await Assert.That(fleet.Calls.Any(static call => call.StartsWith("cordon:", StringComparison.Ordinal))).IsFalse();

        fleet.SetHealth(elasticFra, up: true, lag: 0);
        var status = await PlacementTestHarness.TickUntilAsync(
            () => reconciler.TickAsync(CancellationToken.None),
            result => result.Action == "remove");
        await Assert.That(status.Member).IsEqualTo("elastic-fra");

        var members = await PlacementTestHarness.MemberStatesAsync(server.Delivery, "prod-db");
        await Assert.That(members.Any(static member => member.MemberId == "elastic-fra")).IsFalse();
        await Assert.That(fleet.Calls.Any(static call => call.StartsWith("drain:", StringComparison.Ordinal))).IsTrue();
        await Assert.That(fleet.Calls.Any(static call => call.StartsWith("retire:", StringComparison.Ordinal))).IsTrue();
        // The planned detach executed at the provider before the retire, by the victim's
        // durable volume identity and against its exact instance.
        var detachIndex = fleet.Calls.FindIndex(static call =>
            call.StartsWith("detach-volume:vol-elastic-fra:", StringComparison.Ordinal));
        var retireIndex = fleet.Calls.FindIndex(static call =>
            call.StartsWith("retire:", StringComparison.Ordinal));
        await Assert.That(detachIndex).IsGreaterThan(-1);
        await Assert.That(retireIndex).IsGreaterThan(detachIndex);
        await Assert.That(fleet.Calls[detachIndex]).EndsWith($":{elasticFra}");
        // The victim's retained volume record survives the member.
        var volume = await TerraBasePlacementReconciler.ReadVolumeAsync(
            server.Delivery, "prod-db", "elastic-fra", CancellationToken.None);
        await Assert.That(volume).IsNotNull();

        // The exited Region's permanent member is permanent: it stays, refused forever.
        var refused = await PlacementTestHarness.TickUntilAsync(
            () => reconciler.TickAsync(CancellationToken.None),
            result => result.Member == "permanent-c" && result.State == PlacementTickObservation.StateHeld);
        await Assert.That(refused.Error).IsEqualTo(nameof(TerraBaseCode.PermanentMember));
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Drain_holds_when_retained_volume_is_missing_or_disagrees_with_the_host(bool mismatch)
    {
        if (!OperatingSystem.IsLinux()) return;
        await using var server = await PlacementNatsServer.StartAsync();
        var fleet = new FakeMemberHostFleet();
        var authority = new PlacementAuthorityHolder();
        var reconciler = PlacementTestHarness.Reconciler(server, fleet, authority);
        await PlacementTestHarness.ConvergeAsync(server, fleet, authority, reconciler, "prod-db", 1, "GRU", "SFO", "FRA");
        await PlacementTestHarness.ApplyIntentAsync(server.Delivery, "prod-db", 2, "GRU", "SFO");
        await PlacementTestHarness.TickUntilAsync(() => reconciler.TickAsync(CancellationToken.None), result => result.Action == "deregister");
        if (mismatch)
            fleet.SetVolume(fleet.Instances.Single(instance => instance.EndsWith(".6")), "wrong-disk");
        else
            await server.Delivery.DeleteAsync(PlacementVolumeStateDocument.Key("prod-db", "elastic-fra"));
        for (var tick = 0; tick < 3; tick++)
        {
            var held = await reconciler.TickAsync(CancellationToken.None);
            await Assert.That(held.State).IsEqualTo(PlacementTickObservation.StateHeld);
            await Assert.That(held.Error).IsEqualTo(mismatch ? "provider-volume-mismatched" : "retained-volume-missing");
        }
        await Assert.That(fleet.Calls.Any(call => call.StartsWith("detach-volume:", StringComparison.Ordinal))).IsFalse();
        await Assert.That(fleet.Calls.Any(call => call.StartsWith("retire:", StringComparison.Ordinal))).IsFalse();
    }

    [Test]
    public async Task Lost_member_evidence_during_drain_never_authorizes_storage_detach_or_retirement()
    {
        if (!OperatingSystem.IsLinux()) return;
        await using var server = await PlacementNatsServer.StartAsync();
        var fleet = new FakeMemberHostFleet();
        var authority = new PlacementAuthorityHolder();
        var reconciler = PlacementTestHarness.Reconciler(server, fleet, authority);
        await PlacementTestHarness.ConvergeAsync(server, fleet, authority, reconciler, "prod-db", 1, "GRU", "SFO", "FRA");
        var victim = fleet.Instances.Single(instance => instance.EndsWith(".6"));
        await PlacementTestHarness.ApplyIntentAsync(server.Delivery, "prod-db", 2, "GRU", "SFO");
        await PlacementTestHarness.TickUntilAsync(() => reconciler.TickAsync(CancellationToken.None), result => result.Action == "drain");
        fleet.ForgetHealth(victim);
        for (var tick = 0; tick < 3; tick++)
        {
            var result = await reconciler.TickAsync(CancellationToken.None);
            await Assert.That(result.State).IsEqualTo(PlacementTickObservation.StateHeld);
            await Assert.That(result.Error).IsEqualTo("member-evidence-missing");
        }
        await Assert.That(fleet.Calls.Any(call => call.StartsWith("detach-volume:", StringComparison.Ordinal))).IsFalse();
        await Assert.That(fleet.Calls.Any(call => call.StartsWith("retire:", StringComparison.Ordinal))).IsFalse();
    }

    [Test]
    public async Task HealsDeadHostWithVolumeReattachAtEpochPlusOneEndToEnd()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var server = await PlacementNatsServer.StartAsync();
        var fleet = new FakeMemberHostFleet();
        var authority = new PlacementAuthorityHolder();
        var reconciler = PlacementTestHarness.Reconciler(server, fleet, authority);

        await PlacementTestHarness.ConvergeAsync(server, fleet, authority, reconciler, "prod-db", 1, "GRU");
        var oldInstance = fleet.Instances.Single(instance => instance.EndsWith(".2"));
        var volumeBefore = await TerraBasePlacementReconciler.ReadVolumeAsync(
            server.Delivery, "prod-db", "elastic-gru", CancellationToken.None);

        fleet.RemoveHost(oldInstance);
        var replaced = await PlacementTestHarness.TickUntilAsync(
            () => reconciler.TickAsync(CancellationToken.None),
            result => result.Action == "healthy" && result.Member == "elastic-gru");
        await Assert.That(replaced.Member).IsEqualTo("elastic-gru");

        var members = await PlacementTestHarness.MemberStatesAsync(server.Delivery, "prod-db");
        var member = members.Single(static candidate => candidate.MemberId == "elastic-gru");
        await Assert.That(member.Stage).IsEqualTo(PlacementMemberStateDocument.StageServing);
        await Assert.That(member.InstanceId).IsNotEqualTo(oldInstance);
        var volumeAfter = await TerraBasePlacementReconciler.ReadVolumeAsync(
            server.Delivery, "prod-db", "elastic-gru", CancellationToken.None);
        // REATTACH, never a new volume: the same provider identity at writer epoch + 1.
        await Assert.That(volumeAfter!.Document.ProviderVolumeId)
            .IsEqualTo(volumeBefore!.Document.ProviderVolumeId);
        await Assert.That(volumeAfter.Document.WriterEpoch).IsEqualTo(volumeBefore.Document.WriterEpoch + 1);
        var provisionCalls = fleet.Calls
            .Where(static call => call.Contains(".elastic-gru:", StringComparison.Ordinal))
            .ToArray();
        await Assert.That(provisionCalls.Length).IsEqualTo(2);
        await Assert.That(provisionCalls[0]).IsNotEqualTo(provisionCalls[1]);
        // The retained volume was attached to the replacement host by its durable identity,
        // idempotently keyed to the new host incarnation.
        await Assert.That(fleet.Calls.Any(static call =>
            call.StartsWith("attach-volume:vol-elastic-gru:", StringComparison.Ordinal))).IsTrue();
        await Assert.That(fleet.Calls.Any(call =>
            call.Contains($":{member.InstanceId}:", StringComparison.Ordinal))).IsTrue();
    }

    [Test]
    public async Task UnknownVolumeAttachOutcomeHoldsTheReplacementUntilItResolvesEndToEnd()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var server = await PlacementNatsServer.StartAsync();
        var fleet = new FakeMemberHostFleet();
        var authority = new PlacementAuthorityHolder();
        var reconciler = PlacementTestHarness.Reconciler(server, fleet, authority);

        await PlacementTestHarness.ConvergeAsync(server, fleet, authority, reconciler, "prod-db", 1, "GRU");
        fleet.RemoveHost(fleet.Instances.Single(instance => instance.EndsWith(".2")));

        // A possibly-executed attach whose response was lost never advances the ladder and is
        // never retried as a second logical attach: every tick holds on the same attach key.
        fleet.VolumeAttachUnknown = true;
        var held = await PlacementTestHarness.TickUntilAsync(
            () => reconciler.TickAsync(CancellationToken.None),
            result => result.Action == "attach-volume");
        await Assert.That(held.State).IsEqualTo(PlacementTickObservation.StateHeld);

        fleet.VolumeAttachUnknown = false;
        var replaced = await PlacementTestHarness.TickUntilAsync(
            () => reconciler.TickAsync(CancellationToken.None),
            result => result.Action == "healthy" && result.Member == "elastic-gru");
        await Assert.That(replaced.Member).IsEqualTo("elastic-gru");
        var members = await PlacementTestHarness.MemberStatesAsync(server.Delivery, "prod-db");
        await Assert.That(members.Single(static candidate => candidate.MemberId == "elastic-gru").Stage)
            .IsEqualTo(PlacementMemberStateDocument.StageServing);
    }

    [Test]
    public async Task IntentStoreAppliesMonotonicallyAndRefusesNonAdvancingRevisions()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var server = await PlacementNatsServer.StartAsync();
        var intent = PlacementTestHarness.Intent("prod-db", 4, "GRU", "SFO");

        await Assert.That(await PlacementIntentStore.ApplyAsync(server.Delivery, intent, CancellationToken.None))
            .IsEqualTo("created");
        await Assert.That(async () => await PlacementIntentStore.ApplyAsync(
                server.Delivery, PlacementTestHarness.Intent("prod-db", 4, "GRU"), CancellationToken.None))
            .Throws<ArgumentException>();
        await Assert.That(await PlacementIntentStore.ApplyAsync(
                server.Delivery, PlacementTestHarness.Intent("prod-db", 5, "GRU"), CancellationToken.None))
            .IsEqualTo("updated");
        var stored = await PlacementWorld.ReadIntentsAsync(server.Delivery, CancellationToken.None);
        await Assert.That(stored.Single().Revision).IsEqualTo(5);
    }
}

/// <summary>Shared helpers for the placement reconciler test lanes.</summary>
internal static class PlacementTestHarness
{
    public static PlacementIntentDocument Intent(string database, long revision, params string[] regions) =>
        new(PlacementIntentDocument.CurrentSchemaVersion, database, regions, "p0", revision);

    public static async Task ApplyIntentAsync(
        NATS.Client.KeyValueStore.INatsKVStore delivery,
        string database,
        long revision,
        params string[] regions)
    {
        await PlacementIntentStore.ApplyAsync(delivery, Intent(database, revision, regions), CancellationToken.None);
    }

    public static TerraBasePlacementReconciler Reconciler(
        PlacementNatsServer server,
        FakeMemberHostFleet fleet,
        PlacementAuthorityHolder authority) =>
        TerraBasePlacementReconciler.Create(
            server.Delivery,
            server.Runtime,
            authority.Snapshot,
            fleet,
            "gru");

    /// <summary>Bootstraps the fleet by reconciling to a fully serving state, then asserts it got there.</summary>
    public static async Task ConvergeAsync(
        PlacementNatsServer server,
        FakeMemberHostFleet fleet,
        PlacementAuthorityHolder authority,
        TerraBasePlacementReconciler reconciler,
        string database,
        long revision,
        params string[] regions)
    {
        await ApplyIntentAsync(server.Delivery, database, revision, regions);
        var status = await TickUntilAsync(
            () => reconciler.TickAsync(CancellationToken.None),
            result => result.State == PlacementTickObservation.StateIdle);
        if (fleet.Instances.Count != regions.Length * 2)
            throw new InvalidOperationException(
                $"The bootstrap converged {fleet.Instances.Count} hosts, expected {regions.Length * 2} ({status.State}).");
    }

    public static async Task<PlacementTickObservation> TickUntilAsync(
        Func<Task<PlacementTickObservation>> tick,
        Func<PlacementTickObservation, bool> predicate,
        int maximumTicks = 80)
    {
        PlacementTickObservation last = new(1, string.Empty, string.Empty, null, null, null, null, 0, default);
        for (var index = 0; index < maximumTicks; index++)
        {
            last = await tick();
            if (predicate(last))
                return last;
        }
        throw new TimeoutException(
            $"The reconciler did not reach the expected state within {maximumTicks} ticks " +
            $"(last: {last.State}/{last.Member}/{last.Action}/{last.Error}).");
    }

    public static async Task<List<PlacementMemberStateDocument>> MemberStatesAsync(
        NATS.Client.KeyValueStore.INatsKVStore delivery,
        string database)
    {
        var records = await PlacementWorld.ReadMemberStatesAsync(delivery, database, CancellationToken.None);
        return records.Select(static record => record.Document).ToList();
    }

    public static async Task<PlacementTickObservation?> ReadStatusAsync(
        NATS.Client.KeyValueStore.INatsKVStore runtime)
    {
        try
        {
            var entry = await runtime.GetEntryAsync<string>(PlacementTickObservation.Key("gru"));
            entry.EnsureSuccess();
            return JsonSerializer.Deserialize(
                entry.Value ?? string.Empty, TerraBasePlacementJsonContext.Default.PlacementTickObservation);
        }
        catch (NatsKVException)
        {
            return null;
        }
    }
}

/// <summary>A mutable authority holder: tests flip leadership mid-flight.</summary>
internal sealed class PlacementAuthorityHolder
{
    public bool IsLeader = true;

    public RegionalAuthoritySnapshot Snapshot() => new(
        "leader",
        IsLeader,
        Epoch: 7,
        KvRevision: 9,
        LeaseExpiresAt: DateTimeOffset.UtcNow.AddMinutes(1),
        ObservedAt: DateTimeOffset.UtcNow,
        Error: null);
}

/// <summary>A single containerized NATS server with the ORCH_DELIVERY and ORCH_RUNTIME buckets.</summary>
internal sealed class PlacementNatsServer : IAsyncDisposable
{
    private readonly LocalNatsServerLease.Handle lease;
    private readonly Process? nats;
    private readonly NatsClient? client;
    private readonly ContainerizedNatsCluster? containers;

    private PlacementNatsServer(
        string directory,
        LocalNatsServerLease.Handle lease,
        Process? nats,
        NatsClient? client,
        ContainerizedNatsCluster? containers)
    {
        this.lease = lease;
        this.nats = nats;
        this.client = client;
        this.containers = containers;
        Directory = directory;
    }

    public string Directory { get; }

    internal NATS.Client.KeyValueStore.INatsKVStore Delivery
    {
        get
        {
            if (delivery is null)
                throw new InvalidOperationException("The placement NATS server is not started.");
            return delivery;
        }
    }

    internal NATS.Client.KeyValueStore.INatsKVStore Runtime
    {
        get
        {
            if (runtimeStore is null)
                throw new InvalidOperationException("The placement NATS server is not started.");
            return runtimeStore;
        }
    }

    internal NATS.Client.Core.INatsConnection Connection =>
        client?.Connection ?? throw new InvalidOperationException("The placement NATS server is not started.");

    private NATS.Client.KeyValueStore.INatsKVStore? delivery;
    private NATS.Client.KeyValueStore.INatsKVStore? runtimeStore;

    public static async Task<PlacementNatsServer> StartAsync()
    {
        var lease = await LocalNatsServerLease.AcquireAsync();
        var directory = Path.Combine(Path.GetTempPath(), $"ts-orch-placement-{Guid.NewGuid():N}");
        PlacementNatsServer? server = null;
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
            var process = containers.Start(configuration);
            var client = new NatsClient(new NatsOpts
            {
                Url = $"nats://127.0.0.1:{port}",
                ConnectTimeout = TimeSpan.FromSeconds(5),
                RequestTimeout = TimeSpan.FromSeconds(5)
            });
            for (var attempt = 1; ; attempt++)
            {
                try
                {
                    await client.ConnectAsync();
                    break;
                }
                catch (NatsException) when (attempt < 150)
                {
                    await Task.Delay(200);
                }
            }
            await NatsOperationJournalProvisioner.ProvisionControllerTopologyAsync(
                client, new NatsTopology("gru", 1, "test-1"), CancellationToken.None);
            var keyValue = client.CreateJetStreamContext().CreateKeyValueStoreContext();
            server = new PlacementNatsServer(directory, lease, process, client, containers)
            {
                delivery = await keyValue.GetStoreAsync("ORCH_DELIVERY"),
                runtimeStore = await keyValue.GetStoreAsync("ORCH_RUNTIME"),
            };
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

    public async ValueTask DisposeAsync()
    {
        if (client is not null) await client.DisposeAsync();
        if (nats is not null && containers is not null) await containers.StopAsync(nats);
        if (containers is not null) await containers.DisposeAsync();
        await new LocalNatsServerLease.DirectoryCleanupOwner(Directory, lease).DisposeAsync();
    }
}
