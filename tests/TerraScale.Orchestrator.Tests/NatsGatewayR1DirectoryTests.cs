using System.Diagnostics;
using NATS.Client.Core;
using NATS.Client.KeyValueStore;
using NATS.Net;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// RF1 gateway evidence for the global cell directory: a remote cell's publisher
/// advertises into the GRU-owned GLOBAL_CELLS bucket, the GRU watch/service
/// projection serves it cross-mesh, and losing the publisher (with the region's
/// gateway links severed) degrades the directory to stale within the semantic
/// lease while regional control keeps serving. Healing and a restarted publisher
/// recover the same cell — never a duplicate — without cross-cell KV access and
/// without losing local authority. This is regional-development (RF1) evidence,
/// not production R3/quorum evidence.
/// </summary>
[NotInParallel("NatsR3")]
public sealed class NatsGatewayR1DirectoryTests
{
    private static readonly TimeSpan StalenessWindow =
        GlobalCellAdvertisement.SemanticLease + TimeSpan.FromSeconds(15);
    private static readonly TimeSpan RecoveryWindow = TimeSpan.FromSeconds(30);

    [Test]
    public async Task PublisherLossMarksTheCellStaleAndHealingRecoversWithoutAuthorityLoss()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var fixture = await NatsGatewayR1Fixture.StartAsync();
        var gruServer = TerraScale.Orchestrator.Messaging.NatsGatewayPlaneTopology.ControlServerName("gru", 1);
        var endpoint = $"tls://127.0.0.1:{fixture.ClientPorts[gruServer]}";

        // The durable global plane: GRU owns the GLOBAL_CELLS bucket at RF1, and
        // JetStream state is account-scoped, so the global-directory account's
        // infrastructure identity provisions it.
        await using var directoryInfrastructure = await fixture.ConnectAsync(
            fixture.Users["directory-infrastructure-gru"], "gru");
        var globalTopology = new GlobalNatsTopology(3);
        _ = await directoryInfrastructure.CreateJetStreamContext()
            .CreateKeyValueStoreContext()
            .CreateStoreAsync(globalTopology.Cells with { NumberOfReplicas = 1 });
        // Pinpoint probe: the watcher identity must see the stream in GRU's domain.
        var watcherProbe = new NatsClient(fixture.ClientOptions(
            fixture.Users["directory-watcher-gru"],
            TerraScale.Orchestrator.Messaging.NatsGatewayPlaneTopology.ControlServerName("gru", 1)));
        await using (watcherProbe)
        {
            await watcherProbe.ConnectAsync();
            var probeInfo = await watcherProbe.CreateJetStreamContext()
                .GetStreamAsync($"KV_{globalTopology.Cells.Bucket}");
            await Assert.That(probeInfo.Info.Config.NumReplicas).IsEqualTo(1);
        }

        // The SFO regional view the publisher advertises: one signed member under
        // one stable leader authority whose epoch must never change across the
        // fault. The snapshot regenerates per publication with the same session
        // and signing identity — identity/session continuity across the fault.
        const long authorityEpoch = 12;
        const long authorityRevision = 34;
        var sfoSession = Guid.NewGuid().ToString("N");
        using var membershipIdentity = RegionalRuntimeMembershipIdentity.Create();
        RegionalRuntimeMembershipSnapshot SfoMembership() => SfoMembershipSnapshot(
            membershipIdentity,
            sfoSession,
            authorityEpoch,
            authorityRevision);
        RegionalAuthoritySnapshot Authority() => new(
            "leader",
            true,
            authorityEpoch,
            authorityRevision,
            DateTimeOffset.UtcNow.AddSeconds(15),
            DateTimeOffset.UtcNow,
            null);

        // The GRU-side projection under its production supervision: the lifecycle
        // restarts the watch runtime if its consumer is disrupted, and serves the
        // snapshot through one queue-grouped read-only service instance. A second
        // instance joins the same queue group to prove horizontal distributability.
        var watcherConfiguration = new GlobalDirectoryNatsConfiguration(
            endpoint,
            NatsAuthenticationFiles.FromCredentialsFile(
                fixture.Users["directory-watcher-gru"].CredentialsFile,
                "TEST_GLOBAL_DIRECTORY_WATCHER"),
            new(
                fixture.CaFile,
                fixture.Users["directory-watcher-gru"].CertificateFile,
                fixture.Users["directory-watcher-gru"].KeyFile),
            3,
            "gru");
        var serviceConfiguration = new GlobalDirectoryServiceNatsConfiguration(
            endpoint,
            NatsAuthenticationFiles.FromCredentialsFile(
                fixture.Users["directory-service-gru"].CredentialsFile,
                "TEST_GLOBAL_DIRECTORY_SERVICE"),
            new(
                fixture.CaFile,
                fixture.Users["directory-service-gru"].CertificateFile,
                fixture.Users["directory-service-gru"].KeyFile),
            3,
            "gru");
        using var supervision = new CancellationTokenSource();
        await using var directory = GlobalCellDirectoryLifecycle.Start(
            watcherConfiguration,
            serviceConfiguration,
            SfoMembership,
            Authority,
            publishEnabled: false,
            supervision.Token);
        await using var serviceTwo = await GlobalCellDirectoryServiceRuntime.StartAsync(
            serviceConfiguration,
            () => directory.Snapshot);

        // Regional participants: the SFO local status service (workload evidence)
        // and the readers that query the directory cross-mesh.
        var sfoRegional = new NatsTopology("sfo", NatsGatewayR1Fixture.ServersPerRegion);
        await using var localServiceClient = await fixture.ConnectAsync(
            fixture.Users["sfo-local-service"], "sfo");
        await using var localStatus = await localServiceClient.Connection.SubscribeCoreAsync<string>(
            sfoRegional.StatusSubject);
        await localServiceClient.PingAsync();
        var localStatusLoop = Task.Run(async () =>
        {
            await foreach (var message in localStatus.Msgs.ReadAllAsync())
                await message.ReplyAsync($"rf1-sfo-status:{message.Data}");
        });
        await using var fraReader = await fixture.ConnectAsync(fixture.Users["directory-reader-fra"], "fra");
        await using var sfoProbe = await fixture.ConnectAsync(fixture.Users["directory-reader-sfo"], "sfo");

        try
        {
            // -----------------------------------------------------------------
            // Healthy: the publisher advertises, the projection serves it, and
            // both queue-grouped service instances answer.
            // -----------------------------------------------------------------
            var publisher = await StartPublisherAsync(fixture, endpoint, SfoMembership, Authority);
            var established = await WaitForSnapshotAsync(
                () => directory.Snapshot,
                snapshot => snapshot is { ActiveCells: 1 } &&
                            snapshot.Cells is [{ Cell: "sfo", IsStale: false }],
                TimeSpan.FromSeconds(15),
                "the initial SFO advertisement to converge");
            established.Validate();
            await Assert.That(established.Condition).IsEqualTo(GlobalCellDirectoryCondition.Healthy);
            await Assert.That(established.Cells.Single().AuthorityEpoch).IsEqualTo(authorityEpoch);
            await Assert.That(established.Cells.Single().Endpoints)
                .IsEquivalentTo(["tls://control-sfo.internal:4222"]);
            var sequenceBefore = established.Cells.Single().Sequence;
            var before = await fraReader.RequestAsync<string, string>(
                GlobalNatsTopology.CellDirectorySubject, "healthy");
            before.EnsureSuccess();
            await Assert.That(ParseActiveCells(before.Data)).IsEqualTo(1);

            // -----------------------------------------------------------------
            // Publisher loss: the advertising process disappears while the mesh is
            // healthy. Within the semantic lease plus a bounded margin the
            // directory degrades the SFO entry to stale — never resurrecting it
            // and never duplicating it.
            // -----------------------------------------------------------------
            await publisher.DisposeAsync();
            var faultAt = Stopwatch.GetTimestamp();
            var stale = await WaitForSnapshotAsync(
                () => directory.Snapshot,
                snapshot => snapshot.Cells is [{ Cell: "sfo", IsStale: true }],
                StalenessWindow,
                "the SFO advertisement to become stale");
            var detectionElapsed = Stopwatch.GetElapsedTime(faultAt);
            stale.Validate();
            await Assert.That(stale.ActiveCells).IsEqualTo(0);
            await Assert.That(stale.StaleCells).IsEqualTo(1);
            await Assert.That(stale.Condition).IsEqualTo(GlobalCellDirectoryCondition.Unavailable);
            await Assert.That(stale.Cells.Count(static cell => cell.Cell == "sfo")).IsEqualTo(1);
            await Assert.That(detectionElapsed)
                .IsLessThanOrEqualTo(GlobalCellAdvertisement.SemanticLease + TimeSpan.FromSeconds(15));

            // The rest of the mesh keeps querying the stale projection, and the
            // stateless queue-grouped handlers stay distributable: stopping the
            // extra service instance leaves the supervised instance serving.
            var fraDuringLoss = await fraReader.RequestAsync<string, string>(
                GlobalNatsTopology.CellDirectorySubject, "during-loss");
            fraDuringLoss.EnsureSuccess();
            await Assert.That(ParseActiveCells(fraDuringLoss.Data)).IsEqualTo(0);
            await serviceTwo.DisposeAsync();
            var fraAfterStop = await fraReader.RequestAsync<string, string>(
                GlobalNatsTopology.CellDirectorySubject, "after-stop");
            fraAfterStop.EnsureSuccess();

            // -----------------------------------------------------------------
            // Recovery: a restarted publisher with the same cell, identity
            // continuity, and the same authority epoch returns the directory to
            // healthy without cross-cell KV access and without authority loss.
            // -----------------------------------------------------------------
            var recoveryStart = Stopwatch.GetTimestamp();
            var restarted = await StartPublisherWithRetryAsync(fixture, endpoint, SfoMembership, Authority);
            var recovered = await WaitForSnapshotAsync(
                () => directory.Snapshot,
                snapshot => snapshot is { ActiveCells: 1, Condition: GlobalCellDirectoryCondition.Healthy } &&
                            snapshot.Cells is [{ Cell: "sfo", IsStale: false, Sequence: > 0 }],
                RecoveryWindow,
                "the recovered SFO advertisement to converge");
            var recoveryElapsed = Stopwatch.GetElapsedTime(recoveryStart);
            recovered.Validate();
            await Assert.That(recovered.Cells.Single().AuthorityEpoch).IsEqualTo(authorityEpoch);
            await Assert.That(recovered.Cells.Single().Sequence).IsGreaterThan(sequenceBefore);
            await Assert.That(recovered.Cells.Count(static cell => cell.Cell == "sfo")).IsEqualTo(1);
            await Assert.That(recoveryElapsed).IsLessThanOrEqualTo(RecoveryWindow);

            // Cross-cell KV access is denied for the regional publisher identity,
            // and the stateless service identity cannot mutate membership truth.
            await using (var publisherDenied = await PublisherDeniedClientAsync(fixture, endpoint))
            {
                await Assert.That(async () => _ = await publisherDenied.RequestAsync<string, string>(
                        "$KV.GLOBAL_CELLS.cell.fra", "cross-cell"))
                    .Throws<NatsException>();
            }
            await using (var serviceClient = await fixture.ConnectAsync(fixture.Users["directory-service-gru"], "gru"))
            {
                await Assert.That(async () => _ = await serviceClient.RequestAsync<string, string>(
                        "$KV.GLOBAL_CELLS.cell.sfo", "service-write"))
                    .Throws<NatsException>();
            }

            // -----------------------------------------------------------------
            // Gateway loss, last: the SFO region loses its gateway links. The
            // isolated cell keeps serving regional control and workloads locally
            // while its cross-mesh request fails, and the rest of the mesh keeps
            // querying the directory — the durable directory rides its own
            // client-network path, not the gateway. After the heal the same
            // client resumes cross-mesh traffic. (No JetStream assertion depends
            // on post-heal state: this fixture's single-server self-route can
            // fail its TLS redial after netns churn, which would wedge the
            // region's JetStream meta layer for the window.)
            // -----------------------------------------------------------------
            await fixture.SeverGatewayLinksAsync("sfo");
            await Assert.That(fixture.ServerIsRunning("sfo")).IsTrue();

            var localDuring = await sfoProbe.RequestAsync<string, string>(
                sfoRegional.StatusSubject, "during");
            localDuring.EnsureSuccess();
            await Assert.That(localDuring.Data).IsEqualTo("rf1-sfo-status:during");
            await Assert.That((await TryRequestAsync(
                    sfoProbe, GlobalNatsTopology.CellDirectorySubject, "during-partition")).Succeeded)
                .IsFalse();

            var fraDuringPartition = await fraReader.RequestAsync<string, string>(
                GlobalNatsTopology.CellDirectorySubject, "during-partition");
            fraDuringPartition.EnsureSuccess();
            await Assert.That(ParseActiveCells(fraDuringPartition.Data)).IsEqualTo(1);

            await fixture.HealGatewayLinksAsync("sfo");
            await WaitForMeshAsync(fixture);
            var after = await sfoProbe.RequestAsync<string, string>(
                GlobalNatsTopology.CellDirectorySubject, "after");
            after.EnsureSuccess();
            await Assert.That(ParseActiveCells(after.Data)).IsEqualTo(1);

            // The publisher outlives the assertions (its advertisement must stay
            // active through the gateway phase); its teardown is guarded because
            // the fixture's post-heal JetStream state is not asserted.
            try
            {
                await restarted.DisposeAsync();
            }
            catch (NatsException)
            {
            }
        }
        finally
        {
            await localStatus.DisposeAsync();
            await localStatusLoop;
        }
    }

    /// <summary>
    /// Starts the publisher with a bounded retry: while the healed gateway mesh is
    /// still re-forming, the GRU JetStream meta layer may answer transiently
    /// offline. The fixture's own heal deadline bounds the retry window.
    /// </summary>
    private static async Task<GlobalCellDirectoryRuntime> StartPublisherWithRetryAsync(
        NatsGatewayR1Fixture fixture,
        string endpoint,
        Func<RegionalRuntimeMembershipSnapshot> membership,
        Func<RegionalAuthoritySnapshot> authority)
    {
        var started = Stopwatch.GetTimestamp();
        while (true)
        {
            try
            {
                return await StartPublisherAsync(fixture, endpoint, membership, authority);
            }
            catch (NatsException) when (Stopwatch.GetElapsedTime(started) < NatsGatewayR1Fixture.HealDeadline)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(500));
            }
        }
    }

    private static async Task<GlobalCellDirectoryRuntime> StartPublisherAsync(
        NatsGatewayR1Fixture fixture,
        string endpoint,
        Func<RegionalRuntimeMembershipSnapshot> membership,
        Func<RegionalAuthoritySnapshot> authority)
    {
        var configuration = new GlobalDirectoryNatsConfiguration(
            endpoint,
            NatsAuthenticationFiles.FromCredentialsFile(
                fixture.Users["directory-publisher-sfo"].CredentialsFile,
                "TEST_GLOBAL_DIRECTORY_PUBLISHER"),
            new(
                fixture.CaFile,
                fixture.Users["directory-publisher-sfo"].CertificateFile,
                fixture.Users["directory-publisher-sfo"].KeyFile),
            3,
            "sfo",
            ["tls://control-sfo.internal:4222"]);
        return await GlobalCellDirectoryRuntime.StartAsync(
            configuration,
            membership,
            authority,
            publishEnabled: true);
    }

    private static async Task<NatsClient> PublisherDeniedClientAsync(
        NatsGatewayR1Fixture fixture,
        string endpoint)
    {
        var gruServer = TerraScale.Orchestrator.Messaging.NatsGatewayPlaneTopology.ControlServerName("gru", 1);
        return await fixture.ConnectToServerAsync(fixture.Users["directory-publisher-sfo"], gruServer);
    }

    private static RegionalRuntimeMembershipSnapshot SfoMembershipSnapshot(
        RegionalRuntimeMembershipIdentity identity,
        string sessionId,
        long authorityEpoch,
        long authorityRevision)
    {
        var observedAt = DateTimeOffset.UtcNow;
        var health = new RegionalRuntimeMembershipHealth(
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            1,
            true,
            0,
            RegionalRuntimeMembershipCondition.Healthy,
            observedAt);
        var member = new RegionalRuntimeMember(
            1,
            "sfo",
            "orchestrator-control-sfo",
            "controller-1",
            sessionId,
            "rf1-build",
            ["authority", "regional-membership", "service-discovery"],
            observedAt.AddMinutes(-1),
            observedAt,
            observedAt.Add(RegionalRuntimeMembership.LeaseDuration),
            "leader",
            true,
            authorityEpoch,
            authorityRevision,
            identity.KeyId,
            identity.PublicKey,
            string.Empty);
        member = member with { IdentitySignature = identity.Sign(member) };
        return new(2, "sfo", observedAt, health, [member]);
    }

    private static async Task<GlobalCellDirectorySnapshot> WaitForSnapshotAsync(
        Func<GlobalCellDirectorySnapshot> observe,
        Func<GlobalCellDirectorySnapshot, bool> condition,
        TimeSpan timeout,
        string description)
    {
        var started = Stopwatch.GetTimestamp();
        GlobalCellDirectorySnapshot? last = null;
        while (Stopwatch.GetElapsedTime(started) < timeout)
        {
            last = observe();
            if (condition(last)) return last;
            await Task.Delay(TimeSpan.FromMilliseconds(250));
        }
        throw new TimeoutException(
            $"Timed out waiting for {description} within {timeout.TotalSeconds} seconds. " +
            $"Last observed: {(last is null ? "none" : DescribeSnapshot(last))}.");
    }

    /// <summary>Waits for the healed mesh to report every directed edge connected again.</summary>
    private static async Task WaitForMeshAsync(NatsGatewayR1Fixture fixture)
    {
        var started = Stopwatch.GetTimestamp();
        while (Stopwatch.GetElapsedTime(started) < NatsGatewayR1Fixture.HealDeadline)
        {
            if (fixture.IsFullMeshConnected(await fixture.GatewayLinkStateAsync())) return;
            await Task.Delay(TimeSpan.FromMilliseconds(300));
        }
        throw new TimeoutException(
            $"The healed RF1 mesh did not re-form within {NatsGatewayR1Fixture.HealDeadline.TotalSeconds} seconds. " +
            $"Observed: {fixture.DescribeLinkState(await fixture.GatewayLinkStateAsync())}.");
    }

    private static string DescribeSnapshot(GlobalCellDirectorySnapshot snapshot) =>
        $"active={snapshot.ActiveCells} stale={snapshot.StaleCells} " +
        string.Join(",", snapshot.Cells.Select(static cell => $"{cell.Cell}:{(cell.IsStale ? "stale" : "active")}"));

    private static int ParseActiveCells(string? snapshotJson)
    {
        using var document = System.Text.Json.JsonDocument.Parse(
            snapshotJson ?? throw new InvalidOperationException("The directory service returned no snapshot."));
        return document.RootElement.GetProperty("ActiveCells").GetInt32();
    }

    private static async Task<(bool Succeeded, string? Data)> TryRequestAsync(
        NatsClient client,
        string subject,
        string payload)
    {
        try
        {
            var response = await client.RequestAsync<string, string>(subject, payload);
            response.EnsureSuccess();
            return (response.Data is { Length: > 0 }, response.Data);
        }
        catch (NatsException)
        {
            return (false, null);
        }
        catch (TimeoutException)
        {
            return (false, null);
        }
    }
}
