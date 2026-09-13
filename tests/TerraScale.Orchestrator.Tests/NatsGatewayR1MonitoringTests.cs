using NATS.Client.Core;
using NATS.Net;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// RF1 real-NATS evidence for the monitoring contract (issue #23): the read-only
/// monitoring identity observes bounded connection, gateway, JetStream, and mesh
/// state through exactly the allowlisted <c>$SYS</c> subjects; a gateway partition
/// is observed truthfully (disconnected mesh state, partition duration, recovery);
/// and the same identity cannot perform control work, JetStream mutation, or
/// secret/product reads through the server: every forbidden request goes
/// unanswered (the publish permission never lets it reach a responder) while the
/// allowlisted monitoring requests are answered. A monitoring runtime pointed at
/// a dead endpoint fails fast while the control plane keeps serving. This is
/// regional-development (RF1) evidence, not production R3/quorum evidence.
/// </summary>
[NotInParallel("NatsR3")]
public sealed class NatsGatewayR1MonitoringTests
{
    private static readonly TimeSpan ObservationWindow = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan DenialWindow = TimeSpan.FromSeconds(2);

    [Test]
    public async Task Monitoring_identity_observes_bounded_system_state_and_mesh()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var fixture = await NatsGatewayR1Fixture.StartAsync();
        var gruServer = TerraScale.Orchestrator.Messaging.NatsGatewayPlaneTopology.ControlServerName("gru", 1);

        await using var monitor = await NatsMonitoringRuntime.StartAsync(MonitorOptions(fixture, gruServer));

        var aggregate = await EventuallyObserveAsync(monitor, candidate =>
            candidate.Availability == NatsMonitoringAvailability.Available &&
            candidate.Mesh.Cells.Count == 3);
        aggregate.Validate();

        // Bounded server observations: the monitor sees real connections, storage,
        // memory, and the mesh with every cell classified.
        await Assert.That(aggregate.Connections).IsGreaterThan(0);
        await Assert.That(aggregate.ServerMemoryBytes).IsGreaterThan(0);
        await Assert.That(aggregate.GatewaysConnected).IsEqualTo(2);
        await Assert.That(aggregate.GatewaysDisconnected).IsEqualTo(0);
        await Assert.That(aggregate.Mesh.HealthyCells + aggregate.Mesh.DisconnectedCells +
                          aggregate.Mesh.StaleCells + aggregate.Mesh.MissingCells +
                          aggregate.Mesh.ConflictingCells)
            .IsEqualTo(3);

        var snapshot = monitor.Snapshot();
        snapshot.Validate();
        await Assert.That(snapshot.Entries.All(static entry =>
            entry.Labels.Values.All(static value => value.Length <= 32))).IsTrue();
        await Assert.That(snapshot.Entries.Select(static entry => entry.Instrument))
            .Contains("terrascale.orchestrator.nats.connections");
        await Assert.That(NatsMonitoringRedaction.ContainsSecretMaterial(snapshot.RenderPrometheus())).IsFalse();
    }

    [Test]
    public async Task Gateway_partition_is_observed_truthfully_with_partition_and_recovery_durations()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var fixture = await NatsGatewayR1Fixture.StartAsync();
        var gruServer = TerraScale.Orchestrator.Messaging.NatsGatewayPlaneTopology.ControlServerName("gru", 1);

        await using var monitor = await NatsMonitoringRuntime.StartAsync(MonitorOptions(fixture, gruServer));
        await EventuallyObserveAsync(monitor, candidate =>
            candidate.Availability == NatsMonitoringAvailability.Available &&
            candidate.GatewaysConnected == 2);

        // Sever GRU's gateway links: a real transport-level mesh partition while
        // the server, its client listener, and the monitor stay alive.
        await fixture.SeverGatewayLinksAsync("gru");

        var partitioned = await EventuallyObserveAsync(monitor, candidate =>
            candidate.Mesh.Cells.Single(cell => cell.Cell == "gru").State == NatsMeshCellState.Disconnected);
        await Assert.That(partitioned.GatewaysConnected).IsEqualTo(0);
        await Assert.That(partitioned.GatewaysDisconnected).IsGreaterThanOrEqualTo(1);
        await Assert.That(partitioned.PartitionDurationMilliseconds).IsGreaterThanOrEqualTo(0);
        // Observability itself stays available: monitoring rides the client
        // network, not the gateway mesh — truthful degraded inputs, not blindness.
        await Assert.That(partitioned.Availability).IsEqualTo(NatsMonitoringAvailability.Available);

        await fixture.HealGatewayLinksAsync("gru");
        var recovered = await EventuallyObserveAsync(monitor, candidate =>
            candidate.GatewaysConnected == 2);
        await Assert.That(recovered.PartitionDurationMilliseconds).IsEqualTo(0);
        await Assert.That(recovered.RecoveryDurationMilliseconds).IsGreaterThanOrEqualTo(0);
    }

    [Test]
    public async Task Monitoring_identity_is_denied_control_mutation_secrets_and_product_reads()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var fixture = await NatsGatewayR1Fixture.StartAsync();
        var gruServer = TerraScale.Orchestrator.Messaging.NatsGatewayPlaneTopology.ControlServerName("gru", 1);

        // Positive control first: the allowlisted monitoring requests are answered,
        // so the denials below are permission denials, not a broken connection.
        await using (var allowed = await fixture.ConnectToServerAsync(fixture.Users["system-monitor"], gruServer))
        {
            using var answered = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var reply = await allowed.Connection.RequestAsync<string, string>(
                NatsMonitoringSubjects.Server, "", cancellationToken: answered.Token);
            await Assert.That(reply.Data is { Length: > 0 }).IsTrue();
        }

        // Every forbidden request goes unanswered: the monitoring identity's
        // publish permission never lets the request reach a responder (control
        // work, JetStream mutation and inspection, secret journal reads, and the
        // product plane alike).
        foreach (var forbidden in NatsMonitoringPermissions.Forbidden.JetStreamMutation()
                     .Concat(NatsMonitoringPermissions.Forbidden.ControlPublish("gru"))
                     .Concat(NatsMonitoringPermissions.Forbidden.ProductPlane())
                     .Where(static subject => !subject.EndsWith(".>", StringComparison.Ordinal))
                     .Append("$JS.API.STREAM.INFO.CELL_EVENTS")
                     .Append("$JS.API.CONSUMER.INFO.CELL_EVENTS.runtime_startup"))
        {
            Exception? denial = null;
            try
            {
                await RequestAs(fixture, gruServer, forbidden, "{}");
            }
            catch (Exception exception) when (exception is NatsNoReplyException or OperationCanceledException or NatsException)
            {
                // No reply within the denial window: the request never reached a
                // responder, because the identity holds no publish permission for it.
                denial = exception;
            }
            await Assert.That(denial).IsNotNull();
        }

        // Forbidden subscriptions stay silent: the monitoring identity may
        // subscribe only to its inbox and the advisory families. Silence alone is
        // not denial evidence (an authorized subscriber would also be silent on an
        // idle subject), so the sweep is bracketed by delivery canaries: first a
        // positive-delivery control proves the monitor's reader path delivers on
        // an allowed subject, then every forbidden subject stays silent under the
        // same reader, and the request control is re-verified after the sweep.
        // One connection per identity is reused for the whole bracketed sweep.
        await using var monitorClient = await fixture.ConnectToServerAsync(fixture.Users["system-monitor"], gruServer);
        await using var canary = await fixture.ConnectToServerAsync(fixture.Users["system-observer"], gruServer);
        const string inboxCanary = "_INBOX.monitoring.canary";
        await using (var allowedSubscription = await monitorClient.Connection.SubscribeCoreAsync<string>(inboxCanary))
        {
            await monitorClient.Connection.PingAsync();
            await canary.Connection.PublishAsync(inboxCanary, "canary");
            using var delivered = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var message = await allowedSubscription.Msgs.ReadAsync(delivered.Token);
            await Assert.That(message.Data).IsEqualTo("canary");
        }

        foreach (var forbidden in NatsMonitoringPermissions.Forbidden.SecretAndJournalReads()
                     .Concat(NatsMonitoringPermissions.Forbidden.ProductPlane())
                     .Where(static subject => !subject.EndsWith(".>", StringComparison.Ordinal))
                     .Append("$KV.ORCH_OPERATIONS.key"))
        {
            await using var subscription = await monitorClient.Connection.SubscribeCoreAsync<string>(forbidden);
            // Let the subscription register before the window opens.
            await monitorClient.Connection.PingAsync();
            Exception? silence = null;
            try
            {
                using var window = new CancellationTokenSource(DenialWindow);
                await subscription.Msgs.ReadAsync(window.Token);
            }
            catch (Exception exception) when (exception is OperationCanceledException or NatsException)
            {
                silence = exception;
            }
            await Assert.That(silence).IsNotNull();
        }

        // Re-verify both controls after the sweep: the monitor's reader still
        // delivers where allowed, and its allowlisted request is still answered —
        // every silence above was a permission denial, not a degraded reader.
        await using (var recheck = await monitorClient.Connection.SubscribeCoreAsync<string>(inboxCanary))
        {
            await monitorClient.Connection.PingAsync();
            await canary.Connection.PublishAsync(inboxCanary, "still-alive");
            using var delivered = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await Assert.That((await recheck.Msgs.ReadAsync(delivered.Token)).Data).IsEqualTo("still-alive");
        }
        {
            using var answered = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var reply = await monitorClient.Connection.RequestAsync<string, string>(
                NatsMonitoringSubjects.Server, "", cancellationToken: answered.Token);
            await Assert.That(reply.Data is { Length: > 0 }).IsTrue();
        }
    }

    [Test]
    public async Task Monitoring_unavailability_fails_fast_and_the_control_plane_keeps_serving()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var fixture = await NatsGatewayR1Fixture.StartAsync();
        var gruServer = TerraScale.Orchestrator.Messaging.NatsGatewayPlaneTopology.ControlServerName("gru", 1);

        // A monitoring runtime pointed at a dead endpoint fails fast at startup —
        // no retry storm, no hang — because observability must never be able to
        // delay or block control.
        var failed = false;
        try
        {
            await using var dead = await NatsMonitoringRuntime.StartAsync(
                MonitorOptions(fixture, gruServer) with
                {
                    Url = $"tls://127.0.0.1:{FreePort()}",
                    PollInterval = TimeSpan.FromSeconds(1)
                });
        }
        catch (Exception exception) when (exception is NatsException or TimeoutException)
        {
            failed = true;
        }
        await Assert.That(failed).IsTrue();

        // While monitoring is unavailable, the control plane still serves: the
        // pinned server answers gateway state for a different identity.
        var linkSnapshot = await fixture.GatewayLinkStateAsync();
        await Assert.That(linkSnapshot.OutboundByCluster).IsNotEmpty();
    }

    private static NatsMonitoringRuntimeOptions MonitorOptions(
        NatsGatewayR1Fixture fixture,
        string gruServer)
    {
        var identity = fixture.Users["system-monitor"];
        return new(
            $"tls://127.0.0.1:{fixture.ClientPorts[gruServer]}",
            "gru",
            NatsMonitoringPlane.Control,
            NatsClusterRole.Regional,
            ["gru", "sfo", "fra"],
            CredsFile: identity.CredentialsFile,
            Tls: new NatsTlsFiles(fixture.CaFile, identity.CertificateFile, identity.KeyFile),
            ClientCertificateFile: identity.CertificateFile,
            ClientKeyFile: identity.KeyFile,
            PollInterval: TimeSpan.FromSeconds(1));
    }
    /// <summary>
    /// One request under the monitoring identity with a bounded denial window: a
    /// subject the plan cannot publish never reaches a responder, which surfaces
    /// as <see cref="NatsNoReplyException"/> once the window closes.
    /// </summary>
    private static async Task<string?> RequestAs(
        NatsGatewayR1Fixture fixture,
        string gruServer,
        string subject,
        string payload)
    {
        await using var client = await fixture.ConnectToServerAsync(fixture.Users["system-monitor"], gruServer);
        using var timeout = new CancellationTokenSource(DenialWindow);
        var reply = await client.Connection.RequestAsync<string, string>(
            subject, payload, cancellationToken: timeout.Token);
        return reply.Data;
    }

    private static async Task<NatsMonitoringAggregate> EventuallyObserveAsync(
        NatsMonitoringRuntime monitor,
        Func<NatsMonitoringAggregate, bool> condition)
    {
        using var timeout = new CancellationTokenSource(ObservationWindow);
        while (true)
        {
            var aggregate = monitor.Current;
            if (condition(aggregate)) return aggregate;
            try
            {
                await Task.Delay(200, timeout.Token);
            }
            catch (OperationCanceledException)
            {
                var last = monitor.Current;
                throw new TimeoutException(
                    $"The bounded observation did not converge within {ObservationWindow}. " +
                    $"Last availability={last.Availability}, gateways {last.GatewaysConnected}+/{last.GatewaysDisconnected}-, " +
                    $"mesh=[{string.Join(',', last.Mesh.Cells.Select(cell => $"{cell.Cell}={cell.State}"))}], " +
                    $"last round error='{monitor.LastRoundError}', " +
                    $"rounds started={monitor.StartedRounds} completed={monitor.CompletedRounds}.");
            }
        }
    }

    private static int FreePort()
    {
        var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }
}

