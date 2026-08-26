using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Pure tests for the typed NATS observation model (issue #23): parser shapes,
/// classifier totality, the disconnected mesh state, aggregate validation, and the
/// bounded Grafana/Prometheus-facing snapshot projection.
/// </summary>
public sealed class NatsMonitoringObservationTests
{
    [Test]
    public async Task Parsers_extract_bounded_observations_from_system_shapes()
    {
        var observedAt = DateTimeOffset.UtcNow;

        var connections = NatsMonitoringParsers.Connections(
            """{"total": 4, "connections": [{"cid": 1, "num_reconnects": 2}, {"cid": 2}]}""",
            "gru", NatsMonitoringPlane.Control, observedAt);
        await Assert.That(connections).IsNotNull();
        await Assert.That(connections!.Connections).IsEqualTo(4);
        await Assert.That(connections.Reconnects).IsEqualTo(2);

        var routes = NatsMonitoringParsers.Routes("""{"num_routes": 2}""", "gru", observedAt);
        await Assert.That(routes!.Routes).IsEqualTo(2);

        var gateways = NatsMonitoringParsers.Gateways(
            """{"data": {"name": "gru", "outbound_gateways": {"orchestrator-control-sfo": {"connection": {"id": 1}}, "orchestrator-control-fra": {"configured": true}}}}""",
            "gru", observedAt);
        await Assert.That(gateways).IsNotNull();
        await Assert.That(gateways!.ConnectedGateways).IsEqualTo(1);
        await Assert.That(gateways.DisconnectedGateways).IsEqualTo(1);

        var resources = NatsMonitoringParsers.ServerResources(
            """{"data": {"mem": 52428800, "jetstream": {"storage": 1048576}}}""",
            "gru", observedAt);
        await Assert.That(resources!.ServerMemoryBytes).IsEqualTo(52428800L);
        await Assert.That(resources.JetStreamStorageBytes).IsEqualTo(1048576L);

        var jetStream = NatsMonitoringParsers.JetStream(
            """{"memory": 10, "storage": 20, "streams": 3, "consumers": 4}""",
            "gru", observedAt);
        await Assert.That(jetStream!.Streams).IsEqualTo(3);
        await Assert.That(jetStream.Consumers).IsEqualTo(4);

        var detail = NatsMonitoringParsers.JetStreamDetail(
            """{"stream_detail": [{"name": "CELL_EVENTS", "state": {"messages": 12, "bytes": 3400}, "consumer_detail": [{"name": "runtime_startup", "num_pending": 3, "num_ack_pending": 1, "num_waiting": 0, "delivered": {"consumer_seq": 9}, "ack_floor": {"consumer_seq": 7}}]}, {"name": "KV_GLOBAL_CELLS", "state": {"messages": 2, "bytes": 200}}]}""");
        await Assert.That(detail).IsNotNull();
        var streams = detail!.Value.Streams.ToDictionary(static stream => stream.StreamClass);
        await Assert.That(streams[NatsStreamClass.CellEvents].Messages).IsEqualTo(12);
        await Assert.That(streams[NatsStreamClass.CellEvents].Bytes).IsEqualTo(3400);
        await Assert.That(streams[NatsStreamClass.KeyValue].Streams).IsEqualTo(1);
        var consumers = detail.Value.Consumers.Single();
        await Assert.That(consumers.StreamClass).IsEqualTo(NatsStreamClass.CellEvents);
        await Assert.That(consumers.ConsumerClass).IsEqualTo(NatsConsumerClass.StartupEvent);
        await Assert.That(consumers.Lag).IsEqualTo(3);
        await Assert.That(consumers.AckPending).IsEqualTo(1);
        await Assert.That(consumers.Deliveries).IsEqualTo(9);
        await Assert.That(consumers.Redelivered).IsEqualTo(2);

        // Malformed or unexpected shapes fail closed as null observations, never throw.
        await Assert.That(NatsMonitoringParsers.Connections("{}", "gru", NatsMonitoringPlane.Control, observedAt)).IsNull();
        await Assert.That(NatsMonitoringParsers.Routes("not json", "gru", observedAt)).IsNull();
        await Assert.That(NatsMonitoringParsers.Gateways("""{"data": []}""", "gru", observedAt)).IsNull();
    }

    [Test]
    public async Task Hostile_values_fail_closed_as_null_observations_never_exceptions()
    {
        var now = DateTimeOffset.UtcNow;

        // A negative census from a hostile or buggy reply is a shape mismatch,
        // not an exception into the observation loop.
        await Assert.That(NatsMonitoringParsers.Connections(
            """{"total":-1}""", "gru", NatsMonitoringPlane.Control, now)).IsNull();
        await Assert.That(NatsMonitoringParsers.Connections(
            """{"total":1,"connections":[{"num_reconnects":-5}]}""", "gru", NatsMonitoringPlane.Control, now)).IsNull();
        await Assert.That(NatsMonitoringParsers.Routes(
            """{"num_routes":-2}""", "gru", now)).IsNull();
        await Assert.That(NatsMonitoringParsers.ServerResources(
            """{"mem":-5,"jetstream":{"storage":-1}}""", "gru", now)).IsNull();
        await Assert.That(NatsMonitoringParsers.JetStream(
            """{"memory":-1,"storage":10}""", "gru", now)).IsNull();
        await Assert.That(NatsMonitoringParsers.JetStream(
            """{"memory":10,"storage":-10}""", "gru", now)).IsNull();
        await Assert.That(NatsMonitoringParsers.Accounts(
            """{"name":"x","account_total":-3}""", "gru", now)).IsNull();

        // Hostile timestamps do not reach these parsers (the observer supplies
        // the clock), and hostile detail values fail closed too: two consumer
        // counters at long.MaxValue overflow the per-class merge negative and
        // invalidate the whole detail observation.
        var maxDelivered = $$"""
            {"stream_detail":[{"name":"CELL_EVENTS","state":{"messages":1,"bytes":1},"consumer_detail":[
                {"name":"runtime_startup","delivered":{"consumer_seq":{{long.MaxValue}}},"num_pending":1},
                {"name":"runtime_startup_two","delivered":{"consumer_seq":{{long.MaxValue}}},"num_pending":1}]}]}
            """;
        await Assert.That(NatsMonitoringParsers.JetStreamDetail(maxDelivered)).IsNull();
        var negativeDetail = """
            {"stream_detail":[{"name":"CELL_EVENTS","state":{"messages":-9,"bytes":1}}]}
            """;
        await Assert.That(NatsMonitoringParsers.JetStreamDetail(negativeDetail)).IsNull();
    }

    [Test]
    public async Task Oversized_replies_are_refused_before_parsing()
    {
        await Assert.That(NatsMonitoringParsers.TryDocument(
            "{\"pad\":\"" + new string('x', NatsMonitoringParsers.MaximumReplyBytes) + "\"}",
            out _)).IsFalse();
        // A legitimate small document still parses.
        await Assert.That(NatsMonitoringParsers.TryDocument("""{"total":1}""", out _)).IsTrue();
    }

    [Test]
    public async Task Classifier_is_total_and_bounded()
    {
        foreach (var name in new[] { "CELL_SPEC", "CELL_OPERATIONS", "CELL_EVENTS", "GLOBAL_SPEC", "GLOBAL_CI", "KV_X", "OBJ_Y", "unexpected" })
            await Assert.That(Enum.IsDefined(NatsMonitoringClassifier.ClassifyStream(name))).IsTrue();
        await Assert.That(NatsMonitoringClassifier.ClassifyStream("KV_GLOBAL_CELLS")).IsEqualTo(NatsStreamClass.KeyValue);
        await Assert.That(NatsMonitoringClassifier.ClassifyStream("")).IsEqualTo(NatsStreamClass.Unknown);
        await Assert.That(NatsMonitoringClassifier.ClassifyConsumer("gitops_cell_spec_controller-1")).IsEqualTo(NatsConsumerClass.CellSpec);
        await Assert.That(NatsMonitoringClassifier.ClassifyConsumer("runtime_startup")).IsEqualTo(NatsConsumerClass.StartupEvent);
        await Assert.That(NatsMonitoringClassifier.ClassifyConsumer("ci_gru_runner")).IsEqualTo(NatsConsumerClass.GlobalCi);
        await Assert.That(NatsMonitoringClassifier.ClassifyConsumer("whatever")).IsEqualTo(NatsConsumerClass.Unknown);
        await Assert.That(NatsMonitoringClassifier.ClassifyAdvisory("$SYS.ACCOUNT.X.ADVISORY.SLOW_CONSUMER"))
            .IsEqualTo(NatsAdvisoryKind.SlowConsumer);
        await Assert.That(NatsMonitoringClassifier.ClassifyAdvisory("$SYS.JETSTREAM.ADVISORY.RAFT_LEADER_LOST"))
            .IsEqualTo(NatsAdvisoryKind.LeaderChange);
        await Assert.That(NatsMonitoringClassifier.ClassifyAdvisory("unknown"))
            .IsEqualTo(NatsAdvisoryKind.Unclassified);
    }

    [Test]
    public async Task Mesh_health_distinguishes_disconnected_from_stale_missing_conflicting_and_healthy()
    {
        var now = DateTimeOffset.UtcNow;
        var healthy = Membership("gru", now);
        var conflicting = Membership("sfo", now) with { ConflictingControllers = 1 };
        // FRA's advertisement was valid when published but its lease has expired
        // by observation time: the directory keeps the entry and marks it stale.
        var staleObservedAt = now - GlobalCellAdvertisement.SemanticLease - TimeSpan.FromSeconds(1);
        var degraded = Membership("fra", staleObservedAt) with
        {
            StaleControllers = 1,
            MaximumHeartbeatAgeMilliseconds = 60_000,
            Condition = RegionalRuntimeMembershipCondition.Degraded
        };

        var directory = new GlobalCellDirectory();
        var gruDisposition = directory.Apply(Advertise("gru", healthy, now), now);
        var sfoDisposition = directory.Apply(Advertise("sfo", conflicting, now), now);
        var fraDisposition = directory.Apply(Advertise("fra", degraded, staleObservedAt), now);
        await Assert.That(gruDisposition).IsEqualTo(GlobalCellAdvertisementDisposition.Accepted);
        await Assert.That(sfoDisposition).IsEqualTo(GlobalCellAdvertisementDisposition.Accepted);
        await Assert.That(fraDisposition).IsEqualTo(GlobalCellAdvertisementDisposition.Accepted);

        var mesh = NatsMeshHealth.Evaluate(
            ["gru", "sfo", "fra"],
            new Dictionary<string, RegionalRuntimeMembershipHealth>(StringComparer.Ordinal)
            {
                ["gru"] = healthy,
                ["sfo"] = conflicting
            },
            directory.Snapshot(now),
            new Dictionary<string, NatsGatewaysObservation>(StringComparer.Ordinal)
            {
                // GRU's own outbound links are all down: the partition signal.
                ["gru"] = NatsGatewaysObservation.Observe("gru", 0, 2, now)
            },
            now);

        mesh.Validate();
        await Assert.That(mesh.Count(NatsMeshCellState.Healthy)).IsEqualTo(0);
        await Assert.That(mesh.Cells.Single(cell => cell.Cell == "gru").State).IsEqualTo(NatsMeshCellState.Disconnected);
        await Assert.That(mesh.Cells.Single(cell => cell.Cell == "sfo").State).IsEqualTo(NatsMeshCellState.Conflicting);
        await Assert.That(mesh.Cells.Single(cell => cell.Cell == "fra").State).IsEqualTo(NatsMeshCellState.Stale);

        // A cell never advertised is missing.
        var empty = NatsMeshHealth.Evaluate(
            ["gru"],
            new Dictionary<string, RegionalRuntimeMembershipHealth>(StringComparer.Ordinal),
            new GlobalCellDirectorySnapshot(1, now, 0, 0, 0, GlobalCellDirectoryCondition.Unavailable, []),
            new Dictionary<string, NatsGatewaysObservation>(StringComparer.Ordinal),
            now);
        await Assert.That(empty.MissingCells).IsEqualTo(1);

        // A connected, healthy, conflict-free cell is healthy.
        var healthyMesh = NatsMeshHealth.Evaluate(
            ["gru"],
            new Dictionary<string, RegionalRuntimeMembershipHealth>(StringComparer.Ordinal) { ["gru"] = healthy },
            directory.Snapshot(now),
            new Dictionary<string, NatsGatewaysObservation>(StringComparer.Ordinal)
            {
                ["gru"] = NatsGatewaysObservation.Observe("gru", 2, 0, now)
            },
            now);
        await Assert.That(healthyMesh.HealthyCells).IsEqualTo(1);
    }

    [Test]
    public async Task Aggregate_validation_rejects_duplicate_class_entries_and_negative_values()
    {
        var now = DateTimeOffset.UtcNow;
        var valid = Aggregate(now, NatsMonitoringAvailability.Available);
        valid.Validate();

        var duplicateStream = valid with
        {
            StreamsByClass =
            [
                new NatsStreamClassState(NatsStreamClass.CellEvents, 1, 1, 1, 0),
                new NatsStreamClassState(NatsStreamClass.CellEvents, 1, 1, 1, 0)
            ]
        };
        await Assert.That(() => duplicateStream.Validate()).Throws<InvalidOperationException>();

        var negative = valid with { Connections = -1 };
        await Assert.That(() => negative.Validate()).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Snapshot_projection_is_bounded_and_omits_series_the_source_did_not_report()
    {
        var now = DateTimeOffset.UtcNow;
        var aggregate = Aggregate(now, NatsMonitoringAvailability.Available) with
        {
            Certificates =
            [
                NatsCertificateObservation.Observe("gru", NatsCertificateClass.MonitoringClient, now.AddDays(45), now)
            ]
        };
        var snapshot = NatsMonitoringSnapshot.From(aggregate);
        snapshot.Validate();

        await Assert.That(snapshot.Entries.Select(static entry => entry.Instrument).Distinct())
            .Contains("terrascale.orchestrator.nats.consumer.lag");
        await Assert.That(snapshot.Entries.All(static entry => entry.Labels.Values.All(static value =>
                value.Length <= NatsMonitoringSnapshotEntry.MaximumLabelValueLength)))
            .IsTrue();
        var certificate = snapshot.Entries.Single(entry =>
            entry.Instrument == "terrascale.orchestrator.nats.certificate.expiry.days");
        await Assert.That(certificate.Value).IsEqualTo(45);
        await Assert.That(certificate.Labels["certificate_class"]).IsEqualTo("monitoringclient");

        // Unavailable monitoring serves only its truthful availability entry —
        // never stale zero-filled series.
        var unavailable = NatsMonitoringSnapshot.From(Aggregate(now, NatsMonitoringAvailability.Unavailable));
        unavailable.Validate();
        await Assert.That(unavailable.Entries).HasSingleItem();
        await Assert.That(unavailable.Entries[0].Instrument)
            .IsEqualTo("terrascale.orchestrator.nats.monitoring.availability");

        var prometheus = snapshot.RenderPrometheus();
        await Assert.That(prometheus).Contains("terrascale.orchestrator.nats.streams{");
        await Assert.That(prometheus).Contains("# unit {message} source");
        await Assert.That(NatsMonitoringRedaction.ContainsSecretMaterial(prometheus)).IsFalse();
    }

    private static RegionalRuntimeMembershipHealth Membership(string cell, DateTimeOffset now) => new(
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
        now);

    private static GlobalCellAdvertisement Advertise(
        string cell,
        RegionalRuntimeMembershipHealth membership,
        DateTimeOffset observedAt) => new(
        1,
        cell,
        $"orchestrator-control-{cell}",
        $"{cell}-regional",
        12,
        34,
        1,
        ["authority", "regional-membership", "service-discovery"],
        membership,
        observedAt,
        observedAt + GlobalCellAdvertisement.SemanticLease,
        ["https://gru.terrascale.invalid:18670"]);

    private static NatsMonitoringAggregate Aggregate(DateTimeOffset observedAt, NatsMonitoringAvailability availability) => new(
        NatsMonitoringAggregate.CurrentSchemaVersion,
        "gru",
        NatsMonitoringPlane.Control,
        NatsClusterRole.Regional,
        observedAt,
        availability,
        NatsMeshHealth.Evaluate(
            ["gru", "sfo", "fra"],
            new Dictionary<string, RegionalRuntimeMembershipHealth>(StringComparer.Ordinal),
            new GlobalCellDirectorySnapshot(1, observedAt, 0, 0, 0, GlobalCellDirectoryCondition.Unavailable, []),
            new Dictionary<string, NatsGatewaysObservation>(StringComparer.Ordinal),
            observedAt),
        3,
        1,
        2,
        5,
        1,
        1,
        1,
        1048576,
        2097152,
        0,
        0,
        [new NatsStreamClassState(NatsStreamClass.CellEvents, 1, 12, 3400, 0)],
        [new NatsConsumerClassState(NatsStreamClass.CellEvents, NatsConsumerClass.StartupEvent, 1, 3, 9, 2, 1, 0)],
        [new NatsStoreClassState(NatsStoreClass.KeyValue, 1, 2, 0, 0), new NatsStoreClassState(NatsStoreClass.ObjectStore, 1, 0, 3, 3000)],
        [new NatsAdvisoryCount(NatsAdvisoryKind.SlowConsumer, 2)],
        []);
}
