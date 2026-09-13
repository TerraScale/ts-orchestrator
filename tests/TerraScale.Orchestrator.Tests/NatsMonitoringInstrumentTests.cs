using System.Diagnostics.Metrics;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Observability;
using TerraScale.Orchestrator.Protocol.Messaging;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Bounded-cardinality and catalog tests for the NATS monitoring instruments
/// (issue #23): every cataloged gauge actually exists on the live meter with only
/// bounded label keys and values, the push counters carry only the bounded endpoint
/// and class dimensions, no instance/session/NKey/message/operation identity can
/// become a label, and the alert rules are actionable with explicit recovery.
/// </summary>
public sealed class NatsMonitoringInstrumentTests
{
    [Test]
    public async Task Every_cataloged_gauge_exists_on_the_meter_with_bounded_labels_only()
    {
        var measurements = new List<MetricMeasurement>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, meterListener) =>
        {
            if (instrument.Meter.Name == OrchestratorTelemetry.InstrumentationName &&
                instrument.Name.StartsWith("terrascale.orchestrator.nats.", StringComparison.Ordinal))
                meterListener.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<long>((instrument, value, tags, _) =>
        {
            var copied = new Dictionary<string, object?>(StringComparer.Ordinal);
            foreach (var tag in tags) copied.Add(tag.Key, tag.Value);
            measurements.Add(new(instrument.Name, value, copied));
        });
        listener.Start();
        using var telemetry = OrchestratorTelemetry.Start(new(
            OrchestratorCommand.Check,
            "gru",
            "nats://127.0.0.1:4222",
            3,
            Instance: "controller-1"), _ => null);
        var now = DateTimeOffset.UtcNow;
        telemetry.ObserveNats(() => Aggregate(now));
        listener.RecordObservableInstruments();

        var observed = measurements.Select(static measurement => measurement.Name).ToHashSet(StringComparer.Ordinal);
        var expectedGauges = NatsMonitoringInstrumentCatalog.Instruments
            .Where(static instrument => instrument.Kind != NatsMonitoringInstrumentKind.Counter &&
                                        instrument.Kind != NatsMonitoringInstrumentKind.Histogram)
            .Select(static instrument => instrument.Name)
            .ToHashSet(StringComparer.Ordinal);
        // Every cataloged gauge produced at least one measurement from the aggregate.
        await Assert.That(expectedGauges.Except(observed)).IsEmpty();

        foreach (var measurement in measurements)
        {
            foreach (var tag in measurement.Tags)
            {
                await Assert.That(NatsMonitoringLabels.IsAllowedLabelKey(tag.Key)).IsTrue();
                var value = tag.Value?.ToString();
                await Assert.That(value is null ||
                                  value.Length <= NatsMonitoringSnapshotEntry.MaximumLabelValueLength).IsTrue();
            }
            await Assert.That(measurements.SelectMany(static candidate => candidate.Tags.Keys)
                .Any(key => NatsMonitoringLabels.ForbiddenKeyFragments.Any(fragment =>
                    key.Contains(fragment, StringComparison.OrdinalIgnoreCase)))).IsFalse();
        }

        // Class series carry the bounded classification, not identities.
        var streams = measurements.Single(measurement =>
            measurement.Name == "terrascale.orchestrator.nats.streams" &&
            Equals(measurement.Tags["stream_class"], "cellevents"));
        await Assert.That(streams.Value).IsEqualTo(1);
        var lag = measurements.Single(measurement =>
            measurement.Name == "terrascale.orchestrator.nats.consumer.lag");
        await Assert.That(lag.Tags.Keys.OrderBy(static key => key, StringComparer.Ordinal))
            .IsEquivalentTo(["consumer_class", "plane", "stream_class", "terrascale.cell"]);
        await Assert.That(() => telemetry.ObserveNats(() => Aggregate(now)))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Push_counters_carry_only_bounded_endpoint_and_result_dimensions()
    {
        var measurements = new List<MetricMeasurement>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, meterListener) =>
        {
            if (instrument.Meter.Name == OrchestratorTelemetry.InstrumentationName &&
                instrument.Name.StartsWith("terrascale.orchestrator.nats.", StringComparison.Ordinal))
                meterListener.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<long>((instrument, value, tags, _) =>
        {
            var copied = new Dictionary<string, object?>(StringComparer.Ordinal);
            foreach (var tag in tags) copied.Add(tag.Key, tag.Value);
            measurements.Add(new(instrument.Name, value, copied));
        });
        listener.Start();
        using var telemetry = OrchestratorTelemetry.Start(new(
            OrchestratorCommand.Check,
            "gru",
            "nats://127.0.0.1:4222",
            3,
            Instance: "controller-1"), _ => null);

        telemetry.RecordNatsServiceRequest(NatsServiceEndpointName.Status, NatsServiceRequestResult.Ok, 12.5);
        telemetry.RecordNatsServiceRequest(NatsServiceEndpointName.Status, NatsServiceRequestResult.Ok, 30);
        telemetry.RecordNatsServiceRequest(NatsServiceEndpointName.Members, NatsServiceRequestResult.Error, 5);
        telemetry.RecordNatsMessages(NatsStreamClass.CellEvents, NatsConsumerClass.StartupEvent, "delivered", 7);
        telemetry.RecordNatsMessages(NatsStreamClass.CellEvents, NatsConsumerClass.StartupEvent, "redelivered", 2);
        telemetry.RecordNatsAdvisory(NatsAdvisoryKind.SlowConsumer);

        var requests = measurements.Where(measurement =>
            measurement.Name == "terrascale.orchestrator.nats.service.requests").ToArray();
        await Assert.That(requests.Sum(static measurement => measurement.Value)).IsEqualTo(3);
        var statusOk = requests.Where(measurement => Equals(measurement.Tags["endpoint"], "status")).ToArray();
        await Assert.That(statusOk.Sum(static measurement => measurement.Value)).IsEqualTo(2);
        await Assert.That(Equals(statusOk[0].Tags["service"], "terrascale-orchestrator")).IsTrue();
        await Assert.That(Equals(statusOk[0].Tags["result"], "ok")).IsTrue();
        var errors = measurements.Where(measurement =>
            measurement.Name == "terrascale.orchestrator.nats.service.errors");
        await Assert.That(errors.Sum(static measurement => measurement.Value)).IsEqualTo(1);
        var messages = measurements.Where(measurement =>
            measurement.Name == "terrascale.orchestrator.nats.messages");
        await Assert.That(messages.Sum(static measurement => measurement.Value)).IsEqualTo(9);
        var advisories = measurements.First(measurement =>
            measurement.Name == "terrascale.orchestrator.nats.advisories");
        await Assert.That(Equals(advisories.Tags["result"], "slowconsumer")).IsTrue();

        await Assert.That(measurements.SelectMany(static measurement => measurement.Tags.Keys)
            .All(NatsMonitoringLabels.IsAllowedLabelKey)).IsTrue();
    }

    [Test]
    public async Task The_catalog_and_alert_rules_are_complete_and_actionable()
    {
        await Assert.That(NatsMonitoringInstrumentCatalog.Instruments.Select(static instrument => instrument.Name)
            .Distinct(StringComparer.Ordinal).Count()).IsEqualTo(NatsMonitoringInstrumentCatalog.Instruments.Count);
        foreach (var instrument in NatsMonitoringInstrumentCatalog.Instruments)
        {
            await Assert.That(instrument.Unit).IsNotEmpty();
            await Assert.That(instrument.FailureBehavior).IsNotEmpty();
            await Assert.That(instrument.LabelKeys.All(NatsMonitoringLabels.IsAllowedLabelKey)).IsTrue();
            // Instruments sourced from NATS subjects reference allowlisted subjects only.
            foreach (var source in instrument.SourceSubjects)
                await Assert.That(
                    NatsMonitoringSubjects.IsMonitoringSubject(source) ||
                    source == NatsSubjectTaxonomy.GlobalDirectoryQuerySubject).IsTrue();
            await Assert.That(() => new NatsMonitoringInstrument(
                "unrooted.instrument", "{x}", NatsMonitoringInstrumentKind.Gauge, [], [], "n/a"))
                .Throws<ArgumentException>();
            await Assert.That(() => new NatsMonitoringInstrument(
                "terrascale.orchestrator.nats.bad", "{x}", NatsMonitoringInstrumentKind.Gauge,
                ["instance"], [], "n/a")).Throws<ArgumentException>();
        }

        await Assert.That(NatsAlertCatalog.Rules.Select(static rule => rule.Id)
            .Distinct(StringComparer.Ordinal).Count()).IsEqualTo(NatsAlertCatalog.Rules.Count);
        foreach (var rule in NatsAlertCatalog.Rules)
        {
            await Assert.That(rule.FiresWhen).IsNotEmpty();
            await Assert.That(rule.RecoveryWhen).IsNotEmpty();
            await Assert.That(rule.Runbook).IsNotEmpty();
            // Every rule is tied to catalog instruments and has a recovery state.
            await Assert.That(rule.InstrumentNames.All(name =>
                NatsMonitoringInstrumentCatalog.Instruments.Any(instrument => instrument.Name == name))).IsTrue();
        }
        // The actionable failure coverage the issue demands exists.
        await Assert.That(NatsAlertCatalog.Rules.Select(static rule => rule.Id)).Contains("nats.gateway.partition");
        await Assert.That(NatsAlertCatalog.Rules.Select(static rule => rule.Id)).Contains("nats.consumer.lag");
        await Assert.That(NatsAlertCatalog.Rules.Select(static rule => rule.Id)).Contains("nats.storage.pressure");
        await Assert.That(NatsAlertCatalog.Rules.Select(static rule => rule.Id)).Contains("nats.certificate.expiry.risk");
        await Assert.That(NatsAlertCatalog.Rules.Select(static rule => rule.Id)).Contains("nats.monitoring.unavailable");
    }

    [Test]
    public async Task Snapshot_entries_reject_unbounded_label_keys_and_values()
    {
        await Assert.That(() => new NatsMonitoringSnapshotEntry(
            "terrascale.orchestrator.nats.streams",
            "{stream}",
            new Dictionary<string, string>(StringComparer.Ordinal) { ["instance"] = "controller-1" },
            1)).Throws<ArgumentException>();
        // The cap matches the canonical cell rule: a 63-character DNS-style token
        // is legal, one character more is not.
        _ = new NatsMonitoringSnapshotEntry(
            "terrascale.orchestrator.nats.streams",
            "{stream}",
            new Dictionary<string, string>(StringComparer.Ordinal) { ["terrascale.cell"] = new string('a', 63) },
            1);
        await Assert.That(() => new NatsMonitoringSnapshotEntry(
            "terrascale.orchestrator.nats.streams",
            "{stream}",
            new Dictionary<string, string>(StringComparer.Ordinal) { ["terrascale.cell"] = new string('a', 64) },
            1)).Throws<ArgumentException>();
        await Assert.That(() => new NatsMonitoringSnapshotEntry(
            "not.cataloged",
            "{x}",
            new Dictionary<string, string>(StringComparer.Ordinal),
            1)).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Prometheus_rendering_escapes_format_critical_label_characters()
    {
        // A hostile label value carrying the three exposition-format-critical
        // characters must be escaped, never emitted raw: a raw quote or newline
        // would let one metric line forge another.
        var hostile = "a\\b\"c\nd";
        var snapshot = new NatsMonitoringSnapshot(
            NatsMonitoringSnapshot.CurrentSchemaVersion,
            "gru",
            DateTimeOffset.UtcNow,
            NatsMonitoringAvailability.Degraded,
            [
                new NatsMonitoringSnapshotEntry(
                    "terrascale.orchestrator.nats.gateways",
                    "{gateway}",
                    new Dictionary<string, string>(StringComparer.Ordinal)
                    {
                        ["terrascale.cell"] = "gru",
                        ["plane"] = "control",
                        ["state"] = hostile
                    },
                    1)
            ]);
        var rendered = snapshot.RenderPrometheus();
        await Assert.That(rendered).Contains("state=\"a\\\\b\\\"c\\nd\"");
        await Assert.That(rendered.Contains("state=\"a\\b\"c\nd\"")).IsFalse();
    }

    private static NatsMonitoringAggregate Aggregate(DateTimeOffset observedAt) => new(
        NatsMonitoringAggregate.CurrentSchemaVersion,
        "gru",
        NatsMonitoringPlane.Control,
        NatsClusterRole.Regional,
        observedAt,
        NatsMonitoringAvailability.Available,
        NatsMeshHealth.Evaluate(
            ["gru", "sfo", "fra"],
            new Dictionary<string, RegionalRuntimeMembershipHealth>(StringComparer.Ordinal),
            new GlobalCellDirectorySnapshot(1, observedAt, 0, 0, 0, GlobalCellDirectoryCondition.Unavailable, []),
            new Dictionary<string, NatsGatewaysObservation>(StringComparer.Ordinal)
            {
                ["gru"] = NatsGatewaysObservation.Observe("gru", 2, 0, observedAt)
            },
            observedAt),
        3,
        1,
        2,
        5,
        1,
        2,
        0,
        1048576,
        2097152,
        0,
        0,
        [new NatsStreamClassState(NatsStreamClass.CellEvents, 1, 12, 3400, 4)],
        [new NatsConsumerClassState(NatsStreamClass.CellEvents, NatsConsumerClass.StartupEvent, 1, 3, 9, 2, 1, 0)],
        [new NatsStoreClassState(NatsStoreClass.KeyValue, 1, 2, 0, 0), new NatsStoreClassState(NatsStoreClass.ObjectStore, 1, 0, 3, 3000)],
        [new NatsAdvisoryCount(NatsAdvisoryKind.SlowConsumer, 1)],
        [NatsCertificateObservation.Observe("gru", NatsCertificateClass.MonitoringClient, observedAt.AddDays(45), observedAt)]);

    private sealed record MetricMeasurement(
        string Name,
        long Value,
        IReadOnlyDictionary<string, object?> Tags);
}

