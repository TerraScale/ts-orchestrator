using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Pure supervision tests (issue #23): advisory loss and monitoring unavailability
/// degrade observability truthfully — available, degraded, then unavailable with the
/// last observation age — while regional control continues in every state, because
/// supervision holds no capability that could gate it.
/// </summary>
public sealed class NatsMonitoringSupervisionTests
{
    [Test]
    public async Task Fresh_observations_are_available_and_aging_observations_degrade_truthfully()
    {
        var now = DateTimeOffset.UtcNow;

        await Assert.That(NatsMonitoringSupervision.Availability(now, 0, now))
            .IsEqualTo(NatsMonitoringAvailability.Available);
        await Assert.That(NatsMonitoringSupervision.Availability(now - TimeSpan.FromSeconds(10), 0, now))
            .IsEqualTo(NatsMonitoringAvailability.Available);

        // One failed round with a recent observation degrades.
        await Assert.That(NatsMonitoringSupervision.Availability(now, 1, now))
            .IsEqualTo(NatsMonitoringAvailability.Degraded);
        await Assert.That(NatsMonitoringSupervision.Availability(now - TimeSpan.FromSeconds(60), 0, now))
            .IsEqualTo(NatsMonitoringAvailability.Degraded);

        // Beyond the trust window the signal reports unavailable instead of
        // stale-serving numbers.
        await Assert.That(NatsMonitoringSupervision.Availability(now - TimeSpan.FromMinutes(5), 0, now))
            .IsEqualTo(NatsMonitoringAvailability.Unavailable);
        await Assert.That(NatsMonitoringSupervision.Availability(null, 3, now))
            .IsEqualTo(NatsMonitoringAvailability.Unavailable);

        // Before the first successful observation nothing is healthy: starting
        // without a failure is degraded (no data yet), never available.
        await Assert.That(NatsMonitoringSupervision.Availability(null, 0, now))
            .IsEqualTo(NatsMonitoringAvailability.Degraded);

        await Assert.That(() => NatsMonitoringSupervision.Availability(now, -1, now))
            .Throws<ArgumentOutOfRangeException>();
    }

    [Test]
    public async Task Every_supervision_state_leaves_regional_control_continuing()
    {
        foreach (var action in Enum.GetValues<NatsMonitoringSupervisionAction>())
            await Assert.That(NatsMonitoringSupervision.RegionalControlContinues(action)).IsTrue();

        // The supervision decision is a pure function of freshness and failure count:
        // it exposes no capability that could delay, gate, or fail control paths.
        var transitions = new[]
        {
            NatsMonitoringSupervisionAction.Continue,
            NatsMonitoringSupervisionAction.MarkDegraded,
            NatsMonitoringSupervisionAction.MarkUnavailable
        };
        await Assert.That(transitions.Length).IsEqualTo(Enum.GetValues<NatsMonitoringSupervisionAction>().Length);
    }

    [Test]
    public async Task Degraded_aggregates_hold_last_values_and_unavailable_aggregates_report_only_availability()
    {
        var now = DateTimeOffset.UtcNow;
        var aggregate = TestAggregate(now, NatsMonitoringAvailability.Degraded);
        aggregate.Validate();
        var degradedSnapshot = NatsMonitoringSnapshot.From(aggregate);
        await Assert.That(degradedSnapshot.Entries.Select(static entry => entry.Instrument))
            .Contains("terrascale.orchestrator.nats.connections");

        var unavailable = NatsMonitoringSnapshot.From(TestAggregate(now, NatsMonitoringAvailability.Unavailable));
        await Assert.That(unavailable.Entries).HasSingleItem();
        await Assert.That(unavailable.Entries[0].Labels["condition"]).IsEqualTo("unavailable");
    }

    private static NatsMonitoringAggregate TestAggregate(DateTimeOffset observedAt, NatsMonitoringAvailability availability) => new(
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
        2,
        0,
        1048576,
        2097152,
        0,
        0,
        [],
        [],
        [],
        [],
        []);
}
