using NATS.Client.Core;
using NATS.Net;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Supervision-boundary tests for the monitoring runtime (issue #23): a hostile
/// or unexpected round failure degrades observability truthfully and is retried —
/// the observation loop never dies from a round failure, and the diagnostic text
/// is sanitized. These use the runtime's internal round seam with an
/// never-connected client: no server is needed to prove the supervision
/// boundary, which is exactly the property under test.
/// </summary>
public sealed class NatsMonitoringRuntimeRoundTests
{
    [Test]
    public async Task A_throwing_round_degrades_and_is_retried_never_killing_the_loop()
    {
        var runtime = NewRuntime();
        runtime.CompleteRoundForTest(AvailableAggregate());

        // A hostile round fault (anything at all, not only transport errors) is
        // recorded as a failure and degrades availability; it must not escape.
        await runtime.TryRoundForTestAsync(_ => throw new InvalidOperationException("hostile"));
        await Assert.That(runtime.Current.Availability).IsEqualTo(NatsMonitoringAvailability.Degraded);
        await Assert.That(runtime.LastRoundError).Contains("InvalidOperationException");

        // The loop is still alive: a second failing round is recorded too...
        await runtime.TryRoundForTestAsync(_ => throw new InvalidOperationException("hostile again"));
        await Assert.That(runtime.Current.Availability).IsEqualTo(NatsMonitoringAvailability.Degraded);

        // ...and a later good round restores availability through the real commit
        // path — degraded-then-retry, not a dead loop.
        runtime.CompleteRoundForTest(AvailableAggregate());
        await Assert.That(runtime.Current.Availability).IsEqualTo(NatsMonitoringAvailability.Available);
        await Assert.That(runtime.LastRoundError).IsNull();
        await runtime.DisposeAsync();
    }

    [Test]
    public async Task Round_failure_diagnostics_are_sanitized_and_bounded()
    {
        var runtime = NewRuntime();
        runtime.CompleteRoundForTest(AvailableAggregate());

        const string jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N7LHERSL2pFp0.";
        await runtime.TryRoundForTestAsync(_ => throw new InvalidOperationException($"connect failed bearer {jwt}"));
        await Assert.That(runtime.LastRoundError).Contains(NatsMonitoringRedaction.RedactedPlaceholder);
        await Assert.That(runtime.LastRoundError!.Contains("eyJ", StringComparison.Ordinal)).IsFalse();
        await Assert.That(runtime.LastRoundError!.Length <= 256 + "InvalidOperationException: ".Length).IsTrue();
        await runtime.DisposeAsync();
    }

    [Test]
    public async Task Before_the_first_successful_round_nothing_reports_healthy()
    {
        var runtime = NewRuntime();
        // No successful observation yet: starting is degraded (no data yet), so a
        // consumer of Current cannot mistake a cold monitor for a healthy one.
        await Assert.That(runtime.Current.Availability).IsEqualTo(NatsMonitoringAvailability.Degraded);
        // And a failing cold monitor is unavailable, never healthy.
        await runtime.TryRoundForTestAsync(_ => throw new TimeoutException("cold"));
        await Assert.That(runtime.Current.Availability).IsEqualTo(NatsMonitoringAvailability.Unavailable);
        await runtime.DisposeAsync();
    }

    private static NatsMonitoringRuntime NewRuntime() => new(
        new NatsMonitoringRuntimeOptions(
            "nats://127.0.0.1:1",
            "gru",
            NatsMonitoringPlane.Control,
            NatsClusterRole.Regional,
            ["gru", "sfo", "fra"]),
        telemetry: null,
        directory: null,
        new NatsClient(new NatsOpts { Url = "nats://127.0.0.1:1" }));

    private static NatsMonitoringAggregate AvailableAggregate() => new(
        NatsMonitoringAggregate.CurrentSchemaVersion,
        "gru",
        NatsMonitoringPlane.Control,
        NatsClusterRole.Regional,
        DateTimeOffset.UtcNow,
        NatsMonitoringAvailability.Available,
        NatsMeshHealth.Evaluate(
            ["gru", "sfo", "fra"],
            new Dictionary<string, RegionalRuntimeMembershipHealth>(StringComparer.Ordinal),
            new GlobalCellDirectorySnapshot(1, DateTimeOffset.UtcNow, 0, 0, 0, GlobalCellDirectoryCondition.Unavailable, []),
            new Dictionary<string, NatsGatewaysObservation>(StringComparer.Ordinal),
            DateTimeOffset.UtcNow),
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

