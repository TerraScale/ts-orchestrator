using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Pure tests for the bounded service endpoint statistics model (issue #23):
/// request/error counting, p50/p95/p99 latency over the bounded reservoir, and the
/// read-only stats document contract.
/// </summary>
public sealed class NatsServiceEndpointStatsTests
{
    [Test]
    public async Task Recorder_counts_requests_and_errors_and_serves_bounded_percentiles()
    {
        var stats = new NatsServiceEndpointStats();
        // No traffic yet: an empty measurement is valid.
        await Assert.That(stats.Snapshot()).IsEmpty();

        foreach (var milliseconds in new[] { 5, 10, 20, 40, 80 })
            stats.Record(NatsServiceEndpointName.Status, NatsServiceRequestResult.Ok, TimeSpan.FromMilliseconds(milliseconds));
        stats.Record(NatsServiceEndpointName.Status, NatsServiceRequestResult.Error, TimeSpan.FromMilliseconds(100));
        stats.Record(NatsServiceEndpointName.Members, NatsServiceRequestResult.Ok, TimeSpan.FromMilliseconds(7));

        var snapshot = stats.Snapshot();
        await Assert.That(snapshot.Select(static measurement => measurement.Endpoint)
            .OrderBy(static endpoint => endpoint))
            .IsEquivalentTo([NatsServiceEndpointName.Members, NatsServiceEndpointName.Status]);

        var status = snapshot.Single(measurement => measurement.Endpoint == NatsServiceEndpointName.Status);
        status.Validate();
        await Assert.That(status.Requests).IsEqualTo(6);
        await Assert.That(status.Errors).IsEqualTo(1);
        await Assert.That(status.MinimumMilliseconds).IsEqualTo(5);
        await Assert.That(status.MaximumMilliseconds).IsEqualTo(100);
        await Assert.That(status.P50Milliseconds).IsEqualTo(20);
        await Assert.That(status.P99Milliseconds).IsEqualTo(100);
        await Assert.That(status.P50Milliseconds <= status.P95Milliseconds &&
                          status.P95Milliseconds <= status.P99Milliseconds).IsTrue();

        // The bounded endpoint domain is closed: unknown endpoints are rejected.
        await Assert.That(() => stats.Record((NatsServiceEndpointName)99, NatsServiceRequestResult.Ok, TimeSpan.Zero))
            .Throws<ArgumentOutOfRangeException>();
    }

    [Test]
    public async Task The_stats_document_is_bounded_and_validates()
    {
        var stats = new NatsServiceEndpointStats();
        stats.Record(NatsServiceEndpointName.Stats, NatsServiceRequestResult.Ok, TimeSpan.FromMilliseconds(3));
        var document = NatsServiceStatsDocument.Create(
            "gru",
            "terrascale-orchestrator/dev",
            2,
            healthy: true,
            DateTimeOffset.UtcNow,
            stats.Snapshot());
        document.Validate();
        await Assert.That(document.Service).IsEqualTo("terrascale_orchestrator_gru");
        await Assert.That(document.Endpoints).HasSingleItem();
        await Assert.That(document.Endpoints[0].Endpoint).IsEqualTo(NatsServiceEndpointName.Stats);

        await Assert.That(() => NatsServiceStatsDocument.Create(
            "gru",
            "v1",
            2,
            healthy: true,
            default,
            stats.Snapshot())).Throws<InvalidOperationException>();
        await Assert.That(() => NatsServiceStatsDocument.Create(
            "gru",
            "v1",
            2,
            healthy: true,
            DateTimeOffset.UtcNow,
            [
                new NatsServiceEndpointMeasurement(NatsServiceEndpointName.Stats, 1, 0, 0, 0, 0, 0, 0),
                new NatsServiceEndpointMeasurement(NatsServiceEndpointName.Stats, 1, 0, 0, 0, 0, 0, 0)
            ])).Throws<InvalidOperationException>();
        // Errors can never exceed requests and percentiles stay ordered.
        await Assert.That(() => new NatsServiceEndpointMeasurement(
            NatsServiceEndpointName.Stats, 1, 2, 0, 0, 0, 0, 0).Validate())
            .Throws<InvalidOperationException>();
        await Assert.That(() => new NatsServiceEndpointMeasurement(
            NatsServiceEndpointName.Stats, 10, 0, 5, 20, 10, 5, 4).Validate())
            .Throws<InvalidOperationException>();
    }
}

