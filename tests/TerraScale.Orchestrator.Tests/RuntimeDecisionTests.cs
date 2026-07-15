using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

public sealed class RuntimeDecisionTests
{
    [Test]
    public async Task ConfigurationBuildsCellScopedNatsTopology()
    {
        var values = new Dictionary<string, string?>
        {
            ["TS_ORCH_CELL"] = "gru",
            ["TS_ORCH_NATS_URL"] = "nats://nats.internal:4222",
            ["TS_ORCH_REPLICAS"] = "3"
        };

        var options = OrchestratorOptions.Parse(["check"], key => values.GetValueOrDefault(key));
        var topology = new NatsTopology(options.Cell, options.Replicas);

        await Assert.That(options.Command).IsEqualTo(OrchestratorCommand.Check);
        await Assert.That(topology.HealthSubject).IsEqualTo("ts.orch.v1.gru.query.health");
        await Assert.That(topology.Streams).Count().IsEqualTo(3);
        await Assert.That(topology.Streams.Select(static stream => stream.NumReplicas).Distinct())
            .IsEquivalentTo([3]);
        await Assert.That(topology.Leaders.NumberOfReplicas).IsEqualTo(3);
        await Assert.That(topology.Bundles.NumberOfReplicas).IsEqualTo(3);
    }

    [Test]
    [Arguments("GRU", "3")]
    [Arguments("gru.*", "3")]
    [Arguments("gru", "2")]
    public async Task ConfigurationRejectsUnsafeNatsValues(string cell, string replicas)
    {
        var values = new Dictionary<string, string?>
        {
            ["TS_ORCH_CELL"] = cell,
            ["TS_ORCH_REPLICAS"] = replicas
        };

        await Assert.That(() => OrchestratorOptions.Parse([], key => values.GetValueOrDefault(key)))
            .Throws<ArgumentException>();
    }
}
