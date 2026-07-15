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
        await Assert.That(topology.StartupSubject).IsEqualTo("ts.orch.v1.gru.event.runtime.started");
        await Assert.That(topology.ProtocolObject).IsEqualTo("orchestrator-protocol-v1");
        await Assert.That(topology.ServiceName).IsEqualTo("terrascale_orchestrator");
        await Assert.That(topology.ServiceQueueGroup).IsEqualTo("orchestrator_gru");
        await Assert.That(topology.Streams).Count().IsEqualTo(3);
        await Assert.That(topology.Streams.Select(static stream => stream.NumReplicas).Distinct())
            .IsEquivalentTo([3]);
        await Assert.That(topology.Streams.Select(static stream => stream.Storage).Distinct())
            .IsEquivalentTo([NATS.Client.JetStream.Models.StreamConfigStorage.File]);
        await Assert.That(topology.StartupConsumer.FilterSubject).IsEqualTo(topology.StartupSubject);
        await Assert.That(topology.StartupConsumer.MaxAckPending).IsEqualTo(32);
        await Assert.That(topology.StartupConsumer.Backoff).Count().IsEqualTo(4);
        await Assert.That(topology.Leaders.NumberOfReplicas).IsEqualTo(3);
        await Assert.That(topology.Runtime.NumberOfReplicas).IsEqualTo(3);
        await Assert.That(topology.Runtime.History).IsEqualTo(2);
        await Assert.That(topology.Runtime.MaxAge).IsEqualTo(TimeSpan.FromMinutes(5));
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
