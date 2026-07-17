using Microsoft.Extensions.Primitives;
using NATS.Client.Core;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

public sealed class NativeGitOpsCellNatsConsumerTests
{
    [Test]
    public async Task RegionalTopologyDefinesOneBoundedExplicitAckPullConsumer()
    {
        var topology = new NatsTopology("gru", 3, "controller-1");
        var consumer = topology.CellSpecConsumer;

        await Assert.That(topology.CellSpecSubject).IsEqualTo("ts.orch.v1.gru.desired.gitops");
        await Assert.That(consumer.Name).IsEqualTo("gitops_cell_spec_controller-1");
        await Assert.That(consumer.DurableName).IsEqualTo(consumer.Name);
        await Assert.That(consumer.FilterSubject).IsEqualTo(topology.CellSpecSubject);
        await Assert.That(consumer.AckWait).IsEqualTo(TimeSpan.FromSeconds(15));
        await Assert.That(consumer.MaxDeliver).IsEqualTo(5);
        await Assert.That(consumer.MaxAckPending).IsEqualTo(8);
        await Assert.That(consumer.MaxWaiting).IsEqualTo(8);
        await Assert.That(consumer.NumReplicas).IsEqualTo(3);
    }

    [Test]
    public async Task RepeatedNatsHeaderValuesRemainVisibleToStrictWireValidation()
    {
        var headers = new NatsHeaders
        {
            { "TS-Cell", new StringValues(["gru", "sfo"]) },
            { "TS-Protocol-Version", "1" },
        };

        var flattened = NativeGitOpsCellNatsConsumer.Flatten(headers);

        await Assert.That(flattened.Count).IsEqualTo(3);
        await Assert.That(flattened.Count(item => item.Key == "TS-Cell")).IsEqualTo(2);
        await Assert.That(string.Join(',', flattened.Select(static item => item.Value)))
            .IsEqualTo("gru,sfo,1");
    }

    [Test]
    public async Task HeaderFlatteningStopsAtOneBeyondTheClosedWireContract()
    {
        var headers = new NatsHeaders();
        for (var index = 0; index < 32; index++) headers.Add($"X-{index}", index.ToString());

        var flattened = NativeGitOpsCellNatsConsumer.Flatten(headers);

        await Assert.That(flattened.Count).IsEqualTo(17);
    }
}
