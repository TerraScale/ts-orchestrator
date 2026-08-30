using Microsoft.Extensions.Primitives;
using NATS.Client.Core;
using NATS.Net;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Protocol.Messaging;

namespace TerraScale.Orchestrator.Tests;

public sealed class NativeGitOpsCellNatsConsumerTests
{
    [Test]
    public async Task InfrastructureProvisionedRegionalConsumerIsExactAndControllerCannotCreateIt()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var fixture = await NatsControlR3L0cFixture.StartAsync();
        await fixture.ProvisionAsync();
        await using var controller = await fixture.ConnectAsync(fixture.Controller);
        var expected = fixture.Topology.CellSpecConsumer;
        var jetStream = controller.CreateJetStreamContext();
        var consumer = await jetStream.GetConsumerAsync("CELL_SPEC", expected.Name!);
        await consumer.RefreshAsync();

        await Assert.That(CiRunnerConsumerReconciler.Matches(
            consumer.Info, expected, "CELL_SPEC")).IsTrue();
        await Assert.That(async () => _ = await controller.RequestAsync<string, string>(
                $"$JS.API.CONSUMER.CREATE.CELL_SPEC.{expected.Name}", "{}"))
            .Throws<NatsException>();
    }

    [Test]
    public async Task RegionalTopologyDefinesOneBoundedExplicitAckPullConsumer()
    {
        var topology = new NatsTopology("gru", 3, "controller-1");
        var consumer = topology.CellSpecConsumer;

        await Assert.That(topology.CellSpecSubject)
            .IsEqualTo(NatsSubjectTaxonomy.CellSpecSubject("gru"));
        await Assert.That(consumer.Name).IsEqualTo("gitops_cell_spec_controller-1");
        await Assert.That(consumer.DurableName).IsEqualTo(consumer.Name);
        await Assert.That(consumer.FilterSubject).IsEqualTo(topology.CellSpecSubject);
        await Assert.That(consumer.DeliverPolicy)
            .IsEqualTo(NATS.Client.JetStream.Models.ConsumerConfigDeliverPolicy.All);
        await Assert.That(consumer.AckPolicy)
            .IsEqualTo(NATS.Client.JetStream.Models.ConsumerConfigAckPolicy.Explicit);
        await Assert.That(consumer.ReplayPolicy)
            .IsEqualTo(NATS.Client.JetStream.Models.ConsumerConfigReplayPolicy.Instant);
        await Assert.That(consumer.AckWait).IsEqualTo(TimeSpan.FromSeconds(1));
        await Assert.That(consumer.MaxDeliver).IsEqualTo(5);
        await Assert.That(consumer.MaxAckPending).IsEqualTo(8);
        await Assert.That(consumer.MaxWaiting).IsEqualTo(8);
        await Assert.That(consumer.MaxBatch).IsEqualTo(1);
        await Assert.That(consumer.MaxExpires).IsEqualTo(TimeSpan.FromSeconds(30));
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
