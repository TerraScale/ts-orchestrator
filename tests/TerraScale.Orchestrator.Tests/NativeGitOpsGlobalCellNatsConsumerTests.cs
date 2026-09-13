using Microsoft.Extensions.Primitives;
using NATS.Client.Core;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Protocol.Messaging;

namespace TerraScale.Orchestrator.Tests;

public sealed class NativeGitOpsGlobalCellNatsConsumerTests
{
    [Test]
    public async Task GlobalCellConsumerIsExactBoundedAndExplicitlyAcknowledged()
    {
        var topology = new GlobalNatsTopology(3);
        var consumer = topology.CellSpecConsumer("gru");

        await Assert.That(consumer.Name).IsEqualTo("gitops_global_cell_spec_gru");
        await Assert.That(consumer.DurableName).IsEqualTo(consumer.Name);
        await Assert.That(consumer.FilterSubject)
            .IsEqualTo(NatsSubjectTaxonomy.GlobalCellSpecSubject("gru"));
        await Assert.That(consumer.AckPolicy).IsEqualTo(NATS.Client.JetStream.Models.ConsumerConfigAckPolicy.Explicit);
        await Assert.That(consumer.AckWait).IsEqualTo(TimeSpan.FromSeconds(1));
        await Assert.That(consumer.MaxDeliver).IsEqualTo(5);
        await Assert.That(consumer.MaxAckPending).IsEqualTo(8);
        await Assert.That(consumer.MaxWaiting).IsEqualTo(8);
        await Assert.That(consumer.MaxBatch).IsEqualTo(1);
        await Assert.That(consumer.MaxExpires).IsEqualTo(TimeSpan.FromSeconds(30));
        await Assert.That(consumer.NumReplicas).IsEqualTo(3);
        await Assert.That(() => topology.CellSpecConsumer("bad.cell")).Throws<ArgumentException>();
    }

    [Test]
    public async Task GlobalCellMetadataRequiresExactStreamConsumerSubjectAndBounds()
    {
        var configuration = new GlobalNatsTopology(3).CellSpecConsumer("gru");
        var valid = new NativeGitOpsGlobalCellMessageMetadata(
            configuration.FilterSubject!,
            GlobalNatsTopology.CellSpecStream,
            configuration.Name!,
            41,
            1,
            1,
            NativeGitOpsCellWireCodec.MaximumWireBytes);

        await Assert.That(NativeGitOpsGlobalCellNatsConsumer.ValidMetadata(valid, configuration)).IsTrue();
        await Assert.That(NativeGitOpsGlobalCellNatsConsumer.ValidMetadata(
            valid with { Subject = GlobalNatsTopology.CellSpecSubject("sfo") }, configuration)).IsFalse();
        await Assert.That(NativeGitOpsGlobalCellNatsConsumer.ValidMetadata(
            valid with { Stream = "CELL_SPEC" }, configuration)).IsFalse();
        await Assert.That(NativeGitOpsGlobalCellNatsConsumer.ValidMetadata(
            valid with { Consumer = "gitops_global_cell_spec_sfo" }, configuration)).IsFalse();
        await Assert.That(NativeGitOpsGlobalCellNatsConsumer.ValidMetadata(
            valid with { StreamSequence = 0 }, configuration)).IsFalse();
        await Assert.That(NativeGitOpsGlobalCellNatsConsumer.ValidMetadata(
            valid with { ConsumerSequence = 0 }, configuration)).IsFalse();
        await Assert.That(NativeGitOpsGlobalCellNatsConsumer.ValidMetadata(
            valid with { DeliveryCount = 6 }, configuration)).IsFalse();
        await Assert.That(NativeGitOpsGlobalCellNatsConsumer.ValidMetadata(
            valid with { MessageSize = NativeGitOpsCellWireCodec.MaximumWireBytes + 1 },
            configuration)).IsFalse();
    }

    [Test]
    public async Task RepeatedHeadersRemainVisibleAndFlatteningIsBounded()
    {
        var repeated = new NatsHeaders
        {
            { "TS-Cell", new StringValues(["gru", "sfo"]) },
            { "TS-Protocol-Version", "1" },
        };
        var flattened = NativeGitOpsGlobalCellNatsConsumer.Flatten(repeated);
        var excessive = new NatsHeaders();
        for (var index = 0; index < 32; index++) excessive.Add($"X-{index}", index.ToString());

        await Assert.That(flattened.Count).IsEqualTo(3);
        await Assert.That(flattened.Count(item => item.Key == "TS-Cell")).IsEqualTo(2);
        await Assert.That(NativeGitOpsGlobalCellNatsConsumer.Flatten(excessive).Count).IsEqualTo(17);
    }
}

