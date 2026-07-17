using Microsoft.Extensions.Primitives;
using NATS.Client.Core;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

public sealed class RepositoryCiJobNatsConsumerTests
{
    [Test]
    public async Task RunnerMetadataRequiresTheExactConsumerStreamSubjectAndBounds()
    {
        var configuration = new GlobalNatsTopology(3)
            .CiJobConsumer("untrusted-product", "runner-static");
        var valid = new RepositoryCiJobMessageMetadata(
            configuration.FilterSubject!,
            GlobalNatsTopology.CiStream,
            configuration.Name!,
            41,
            1,
            1,
            RepositoryCiJobWireCodec.MaximumWireBytes);

        await Assert.That(RepositoryCiJobNatsConsumer.ValidMetadata(valid, configuration)).IsTrue();
        await Assert.That(RepositoryCiJobNatsConsumer.ValidMetadata(
            valid with { Subject = GlobalNatsTopology.CiJobSubject("untrusted-product", "runner-other") },
            configuration)).IsFalse();
        await Assert.That(RepositoryCiJobNatsConsumer.ValidMetadata(
            valid with { Stream = "GLOBAL_SPEC" }, configuration)).IsFalse();
        await Assert.That(RepositoryCiJobNatsConsumer.ValidMetadata(
            valid with { Consumer = "ci_runner_other" }, configuration)).IsFalse();
        await Assert.That(RepositoryCiJobNatsConsumer.ValidMetadata(
            valid with { StreamSequence = 0 }, configuration)).IsFalse();
        await Assert.That(RepositoryCiJobNatsConsumer.ValidMetadata(
            valid with { ConsumerSequence = 0 }, configuration)).IsFalse();
        await Assert.That(RepositoryCiJobNatsConsumer.ValidMetadata(
            valid with { DeliveryCount = 6 }, configuration)).IsFalse();
        await Assert.That(RepositoryCiJobNatsConsumer.ValidMetadata(
            valid with { MessageSize = RepositoryCiJobWireCodec.MaximumWireBytes + 1 },
            configuration)).IsFalse();
    }

    [Test]
    public async Task RepeatedHeadersRemainVisibleAndFlatteningStopsAtOneBeyondTheContract()
    {
        var repeated = new NatsHeaders
        {
            { "TS-Runner-Id", new StringValues(["runner-static", "runner-other"]) },
            { "TS-Protocol-Version", "1" },
        };
        var flattened = RepositoryCiJobNatsConsumer.Flatten(repeated);
        var excessive = new NatsHeaders();
        for (var index = 0; index < 32; index++) excessive.Add($"X-{index}", index.ToString());
        var bounded = RepositoryCiJobNatsConsumer.Flatten(excessive);

        await Assert.That(flattened.Count).IsEqualTo(3);
        await Assert.That(flattened.Count(item => item.Key == "TS-Runner-Id")).IsEqualTo(2);
        await Assert.That(bounded.Count).IsEqualTo(RepositoryCiJobWireCodec.ExpectedHeaderCount + 1);
    }
}
