using NATS.Client.JetStream.Models;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

public sealed class CiRunnerConsumerReconcilerTests
{
    [Test]
    public async Task ExactPullConsumerReadbackIsAccepted()
    {
        var topology = new GlobalNatsTopology(3);
        var expected = topology.CiJobConsumer("untrusted-product", "runner-static");
        var observed = Observed(expected);

        await Assert.That(CiRunnerConsumerReconciler.Matches(observed, expected)).IsTrue();
    }

    [Test]
    public async Task AlteredOrBroadenedConsumerReadbackFailsClosed()
    {
        var topology = new GlobalNatsTopology(3);
        var expected = topology.CiJobConsumer("trusted-build", "runner-static");
        var invalid = new[]
        {
            Observed(expected) with { StreamName = "OTHER" },
            Observed(expected) with { Name = "other" },
            Observed(expected) with { IsPaused = true },
            Observed(expected) with { PushBound = true },
            With(expected, configuration => configuration.FilterSubject = "ts.orch.v1.global.ci.job.>"),
            With(expected, configuration => configuration.FilterSubjects = [expected.FilterSubject!, ">"]),
            With(expected, configuration => configuration.DeliverSubject = "runner.push"),
            With(expected, configuration => configuration.AckPolicy = ConsumerConfigAckPolicy.None),
            With(expected, configuration => configuration.MaxAckPending = 2),
            With(expected, configuration => configuration.MaxBatch = 2),
            With(expected, configuration => configuration.NumReplicas = 1),
        };

        foreach (var observed in invalid)
            await Assert.That(CiRunnerConsumerReconciler.Matches(observed, expected)).IsFalse();
    }

    private static ConsumerInfo With(ConsumerConfig expected, Action<ConsumerConfig> change)
    {
        var observed = Observed(expected);
        change(observed.Config);
        return observed;
    }

    private static ConsumerInfo Observed(ConsumerConfig expected) => new()
    {
        StreamName = GlobalNatsTopology.CiStream,
        Name = expected.Name!,
        Config = expected with
        {
            Backoff = expected.Backoff?.ToArray(),
            FilterSubjects = expected.FilterSubjects?.ToArray(),
        },
        Created = DateTimeOffset.UnixEpoch,
    };
}

