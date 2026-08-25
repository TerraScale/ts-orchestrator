using NATS.Client.JetStream;
using NATS.Client.JetStream.Models;

namespace TerraScale.Orchestrator.Messaging;

internal sealed record CiRunnerConsumerRegistration(
    string Zone,
    string Consumer,
    string Subject);

/// <summary>
/// Reconciles controller-owned runner consumers before any runner identity can be issued.
/// </summary>
internal sealed class CiRunnerConsumerReconciler
{
    private readonly INatsJSContext jetStream;
    private readonly GlobalNatsTopology topology;

    internal CiRunnerConsumerReconciler(INatsJSContext jetStream, GlobalNatsTopology topology)
    {
        this.jetStream = jetStream ?? throw new ArgumentNullException(nameof(jetStream));
        this.topology = topology ?? throw new ArgumentNullException(nameof(topology));
    }

    internal async Task<CiRunnerConsumerRegistration> ReconcileAsync(
        string zone,
        string runner,
        CancellationToken cancellationToken = default)
    {
        var expected = topology.CiJobConsumer(zone, runner);
        if (expected.Name is not { Length: > 0 } expectedName)
            throw new InvalidOperationException("NATS returned a CI runner consumer without a name.");
        if (expected.FilterSubject is not { Length: > 0 } expectedFilterSubject)
            throw new InvalidOperationException("NATS returned a CI runner consumer without a filter subject.");
        var consumer = await jetStream.CreateOrUpdateConsumerAsync(
            GlobalNatsTopology.CiStream,
            expected,
            cancellationToken);
        await consumer.RefreshAsync(cancellationToken);
        if (!Matches(consumer.Info, expected))
            throw new InvalidOperationException(
                $"NATS returned an unsafe CI runner consumer configuration for {expectedName}.");

        return new(zone, expectedName, expectedFilterSubject);
    }

    internal static bool Matches(
        ConsumerInfo observed,
        ConsumerConfig expected,
        string expectedStream = GlobalNatsTopology.CiStream)
    {
        ArgumentNullException.ThrowIfNull(observed);
        ArgumentNullException.ThrowIfNull(expected);
        if (expected.Name is not { Length: > 0 } expectedName ||
            expected.FilterSubject is not { Length: > 0 } expectedFilterSubject)
            return false;
        var actual = observed.Config;
        return observed.StreamName == expectedStream &&
               observed.Name == expectedName &&
               !observed.IsPaused &&
               !observed.PushBound &&
               actual.Name == expectedName &&
               actual.DurableName == expected.DurableName &&
               actual.Description == expected.Description &&
               actual.DeliverPolicy == expected.DeliverPolicy &&
               actual.OptStartSeq == expected.OptStartSeq &&
               actual.OptStartTime == expected.OptStartTime &&
               actual.DeliverSubject is null &&
               actual.DeliverGroup is null &&
               actual.AckPolicy == expected.AckPolicy &&
               actual.AckWait == expected.AckWait &&
               actual.MaxDeliver == expected.MaxDeliver &&
               actual.FilterSubject == expectedFilterSubject &&
               IsEmpty(actual.FilterSubjects) &&
               actual.ReplayPolicy == expected.ReplayPolicy &&
               actual.SampleFreq is null &&
               actual.RateLimitBps == expected.RateLimitBps &&
               actual.MaxAckPending == expected.MaxAckPending &&
               actual.IdleHeartbeat == expected.IdleHeartbeat &&
               actual.FlowControl == expected.FlowControl &&
               actual.MaxWaiting == expected.MaxWaiting &&
               actual.Direct == expected.Direct &&
               actual.HeadersOnly == expected.HeadersOnly &&
               actual.MaxBatch == expected.MaxBatch &&
               actual.MaxExpires == expected.MaxExpires &&
               actual.MaxBytes == expected.MaxBytes &&
               actual.InactiveThreshold == expected.InactiveThreshold &&
               Same(actual.Backoff, expected.Backoff) &&
               actual.NumReplicas == expected.NumReplicas &&
               actual.PauseUntil is null &&
               actual.MemStorage == expected.MemStorage &&
               IsEmpty(actual.PriorityGroups) &&
               actual.PriorityPolicy is null &&
               actual.PinnedTTL is null;
    }

    private static bool IsEmpty<T>(ICollection<T>? values) => values is null or { Count: 0 };

    private static bool Same<T>(ICollection<T>? actual, ICollection<T>? expected) =>
        actual is null ? expected is null : expected is not null && actual.SequenceEqual(expected);
}
