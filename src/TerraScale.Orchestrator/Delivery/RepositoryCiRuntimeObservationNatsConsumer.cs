using NATS.Client.JetStream;
using NATS.Client.JetStream.Models;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Delivery;

internal sealed record RepositoryCiRuntimeObservationMessageMetadata(
    string Subject,
    string Stream,
    string Consumer,
    ulong StreamSequence,
    ulong ConsumerSequence,
    ulong DeliveryCount,
    int MessageSize);

/// <summary>
/// Lets only the current global leader verify and persist signed matching-architecture proofs,
/// then double-acknowledges the exact JetStream delivery after its durable pointer wins.
/// </summary>
internal sealed class RepositoryCiRuntimeObservationNatsConsumer : IAsyncDisposable
{
    private static readonly TimeSpan FollowerDelay = TimeSpan.FromSeconds(1);
    private readonly INatsJSConsumer consumer;
    private readonly RepositoryCiRuntimeObservationInbox inbox;
    private readonly Func<RegionalAuthoritySnapshot> authority;
    private readonly ConsumerConfig configuration;
    private readonly CancellationTokenSource stopping = new();
    private readonly Task loop;

    private RepositoryCiRuntimeObservationNatsConsumer(
        INatsJSConsumer consumer,
        RepositoryCiRuntimeObservationInbox inbox,
        Func<RegionalAuthoritySnapshot> authority,
        GlobalNatsTopology topology)
    {
        this.consumer = consumer ?? throw new ArgumentNullException(nameof(consumer));
        this.inbox = inbox ?? throw new ArgumentNullException(nameof(inbox));
        this.authority = authority ?? throw new ArgumentNullException(nameof(authority));
        ArgumentNullException.ThrowIfNull(topology);
        configuration = topology.CiRuntimeProofConsumer;
        loop = RunAsync(stopping.Token);
    }

    public Task Completion => loop;

    internal static RepositoryCiRuntimeObservationNatsConsumer Start(
        INatsJSConsumer consumer,
        RepositoryCiRuntimeObservationInbox inbox,
        Func<RegionalAuthoritySnapshot> authority,
        GlobalNatsTopology topology) => new(consumer, inbox, authority, topology);

    private async Task RunAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            var lease = authority();
            if (!Ready(lease))
            {
                await Task.Delay(FollowerDelay, cancellationToken);
                continue;
            }
            var message = await consumer.NextAsync<byte[]>(
                opts: new NatsJSNextOpts { Expires = TimeSpan.FromSeconds(1) },
                cancellationToken: cancellationToken);
            if (message is null) continue;
            message.EnsureSuccess();
            var metadata = message.Metadata;
            if (message.Data is null || metadata is not { } observed ||
                !ValidMetadata(new(
                    message.Subject,
                    observed.Stream,
                    observed.Consumer,
                    observed.Sequence.Stream,
                    observed.Sequence.Consumer,
                    observed.NumDelivered,
                    message.Size), configuration))
                continue;

            bool StillValid() => RepositoryCiController.SameAuthority(lease, authority());
            var receipt = await inbox.HandleAsync(
                message.Data,
                lease.Epoch,
                lease.KvRevision,
                StillValid,
                cancellationToken);
            if (receipt.CanAcknowledge)
            {
                await message.AckAsync(
                    new AckOpts { DoubleAck = true },
                    cancellationToken: cancellationToken);
                continue;
            }
            if (receipt.Disposition == RepositoryCiRuntimeObservationInboxDisposition.IdentityConflict)
                throw new InvalidDataException("A native runtime proof conflicts with its durable subject.");
            await Task.Delay(FollowerDelay, cancellationToken);
        }
    }

    internal static bool ValidMetadata(
        RepositoryCiRuntimeObservationMessageMetadata metadata,
        ConsumerConfig configuration) =>
        metadata.Subject == configuration.FilterSubject &&
        metadata.Stream == GlobalNatsTopology.CiStream &&
        metadata.Consumer == configuration.Name &&
        metadata.StreamSequence > 0 && metadata.ConsumerSequence > 0 &&
        configuration.MaxDeliver > 0 && metadata.DeliveryCount is > 0 &&
        metadata.DeliveryCount <= (ulong)configuration.MaxDeliver &&
        metadata.MessageSize is > 0 and <= RepositoryCiRuntimeObservationWireCodec.MaximumWireBytes;

    private static bool Ready(RegionalAuthoritySnapshot value) =>
        value.Ready && value.IsLeader && value.Epoch > 0 && value.KvRevision > 0;

    public async ValueTask DisposeAsync()
    {
        await stopping.CancelAsync();
        try
        {
            await loop;
        }
        catch (OperationCanceledException) when (stopping.IsCancellationRequested)
        {
        }
        stopping.Dispose();
    }
}
