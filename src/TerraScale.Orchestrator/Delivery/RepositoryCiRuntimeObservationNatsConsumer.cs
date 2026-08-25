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
    private readonly bool enabled;
    private readonly CancellationTokenSource stopping = new();
    private readonly Task loop;

    private RepositoryCiRuntimeObservationNatsConsumer(
        INatsJSConsumer consumer,
        RepositoryCiRuntimeObservationInbox inbox,
        Func<RegionalAuthoritySnapshot> authority,
        GlobalNatsTopology topology,
        bool enabled)
    {
        this.consumer = consumer ?? throw new ArgumentNullException(nameof(consumer));
        this.inbox = inbox ?? throw new ArgumentNullException(nameof(inbox));
        this.authority = authority ?? throw new ArgumentNullException(nameof(authority));
        ArgumentNullException.ThrowIfNull(topology);
        configuration = topology.CiRuntimeProofConsumer;
        this.enabled = enabled;
        loop = RunAsync(stopping.Token);
    }

    public Task Completion => loop;

    internal static RepositoryCiRuntimeObservationNatsConsumer Start(
        INatsJSConsumer consumer,
        RepositoryCiRuntimeObservationInbox inbox,
        Func<RegionalAuthoritySnapshot> authority,
        GlobalNatsTopology topology,
        bool enabled = true) => new(consumer, inbox, authority, topology, enabled);

    private async Task RunAsync(CancellationToken cancellationToken)
    {
        if (!enabled)
        {
            // Check mode: never durably consume runtime proofs. A Check-mode leader must not
            // fetch, persist, or acknowledge proof deliveries — that is Run-mode work.
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return;
        }
        while (!cancellationToken.IsCancellationRequested)
        {
            // One delivery at a time; a throwing inbox must never poison the loop or silently
            // burn the delivery budget of a message this consumer still owns.
            try
            {
                await ConsumeOnceAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception)
            {
                await Task.Delay(FollowerDelay, cancellationToken);
            }
        }
    }

    private async Task ConsumeOnceAsync(CancellationToken cancellationToken)
    {
        var lease = authority();
        if (!Ready(lease))
        {
            await Task.Delay(FollowerDelay, cancellationToken);
            return;
        }
        var message = await consumer.NextAsync<byte[]>(
            opts: new NatsJSNextOpts { Expires = TimeSpan.FromSeconds(1) },
            cancellationToken: cancellationToken);
        if (message is null) return;
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
        {
            // Invalid framing is deterministic: redelivery can never succeed, so terminate the
            // delivery instead of burning MaxDeliver silently. Terminations are loud: an
            // operator-visible decision, never a silent drop.
            Console.Error.WriteLine(
                $"CI runtime proof terminated after invalid message framing (subject {message.Subject}).");
            await message.AckTerminateAsync(cancellationToken: cancellationToken);
            return;
        }

        bool StillValid() => RepositoryCiController.SameAuthority(lease, authority());
        RepositoryCiRuntimeObservationInboxReceipt receipt;
        try
        {
            receipt = await inbox.HandleAsync(
                message.Data,
                lease.Epoch,
                lease.KvRevision,
                StillValid,
                cancellationToken);
        }
        catch (JournalRetentionOverflowException exception)
        {
            // Operational, never payload — parity with the CI event consumer: the durable proof
            // history exceeded its cap with unprunable records. The proof delivery itself is
            // healthy, so it is retried (loudly) until the operator raises the cap or the
            // bounded-age horizon passes; terminating would silently discard every future proof.
            Console.Error.WriteLine(
                $"CI proof journal retention over capacity; delivery left pending: {exception.Message}");
            await message.NakAsync(delay: FollowerDelay, cancellationToken: cancellationToken);
            return;
        }
        catch (InvalidDataException exception) when (HasRetentionOverflowCause(exception))
        {
            // The overflow surfaced wrapped in a durable-conflict-shaped exception (nested by
            // the journal layer): still operational, still retry-loudly, never terminate.
            var overflowMessage = OverflowCauseMessage(exception);
            Console.Error.WriteLine(
                $"CI proof journal retention over capacity; delivery left pending: {overflowMessage}");
            await message.NakAsync(delay: FollowerDelay, cancellationToken: cancellationToken);
            return;
        }
        catch (InvalidDataException)
        {
            // Deterministic durable conflict: terminate rather than retry the same outcome.
            Console.Error.WriteLine(
                "CI runtime proof terminated after a deterministic durable conflict with its subject.");
            await message.AckTerminateAsync(cancellationToken: cancellationToken);
            return;
        }
        catch (Exception exception) when (exception is IOException or TimeoutException or
            NATS.Client.Core.NatsException or NATS.Client.JetStream.NatsJSException)
        {
            await message.NakAsync(delay: FollowerDelay, cancellationToken: cancellationToken);
            return;
        }
        if (receipt.CanAcknowledge)
        {
            await message.AckAsync(
                new AckOpts { DoubleAck = true },
                cancellationToken: cancellationToken);
            return;
        }
        if (receipt.Disposition == RepositoryCiRuntimeObservationInboxDisposition.IdentityConflict ||
            receipt.Disposition == RepositoryCiRuntimeObservationInboxDisposition.InvalidProof)
        {
            // Both outcomes are deterministic for this exact payload: the durable winner stays
            // and redelivery reproduces the same conflict, so terminate (loudly).
            Console.Error.WriteLine(
                $"CI runtime proof terminated with disposition {receipt.Disposition}: the durable winner stays.");
            await message.AckTerminateAsync(cancellationToken: cancellationToken);
            return;
        }
        await Task.Delay(FollowerDelay, cancellationToken);
    }

    /// <summary>True when the durable-conflict exception's cause is a retention-cap overflow.</summary>
    internal static bool HasRetentionOverflowCause(InvalidDataException exception)
    {
        for (var cause = exception.InnerException; cause is not null; cause = cause.InnerException)
            if (cause is JournalRetentionOverflowException) return true;
        return false;
    }

    /// <summary>The retention-overflow cause's message (the guard proved it exists).</summary>
    internal static string OverflowCauseMessage(InvalidDataException exception)
    {
        for (var cause = exception.InnerException; cause is not null; cause = cause.InnerException)
            if (cause is JournalRetentionOverflowException overflow) return overflow.Message;
        return "retention cap exceeded";
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
