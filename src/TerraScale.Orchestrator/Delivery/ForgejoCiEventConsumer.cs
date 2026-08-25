using NATS.Client.JetStream;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Delivery;

/// <summary>The bounded outcome the CI event consumer derives from one processing attempt.</summary>
internal enum ForgejoCiEventProcessDisposition
{
    /// <summary>Work completed (or nothing was required): acknowledge the delivery.</summary>
    Handled,
    /// <summary>Progress is possible later: negatively acknowledge with a redelivery delay.</summary>
    Retry,
    /// <summary>Deterministic permanent outcome recorded durably: terminate the delivery.</summary>
    Terminal,
}

internal sealed class ForgejoCiEventConsumer : IAsyncDisposable
{
    private static readonly TimeSpan FollowerDelay = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan ProgressInterval = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan RetryDelay = TimeSpan.FromSeconds(2);
    private readonly INatsJSConsumer consumer;
    private readonly ForgejoCiInboxHandler handler;
    private readonly Func<RegionalAuthoritySnapshot> authority;
    private readonly Func<ForgejoCiTriggerPlan, CancellationToken, Task<ForgejoCiEventProcessDisposition>>? process;
    private readonly bool enabled;
    private readonly CancellationTokenSource stopping = new();
    private readonly Task loop;

    private ForgejoCiEventConsumer(
        INatsJSConsumer consumer,
        ForgejoCiInboxHandler handler,
        Func<RegionalAuthoritySnapshot> authority,
        Func<ForgejoCiTriggerPlan, CancellationToken, Task<ForgejoCiEventProcessDisposition>>? process,
        bool enabled)
    {
        this.consumer = consumer;
        this.handler = handler;
        this.authority = authority;
        this.process = process;
        this.enabled = enabled;
        loop = RunAsync(stopping.Token);
    }

    public Task Completion => loop;

    internal static ForgejoCiEventConsumer Start(
        INatsJSConsumer consumer,
        ForgejoCiInboxHandler handler,
        Func<RegionalAuthoritySnapshot> authority,
        Func<ForgejoCiTriggerPlan, CancellationToken, Task<ForgejoCiEventProcessDisposition>>? process = null,
        bool enabled = true) =>
        new(consumer, handler, authority, process, enabled);

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

    private async Task RunAsync(CancellationToken cancellationToken)
    {
        if (!enabled)
        {
            // Check mode: never consume CI events. The consumer object exists only so lifecycle
            // ownership stays uniform; no delivery is ever fetched or acknowledged.
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return;
        }
        while (!cancellationToken.IsCancellationRequested)
        {
            // One delivery at a time; no exception may poison the loop or silently burn the
            // delivery budget (MaxDeliver) of a message this consumer still owns.
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
                // Transient infrastructure or unexpected processing failure outside the per-
                // message handling below: back off and redeliver rather than dying.
                await Task.Delay(FollowerDelay, cancellationToken);
            }
        }
    }

    private async Task ConsumeOnceAsync(CancellationToken cancellationToken)
    {
        var snapshot = authority();
        if (!snapshot.Ready || !snapshot.IsLeader)
        {
            await Task.Delay(FollowerDelay, cancellationToken);
            return;
        }

        var message = await consumer.NextAsync<string>(
            opts: new NatsJSNextOpts { Expires = TimeSpan.FromSeconds(1) },
            cancellationToken: cancellationToken);
        if (message is null) return;
        ForgejoCiTriggerJournalReceipt receipt;
        try
        {
            receipt = await handler.HandleAsync(
                message.Data ?? throw new InvalidDataException("A global CI inbox event is empty."),
                cancellationToken);
        }
        catch (Exception exception)
        {
            await HandleFailureAsync(message, exception, cancellationToken);
            return;
        }

        if (receipt.Disposition is ForgejoCiTriggerJournalDisposition.Recorded or
            ForgejoCiTriggerJournalDisposition.Duplicate)
        {
            if (process is null)
            {
                // Unreachable-defensive in fail-closed compositions (Forgejo requires a pool);
                // kept because losing it would burn the delivery budget. Loud, never acked.
                Console.Error.WriteLine(
                    "CI trigger journaled but no executor is composed; delivery stays pending for a pool-bearing instance.");
                await Task.Delay(FollowerDelay, cancellationToken);
                return;
            }
            if (RequiresProcessing(receipt.Plan))
            {
                ForgejoCiEventProcessDisposition disposition;
                try
                {
                    // The whole process stage — controller, planning, attestation gate, journal
                    // prunes — is inside the classified boundary: a deterministic throw (durable
                    // conflict, retired schema restore, gate fail-closed) must map to a typed
                    // disposition here, never escape to the silent loop catch where it would
                    // burn the delivery budget (MaxDeliver) and silently lose CI.
                    disposition = await ProcessWithProgressAsync(
                        token => process(receipt.Plan, token),
                        token => message.AckProgressAsync(cancellationToken: token).AsTask(),
                        cancellationToken);
                }
                catch (Exception exception)
                {
                    await HandleFailureAsync(message, exception, cancellationToken);
                    return;
                }
                if (disposition == ForgejoCiEventProcessDisposition.Retry)
                {
                    await message.NakAsync(delay: RetryDelay, cancellationToken: cancellationToken);
                    return;
                }
                if (disposition == ForgejoCiEventProcessDisposition.Terminal)
                {
                    await message.AckTerminateAsync(cancellationToken: cancellationToken);
                    return;
                }
            }
            await message.AckAsync(cancellationToken: cancellationToken);
            return;
        }
        if (receipt.Disposition == ForgejoCiTriggerJournalDisposition.IdentityConflict)
        {
            // Same deterministic conflict as above, surfaced by the journal comparison.
            await message.AckTerminateAsync(cancellationToken: cancellationToken);
            return;
        }
        await Task.Delay(FollowerDelay, cancellationToken);
    }

    private static async Task HandleFailureAsync(
        NATS.Client.JetStream.INatsJSMsg<string> message,
        Exception exception,
        CancellationToken cancellationToken)
    {
        switch (ClassifyFailure(exception))
        {
            case ForgejoCiEventProcessDisposition.Retry:
                if (exception is JournalRetentionOverflowException)
                {
                    // Operational, never payload: the durable history cap is exceeded with records
                    // that cannot be pruned. The event itself is healthy — terminating it would
                    // silently discard every future CI event, so it is loud + retried until the
                    // operator raises the cap or the bounded-age horizon passes.
                    Console.Error.WriteLine(
                        $"CI journal retention over capacity; event left pending: {exception.Message}");
                }
                await message.NakAsync(delay: RetryDelay, cancellationToken: cancellationToken);
                break;
            case ForgejoCiEventProcessDisposition.Terminal:
                // A deterministic durable conflict reoccurs on every redelivery: terminate.
                // Loud by design — a terminated CI event is an operator-visible decision, never
                // a silent drop.
                Console.Error.WriteLine(
                    $"CI event terminated after a deterministic processing failure: {exception.Message}");
                await message.AckTerminateAsync(cancellationToken: cancellationToken);
                break;
            default:
                throw new InvalidOperationException(
                    "The CI event failure classifier returned a non-failure disposition.");
        }
    }

    /// <summary>
    /// Maps one processing failure to the delivery disposition: operational retention overflow
    /// and transient infrastructure failures retry; deterministic durable conflicts terminate.
    /// </summary>
    internal static ForgejoCiEventProcessDisposition ClassifyFailure(Exception exception) =>
        exception switch
        {
            JournalRetentionOverflowException => ForgejoCiEventProcessDisposition.Retry,
            // The progress-ack lease-loss wrapper wraps a transient transport failure: the
            // delivery will be redelivered anyway, so retry it rather than terminating.
            InvalidDataException { InnerException: { } inner } when IsTransientDeliveryFailure(inner) =>
                ForgejoCiEventProcessDisposition.Retry,
            InvalidDataException => ForgejoCiEventProcessDisposition.Terminal,
            _ when IsTransientDeliveryFailure(exception) => ForgejoCiEventProcessDisposition.Retry,
            _ => ForgejoCiEventProcessDisposition.Terminal,
        };

    internal static async Task<ForgejoCiEventProcessDisposition> ProcessWithProgressAsync(
        Func<CancellationToken, Task<ForgejoCiEventProcessDisposition>> process,
        Func<CancellationToken, Task> progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(process);
        ArgumentNullException.ThrowIfNull(progress);
        using var failed = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var work = process(failed.Token);
        while (!work.IsCompleted)
        {
            var delay = Task.Delay(ProgressInterval, cancellationToken);
            if (await Task.WhenAny(work, delay) == work) break;
            try
            {
                await progress(cancellationToken);
            }
            catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
            {
                await failed.CancelAsync();
                try { await work; } catch { }
                throw new InvalidDataException("The CI controller lost its Forgejo delivery lease.", exception);
            }
        }
        return await work;
    }

    internal static bool RequiresProcessing(ForgejoCiTriggerPlan plan) =>
        (plan ?? throw new ArgumentNullException(nameof(plan))).Disposition ==
        ForgejoCiTriggerDisposition.Dispatch;

    private static bool IsTransientDeliveryFailure(Exception exception) =>
        exception is IOException or TimeoutException or NATS.Client.Core.NatsException or
            NATS.Client.JetStream.NatsJSException;
}
