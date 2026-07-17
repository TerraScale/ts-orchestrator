using NATS.Client.JetStream;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Delivery;

internal sealed class ForgejoCiEventConsumer : IAsyncDisposable
{
    private static readonly TimeSpan FollowerDelay = TimeSpan.FromSeconds(1);
    private readonly INatsJSConsumer consumer;
    private readonly ForgejoCiInboxHandler handler;
    private readonly Func<RegionalAuthoritySnapshot> authority;
    private readonly CancellationTokenSource stopping = new();
    private readonly Task loop;

    private ForgejoCiEventConsumer(
        INatsJSConsumer consumer,
        ForgejoCiInboxHandler handler,
        Func<RegionalAuthoritySnapshot> authority)
    {
        this.consumer = consumer;
        this.handler = handler;
        this.authority = authority;
        loop = RunAsync(stopping.Token);
    }

    public Task Completion => loop;

    internal static ForgejoCiEventConsumer Start(
        INatsJSConsumer consumer,
        ForgejoCiInboxHandler handler,
        Func<RegionalAuthoritySnapshot> authority) => new(consumer, handler, authority);

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
        while (!cancellationToken.IsCancellationRequested)
        {
            var snapshot = authority();
            if (!snapshot.Ready || !snapshot.IsLeader)
            {
                await Task.Delay(FollowerDelay, cancellationToken);
                continue;
            }

            var message = await consumer.NextAsync<string>(
                opts: new NatsJSNextOpts { Expires = TimeSpan.FromSeconds(1) },
                cancellationToken: cancellationToken);
            if (message is null) continue;
            var receipt = await handler.HandleAsync(
                message.Data ?? throw new InvalidDataException("A global CI inbox event is empty."),
                cancellationToken);
            if (receipt.Disposition is ForgejoCiTriggerJournalDisposition.Recorded or
                ForgejoCiTriggerJournalDisposition.Duplicate)
            {
                await message.AckAsync(cancellationToken: cancellationToken);
                continue;
            }
            if (receipt.Disposition == ForgejoCiTriggerJournalDisposition.IdentityConflict)
                throw new InvalidDataException("A global CI inbox event conflicts with its durable trigger decision.");
            await Task.Delay(FollowerDelay, cancellationToken);
        }
    }
}
