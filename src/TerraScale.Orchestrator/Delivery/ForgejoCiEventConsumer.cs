using NATS.Client.JetStream;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Delivery;

internal sealed class ForgejoCiEventConsumer : IAsyncDisposable
{
    private static readonly TimeSpan FollowerDelay = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan ProgressInterval = TimeSpan.FromSeconds(5);
    private readonly INatsJSConsumer consumer;
    private readonly ForgejoCiInboxHandler handler;
    private readonly Func<RegionalAuthoritySnapshot> authority;
    private readonly Func<ForgejoCiTriggerPlan, CancellationToken, Task<bool>>? process;
    private readonly CancellationTokenSource stopping = new();
    private readonly Task loop;

    private ForgejoCiEventConsumer(
        INatsJSConsumer consumer,
        ForgejoCiInboxHandler handler,
        Func<RegionalAuthoritySnapshot> authority,
        Func<ForgejoCiTriggerPlan, CancellationToken, Task<bool>>? process)
    {
        this.consumer = consumer;
        this.handler = handler;
        this.authority = authority;
        this.process = process;
        loop = RunAsync(stopping.Token);
    }

    public Task Completion => loop;

    internal static ForgejoCiEventConsumer Start(
        INatsJSConsumer consumer,
        ForgejoCiInboxHandler handler,
        Func<RegionalAuthoritySnapshot> authority,
        Func<ForgejoCiTriggerPlan, CancellationToken, Task<bool>>? process = null) =>
        new(consumer, handler, authority, process);

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
                if (process is not null && RequiresProcessing(receipt.Plan))
                {
                    var handled = await ProcessWithProgressAsync(
                        token => process(receipt.Plan, token),
                        token => message.AckProgressAsync(cancellationToken: token).AsTask(),
                        cancellationToken);
                    if (!handled) continue;
                }
                await message.AckAsync(cancellationToken: cancellationToken);
                continue;
            }
            if (receipt.Disposition == ForgejoCiTriggerJournalDisposition.IdentityConflict)
                throw new InvalidDataException("A global CI inbox event conflicts with its durable trigger decision.");
            await Task.Delay(FollowerDelay, cancellationToken);
        }
    }

    internal static async Task<bool> ProcessWithProgressAsync(
        Func<CancellationToken, Task<bool>> process,
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
}
