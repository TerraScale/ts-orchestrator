using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Delivery;

/// <summary>Polls protected Forgejo refs only while this controller holds regional authority.</summary>
internal sealed class ForgejoSourcePoller : IAsyncDisposable
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(30);
    private static readonly string[] Branches = ["develop", "main"];
    private readonly Func<string, CancellationToken, Task<ForgejoBranchObservation>> pollBranch;
    private readonly ForgejoSourceJournal journal;
    private readonly Func<RegionalAuthoritySnapshot> authority;
    private readonly ForgejoSourceClient? ownedClient;
    private readonly CancellationTokenSource stopping = new();
    private Task? loop;
    private long pollSequence;

    internal ForgejoSourcePoller(
        Func<string, CancellationToken, Task<ForgejoBranchObservation>> pollBranch,
        ForgejoSourceJournal journal,
        Func<RegionalAuthoritySnapshot> authority)
        : this(pollBranch, journal, authority, null)
    {
    }

    private ForgejoSourcePoller(
        Func<string, CancellationToken, Task<ForgejoBranchObservation>> pollBranch,
        ForgejoSourceJournal journal,
        Func<RegionalAuthoritySnapshot> authority,
        ForgejoSourceClient? ownedClient)
    {
        this.pollBranch = pollBranch;
        this.journal = journal;
        this.authority = authority;
        this.ownedClient = ownedClient;
    }

    internal Task Completion => loop ?? Task.CompletedTask;

    internal static ForgejoSourcePoller Start(
        ForgejoSourceConfiguration configuration,
        ForgejoSourceJournal journal,
        Func<RegionalAuthoritySnapshot> authority)
    {
        var client = ForgejoSourceClient.Create(configuration);
        var poller = new ForgejoSourcePoller(client.PollBranchAsync, journal, authority, client);
        poller.loop = poller.RunAsync(poller.stopping.Token);
        return poller;
    }

    public async ValueTask DisposeAsync()
    {
        await stopping.CancelAsync();
        try
        {
            if (loop is not null)
            {
                await loop;
            }
        }
        catch (OperationCanceledException) when (stopping.IsCancellationRequested)
        {
        }
        finally
        {
            if (ownedClient is not null) await ownedClient.DisposeAsync();
            stopping.Dispose();
        }
    }

    internal async Task PollOnceAsync(CancellationToken cancellationToken = default)
    {
        var lease = authority();
        if (!lease.Ready || !lease.IsLeader) return;

        foreach (var branch in Branches)
        {
            var observation = await pollBranch(branch, cancellationToken);
            var confirmed = authority();
            if (!confirmed.Ready || !confirmed.IsLeader || confirmed.Epoch != lease.Epoch) return;

            var receipt = await journal.ObserveAsync(
                observation,
                lease.Epoch,
                Interlocked.Increment(ref pollSequence),
                cancellationToken);
            if (receipt.Disposition is ForgejoSourceJournalDisposition.StaleAuthority or
                ForgejoSourceJournalDisposition.StaleSequence)
                return;
            if (receipt.Disposition is ForgejoSourceJournalDisposition.UnprotectedBranch or
                ForgejoSourceJournalDisposition.IdentityConflict or ForgejoSourceJournalDisposition.Unspecified)
                throw new InvalidOperationException("Forgejo source polling produced an unsafe branch observation.");
        }
    }

    private async Task RunAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            try
            {
                await PollOnceAsync(cancellationToken);
            }
            catch (Exception exception) when (
                !cancellationToken.IsCancellationRequested &&
                exception is HttpRequestException or IOException or TimeoutException or OperationCanceledException)
            {
                // Forgejo polling is a fallback path. A transport outage is retried while
                // webhook ingestion and already-journaled work remain available.
            }
            await Task.Delay(PollInterval, cancellationToken);
        }
    }
}
