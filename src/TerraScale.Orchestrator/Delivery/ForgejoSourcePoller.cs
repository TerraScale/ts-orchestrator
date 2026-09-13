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
    private readonly Func<ForgejoBranchObservation, long, long, CancellationToken,
        Task<NativeGitOpsSourceReconcileResult>>? reconcile;
    private readonly Func<ForgejoBranchObservation, long, CancellationToken,
        Task<NativeGitOpsGlobalHandoffCoordinationReceipt>>? publishHandoff;
    private readonly ForgejoSourceClient? ownedClient;
    private readonly CancellationTokenSource stopping = new();
    private Task? loop;
    private long pollSequence;

    internal ForgejoSourcePoller(
        Func<string, CancellationToken, Task<ForgejoBranchObservation>> pollBranch,
        ForgejoSourceJournal journal,
        Func<RegionalAuthoritySnapshot> authority)
        : this(pollBranch, journal, authority, null, null, null)
    {
    }

    internal ForgejoSourcePoller(
        Func<string, CancellationToken, Task<ForgejoBranchObservation>> pollBranch,
        ForgejoSourceJournal journal,
        Func<RegionalAuthoritySnapshot> authority,
        Func<ForgejoBranchObservation, long, long, CancellationToken,
            Task<NativeGitOpsSourceReconcileResult>> reconcile,
        Func<ForgejoBranchObservation, long, CancellationToken,
            Task<NativeGitOpsGlobalHandoffCoordinationReceipt>>? publishHandoff = null)
        : this(pollBranch, journal, authority, reconcile, publishHandoff, null)
    {
    }

    private ForgejoSourcePoller(
        Func<string, CancellationToken, Task<ForgejoBranchObservation>> pollBranch,
        ForgejoSourceJournal journal,
        Func<RegionalAuthoritySnapshot> authority,
        Func<ForgejoBranchObservation, long, long, CancellationToken,
            Task<NativeGitOpsSourceReconcileResult>>? reconcile,
        Func<ForgejoBranchObservation, long, CancellationToken,
            Task<NativeGitOpsGlobalHandoffCoordinationReceipt>>? publishHandoff,
        ForgejoSourceClient? ownedClient)
    {
        this.pollBranch = pollBranch;
        this.journal = journal;
        this.authority = authority;
        this.reconcile = reconcile;
        this.publishHandoff = publishHandoff;
        this.ownedClient = ownedClient;
    }

    internal Task Completion => loop ?? Task.CompletedTask;

    internal static ForgejoSourcePoller Start(
        ForgejoSourceConfiguration configuration,
        ForgejoSourceJournal journal,
        NativeGitOpsSourceJournal gitOps,
        Func<RegionalAuthoritySnapshot> authority,
        NativeGitOpsGlobalHandoffRuntime? handoffs = null)
    {
        var client = ForgejoSourceClient.Create(configuration);
        var reconciler = new NativeGitOpsSourceReconciler(client, gitOps, authority);
        Func<ForgejoBranchObservation, long, CancellationToken,
            Task<NativeGitOpsGlobalHandoffCoordinationReceipt>>? publishHandoff = null;
        if (handoffs is not null) publishHandoff = handoffs.CoordinateAsync;
        var poller = new ForgejoSourcePoller(
            client.PollBranchAsync,
            journal,
            authority,
            reconciler.ReconcileAsync,
            publishHandoff,
            client);
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

            var sequence = Interlocked.Increment(ref pollSequence);
            var receipt = await journal.ObserveAsync(
                observation,
                lease.Epoch,
                sequence,
                cancellationToken);
            if (receipt.Disposition is ForgejoSourceJournalDisposition.StaleAuthority or
                ForgejoSourceJournalDisposition.StaleSequence)
                return;
            if (receipt.Disposition is ForgejoSourceJournalDisposition.UnprotectedBranch or
                ForgejoSourceJournalDisposition.IdentityConflict or ForgejoSourceJournalDisposition.Unspecified)
                throw new InvalidOperationException("Forgejo source polling produced an unsafe branch observation.");

            if (reconcile is null) continue;
            var plan = await reconcile(observation, lease.Epoch, sequence, cancellationToken);
            if (plan.Disposition is NativeGitOpsSourceJournalDisposition.StaleAuthority or
                NativeGitOpsSourceJournalDisposition.StaleSequence)
                return;
            if (plan.Disposition is not (NativeGitOpsSourceJournalDisposition.NotConfigured or
                NativeGitOpsSourceJournalDisposition.Recorded or
                NativeGitOpsSourceJournalDisposition.Duplicate))
                throw new InvalidOperationException("Forgejo source polling produced an unsafe native GitOps plan.");
            if (plan.Disposition == NativeGitOpsSourceJournalDisposition.NotConfigured ||
                plan.SourcePlan is { Proposed.Workloads.Count: 0, Diff.Changes.Count: 0 } ||
                observation.Branch != "main" || publishHandoff is null)
                continue;

            var handoff = await publishHandoff(observation, lease.Epoch, cancellationToken);
            if (handoff.Disposition == NativeGitOpsGlobalHandoffCoordinationDisposition.AuthorityLost)
                return;
            if (!handoff.IsComplete)
                throw new InvalidOperationException("Forgejo source polling produced an unsafe global handoff.");
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

