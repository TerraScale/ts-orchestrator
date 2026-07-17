using NATS.Client.Core;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Delivery;

/// <summary>Runs the bounded candidate-retention sweep only under live global authority.</summary>
internal sealed class RepositoryCiCandidateRetentionWorker : IAsyncDisposable
{
    private static readonly TimeSpan SweepInterval = TimeSpan.FromHours(1);
    private readonly RepositoryCiCandidateRetentionCoordinator coordinator;
    private readonly Func<RegionalAuthoritySnapshot> authority;
    private readonly CancellationTokenSource stopping = new();
    private readonly Task loop;

    private RepositoryCiCandidateRetentionWorker(
        RepositoryCiCandidateRetentionCoordinator coordinator,
        Func<RegionalAuthoritySnapshot> authority)
    {
        this.coordinator = coordinator ?? throw new ArgumentNullException(nameof(coordinator));
        this.authority = authority ?? throw new ArgumentNullException(nameof(authority));
        loop = RunAsync(stopping.Token);
    }

    internal Task Completion => loop;

    internal static RepositoryCiCandidateRetentionWorker Start(
        RepositoryCiCandidateRetentionCoordinator coordinator,
        Func<RegionalAuthoritySnapshot> authority) => new(coordinator, authority);

    internal async Task<RepositoryCiCandidateRetentionSummary?> SweepOnceAsync(
        CancellationToken cancellationToken = default)
    {
        var lease = authority();
        if (!lease.Ready || !lease.IsLeader || lease.Epoch <= 0 || lease.KvRevision <= 0)
            return null;
        bool StillValid() => RepositoryCiController.SameAuthority(lease, authority());
        return await coordinator.RunOnceAsync(
            lease.Epoch,
            lease.KvRevision,
            StillValid,
            cancellationToken);
    }

    private async Task RunAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            try
            {
                _ = await SweepOnceAsync(cancellationToken);
            }
            catch (Exception exception) when (
                !cancellationToken.IsCancellationRequested &&
                exception is NatsException or IOException or TimeoutException or OperationCanceledException)
            {
                // A transient storage outage cannot widen deletion authority. Retry the same
                // lifecycle evidence on the next bounded sweep.
            }
            await Task.Delay(SweepInterval, cancellationToken);
        }
    }

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
