using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.ControlPlane.Runtime;

/// <summary>Maps the sampled regional authority state to the lifecycle gate without exposing authority internals.</summary>
internal sealed class NatsRuntimeLifecycleAuthorityGate(
    RuntimeLifecycleCellId cell,
    RegionalAuthorityCoordinator authority) : IRuntimeLifecycleAuthorityGate
{
    private readonly RuntimeLifecycleCellId cell = cell ?? throw new ArgumentNullException(nameof(cell));
    private readonly RegionalAuthorityCoordinator authority = authority ?? throw new ArgumentNullException(nameof(authority));

    public ValueTask<RuntimeLifecycleAuthority> ReadAsync(RuntimeLifecycleCellId requestedCell, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestedCell);
        cancellationToken.ThrowIfCancellationRequested();
        if (requestedCell != cell)
            return ValueTask.FromResult(new RuntimeLifecycleAuthority(RuntimeLifecycleAuthorityStatus.Unavailable, new RuntimeEpoch(1UL)));

        return ValueTask.FromResult(Map(authority.Snapshot));
    }

    internal static RuntimeLifecycleAuthority Map(RegionalAuthoritySnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        var epoch = snapshot.Epoch > 0 ? new RuntimeEpoch(checked((ulong)snapshot.Epoch)) : new RuntimeEpoch(1UL);
        var status = snapshot.Ready
            ? snapshot is { State: "leader", IsLeader: true, Epoch: > 0 }
                ? RuntimeLifecycleAuthorityStatus.ReadyLeader
                : snapshot.State == "follower" || !snapshot.IsLeader
                    ? RuntimeLifecycleAuthorityStatus.Follower
                    : RuntimeLifecycleAuthorityStatus.NotReady
            : snapshot.Error is not null || snapshot.State == "fenced"
                ? RuntimeLifecycleAuthorityStatus.Unavailable
                : RuntimeLifecycleAuthorityStatus.NotReady;
        return new RuntimeLifecycleAuthority(status, epoch);
    }
}
