using TerraScale.Orchestrator.Protocol.Messaging;

namespace TerraScale.Orchestrator.Messaging;

/// <summary>
/// The eligibility class of one controller derived from current regional evidence
/// and fencing. Transport connectivity is deliberately not an input: a reachable
/// process without a live fenced claim is not eligible, and an unreachable process's
/// claim still expires on its own lease.
/// </summary>
internal enum ControllerEligibilityClass
{
    Unspecified = 0,
    /// <summary>Live fenced claim, current epoch, healthy regional evidence: may mutate.</summary>
    MutatingLeader = 1,
    /// <summary>Live fenced claim held by a peer: serves reads, never mutates.</summary>
    ReadOnlyFollower = 2,
    /// <summary>Regional quorum lost: the controller becomes read-only and holds new mutations.</summary>
    ReadOnlyUncertain = 3,
    /// <summary>No live claim, or a claim fenced by a newer epoch: not eligible for anything authoritative.</summary>
    NotEligible = 4,
}

/// <summary>
/// Pure controller-eligibility rules. They compose the two landed evidence sources —
/// the watched regional membership health (quorum, leaders) and the fenced authority
/// lease claim — and mirror <see cref="QueueGroupOwnership"/>: eligibility is epoch
/// equality under a live lease, not reachability.
/// </summary>
internal static class ControllerEligibilityRules
{
    internal static ControllerEligibilityClass Decide(
        RegionalRuntimeMembershipHealth? membership,
        AuthorityLeaseClaim? claim,
        bool isLeader,
        long maximumObservedEpoch,
        DateTimeOffset now)
    {
        if (membership is not null) membership.Validate();

        // No live, well-formed fenced claim: nothing this controller observes about
        // connectivity can make it eligible.
        if (claim is null || !claim.IsWellFormed || !claim.IsLive(now))
            return ControllerEligibilityClass.NotEligible;

        // A claim fenced by a newer observed epoch is dead even while its lease
        // timestamp is still in the future.
        if (claim.Epoch < maximumObservedEpoch)
            return ControllerEligibilityClass.NotEligible;

        // Without regional quorum the controller is uncertain: it stops new
        // mutations and serves read-only until evidence returns.
        if (membership is null || !membership.QuorumAvailable)
            return ControllerEligibilityClass.ReadOnlyUncertain;

        if (isLeader) return ControllerEligibilityClass.MutatingLeader;
        return ControllerEligibilityClass.ReadOnlyFollower;
    }
}

