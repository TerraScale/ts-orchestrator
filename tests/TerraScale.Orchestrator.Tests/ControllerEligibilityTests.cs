using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Protocol.Messaging;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Controller eligibility derives from current regional evidence and fencing —
/// a live authority lease claim plus membership quorum — and never from transport
/// connectivity, which is not even an input to the decision.
/// </summary>
public sealed class ControllerEligibilityTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;

    [Test]
    public async Task LiveClaimWithQuorumAndLeadershipIsTheOnlyMutatingEligibility()
    {
        var claim = new AuthorityLeaseClaim(7, 40, Now.AddSeconds(10), "gru-regional", "gru-controller-1");
        var healthy = Health(active: 3, quorum: true, leaders: 1);

        await Assert.That(ControllerEligibilityRules.Decide(healthy, claim, isLeader: true, 7, Now))
            .IsEqualTo(ControllerEligibilityClass.MutatingLeader);
        await Assert.That(ControllerEligibilityRules.Decide(healthy, claim, isLeader: false, 7, Now))
            .IsEqualTo(ControllerEligibilityClass.ReadOnlyFollower);
    }

    [Test]
    public async Task ExpiredOrMissingClaimIsNotEligibleRegardlessOfFreshEvidence()
    {
        // Fresh observation times and a healthy quorum must not fake eligibility:
        // the fenced claim itself has lapsed.
        var healthy = Health(active: 3, quorum: true, leaders: 1);
        var expired = new AuthorityLeaseClaim(7, 40, Now.AddSeconds(-1), "gru-regional", "gru-controller-1");

        await Assert.That(ControllerEligibilityRules.Decide(healthy, claim: null, isLeader: true, 0, Now))
            .IsEqualTo(ControllerEligibilityClass.NotEligible);
        await Assert.That(ControllerEligibilityRules.Decide(healthy, expired, isLeader: true, 7, Now))
            .IsEqualTo(ControllerEligibilityClass.NotEligible);
        await Assert.That(ControllerEligibilityRules.Decide(
                healthy,
                new AuthorityLeaseClaim(0, 0, Now.AddSeconds(10), "", ""),
                isLeader: true,
                0,
                Now))
            .IsEqualTo(ControllerEligibilityClass.NotEligible);
    }

    [Test]
    public async Task ClaimFencedByANewerObservedEpochIsNotEligible()
    {
        var claim = new AuthorityLeaseClaim(6, 39, Now.AddSeconds(10), "gru-regional", "gru-controller-1");
        var healthy = Health(active: 3, quorum: true, leaders: 1);

        await Assert.That(ControllerEligibilityRules.Decide(healthy, claim, isLeader: true, maximumObservedEpoch: 7, Now))
            .IsEqualTo(ControllerEligibilityClass.NotEligible);
        await Assert.That(ControllerEligibilityRules.Decide(healthy, claim, isLeader: true, maximumObservedEpoch: 6, Now))
            .IsEqualTo(ControllerEligibilityClass.MutatingLeader);
    }

    [Test]
    public async Task LostRegionalQuorumMakesAnUncertainControllerReadOnly()
    {
        var claim = new AuthorityLeaseClaim(7, 40, Now.AddSeconds(10), "gru-regional", "gru-controller-1");
        var quorumLost = Health(active: 1, quorum: false, leaders: 1);

        await Assert.That(ControllerEligibilityRules.Decide(quorumLost, claim, isLeader: true, 7, Now))
            .IsEqualTo(ControllerEligibilityClass.ReadOnlyUncertain);
        await Assert.That(ControllerEligibilityRules.Decide(membership: null, claim, isLeader: true, 7, Now))
            .IsEqualTo(ControllerEligibilityClass.ReadOnlyUncertain);
    }

    private static RegionalRuntimeMembershipHealth Health(int active, bool quorum, int leaders) =>
        new(
            3,
            active,
            0,
            Math.Max(0, 3 - active),
            Math.Max(0, active - 3),
            0,
            0,
            leaders,
            quorum,
            100,
            active == 0
                ? RegionalRuntimeMembershipCondition.Unavailable
                : active == 3 && leaders == 1
                    ? RegionalRuntimeMembershipCondition.Healthy
                    : RegionalRuntimeMembershipCondition.Degraded,
            Now);
}
