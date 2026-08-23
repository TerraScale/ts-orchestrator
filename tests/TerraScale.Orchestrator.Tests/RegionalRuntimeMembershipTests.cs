using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

public sealed class RegionalRuntimeMembershipTests
{
    [Test]
    public async Task MembershipDocumentCarriesStableDiscoveryIdentityAndAuthority()
    {
        var observedAt = DateTimeOffset.UtcNow;
        var member = Member(observedAt);

        await Assert.That(member.IsValidFor("gru", observedAt)).IsTrue();
        await Assert.That(member.Cluster).IsEqualTo("orchestrator-control-gru");
        await Assert.That(member.Instance).IsEqualTo("controller-1");
        await Assert.That(member.AuthorityEpoch).IsEqualTo(7);
        await Assert.That(member.IsAuthorityLeader).IsTrue();
    }

    [Test]
    public async Task MembershipRejectsExpiredCrossCellAndUnsortedRecords()
    {
        var observedAt = DateTimeOffset.UtcNow;
        var member = Member(observedAt);

        await Assert.That((member with { LeaseExpiresAt = observedAt }).IsValidFor("gru", observedAt)).IsFalse();
        await Assert.That((member with { Cell = "sfo" }).IsValidFor("gru", observedAt)).IsFalse();
        await Assert.That((member with { Cluster = "product-gru" }).IsValidFor("gru", observedAt)).IsFalse();
        await Assert.That((member with { Capabilities = ["service-discovery", "authority"] })
            .IsValidFor("gru", observedAt)).IsFalse();
        await Assert.That((member with { AuthorityState = "follower" })
            .IsValidFor("gru", observedAt)).IsFalse();
    }

    [Test]
    public async Task MembershipSnapshotRequiresUniqueSortedActiveInstances()
    {
        var observedAt = DateTimeOffset.UtcNow;
        var first = Member(observedAt);
        var second = first with
        {
            Instance = "controller-2",
            SessionId = Guid.NewGuid().ToString("N"),
            AuthorityState = "follower",
            IsAuthorityLeader = false
        };
        var health = RegionalRuntimeMembershipHealth.Evaluate("gru", 3, [first, second], 0, observedAt);
        var valid = new RegionalRuntimeMembershipSnapshot(2, "gru", observedAt, health, [first, second]);
        valid.Validate("gru");

        await Assert.That(() => (valid with { Members = [second, first] }).Validate("gru"))
            .Throws<InvalidOperationException>();
        await Assert.That(() => (valid with { Members = [first, first] }).Validate("gru"))
            .Throws<InvalidOperationException>();
        await Assert.That(() => (valid with { Members = [] }).Validate("gru"))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task MembershipHealthMeasuresStaleMissingQuorumAndRecoveryState()
    {
        var observedAt = DateTimeOffset.UtcNow;
        var leader = Member(observedAt.AddMilliseconds(-250));
        var follower = leader with
        {
            Instance = "controller-2",
            SessionId = Guid.NewGuid().ToString("N"),
            AuthorityState = "follower",
            IsAuthorityLeader = false
        };
        var stale = follower with
        {
            Instance = "controller-3",
            SessionId = Guid.NewGuid().ToString("N"),
            ObservedAt = observedAt.AddSeconds(-2),
            LeaseExpiresAt = observedAt.AddMilliseconds(-1)
        };

        var degraded = RegionalRuntimeMembershipHealth.Evaluate(
            "gru", 3, [leader, follower, stale], 4, observedAt);
        degraded.Validate();
        await Assert.That(degraded.ActiveControllers).IsEqualTo(2);
        await Assert.That(degraded.StaleControllers).IsEqualTo(1);
        await Assert.That(degraded.MissingControllers).IsEqualTo(1);
        await Assert.That(degraded.QuorumAvailable).IsTrue();
        await Assert.That(degraded.RejectedRecords).IsEqualTo(4);
        await Assert.That(degraded.MaximumHeartbeatAgeMilliseconds).IsGreaterThanOrEqualTo(250);
        await Assert.That(degraded.Condition).IsEqualTo(RegionalRuntimeMembershipCondition.Degraded);

        var recovered = RegionalRuntimeMembershipHealth.Evaluate(
            "gru",
            3,
            [leader, follower, stale with { ObservedAt = observedAt, LeaseExpiresAt = observedAt.AddSeconds(20) }],
            4,
            observedAt);
        recovered.Validate();
        await Assert.That(recovered.ActiveControllers).IsEqualTo(3);
        await Assert.That(recovered.StaleControllers).IsEqualTo(0);
        await Assert.That(recovered.MissingControllers).IsEqualTo(0);
        await Assert.That(recovered.Condition).IsEqualTo(RegionalRuntimeMembershipCondition.Healthy);

        var unavailable = RegionalRuntimeMembershipHealth.Evaluate(
            "gru", 3, [stale], 4, observedAt);
        unavailable.Validate();
        await Assert.That(unavailable.QuorumAvailable).IsFalse();
        await Assert.That(unavailable.Condition).IsEqualTo(RegionalRuntimeMembershipCondition.Unavailable);
    }

    private static RegionalRuntimeMember Member(DateTimeOffset observedAt) => new(
        1,
        "gru",
        "orchestrator-control-gru",
        "controller-1",
        Guid.NewGuid().ToString("N"),
        "test-build",
        ["authority", "regional-membership", "service-discovery"],
        observedAt.AddMinutes(-1),
        observedAt,
        observedAt.Add(RegionalRuntimeMembership.LeaseDuration),
        "leader",
        true,
        7,
        11);
}
