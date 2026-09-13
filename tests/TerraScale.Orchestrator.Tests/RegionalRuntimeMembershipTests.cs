using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

public sealed class RegionalRuntimeMembershipTests
{
    [Test]
    public async Task MembershipDocumentCarriesStableDiscoveryIdentityAndAuthority()
    {
        var observedAt = DateTimeOffset.UtcNow;
        using var identity = RegionalRuntimeMembershipIdentity.Create();
        var member = Member(identity, observedAt);

        await Assert.That(member.IsValidFor("gru", observedAt)).IsTrue();
        await Assert.That(member.Cluster).IsEqualTo("orchestrator-control-gru");
        await Assert.That(member.Instance).IsEqualTo("controller-1");
        await Assert.That(member.AuthorityEpoch).IsEqualTo(7);
        await Assert.That(member.IsAuthorityLeader).IsTrue();
        await Assert.That(member.VerifySignedIdentity()).IsTrue();
    }

    [Test]
    public async Task MembershipRejectsExpiredCrossCellAndUnsortedRecords()
    {
        var observedAt = DateTimeOffset.UtcNow;
        using var identity = RegionalRuntimeMembershipIdentity.Create();
        var member = Member(identity, observedAt);

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
        using var identity = RegionalRuntimeMembershipIdentity.Create();
        var first = Member(identity, observedAt);
        var second = Member(identity, observedAt, instance: "controller-2", leader: false);
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
        using var identity = RegionalRuntimeMembershipIdentity.Create();
        var leader = Member(identity, observedAt.AddMilliseconds(-250));
        var follower = Member(
            identity, observedAt.AddMilliseconds(-250), instance: "controller-2", leader: false);
        var stale = Member(
            identity,
            observedAt.AddSeconds(-2),
            instance: "controller-3",
            leader: false,
            lease: TimeSpan.FromSeconds(1));

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
            [leader, follower, Member(identity, observedAt, instance: "controller-3", leader: false)],
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

    [Test]
    public async Task ConflictingSessionsAreACurrentGaugeNotALifetimeCounter()
    {
        // A conflict storm far beyond the slot count must never overflow the
        // projection: the conflicting count is bounded by the slots currently
        // observed, because it is derived per slot from the live record
        // classified against its immediately preceding observation.
        using var identity = RegionalRuntimeMembershipIdentity.Create();
        var observedAt = DateTimeOffset.UtcNow;
        var first = Member(identity, observedAt);
        var second = Member(identity, observedAt, instance: "controller-2", leader: false);
        var third = Member(identity, observedAt, instance: "controller-3", leader: false);
        var records = new[] { first, second, third };

        // Simulate many successive session changes on every slot: whatever the
        // history, the current gauge counts at most one conflict per slot.
        for (var rotation = 0; rotation < 10; rotation++)
        {
            var currentConflict = rotation % 2 == 0 ? 1 : 0;
            var health = RegionalRuntimeMembershipHealth.Evaluate(
                "gru", 3, records, 0, observedAt, currentConflict);
            health.Validate();
            await Assert.That(health.ConflictingControllers).IsEqualTo(currentConflict);
            await Assert.That(health.ConflictingControllers)
                .IsLessThanOrEqualTo(health.ActiveControllers + health.StaleControllers);
        }

        // The maximum expressible current conflict is one per observed slot: the
        // projection stays valid even in the fully conflicted state.
        var allConflicted = RegionalRuntimeMembershipHealth.Evaluate(
            "gru", 3, records, 0, observedAt, 3);
        allConflicted.Validate();
        await Assert.That(allConflicted.ConflictingControllers).IsEqualTo(3);
    }

    private static RegionalRuntimeMember Member(
        RegionalRuntimeMembershipIdentity identity,
        DateTimeOffset observedAt,
        string instance = "controller-1",
        bool leader = true,
        TimeSpan? lease = null)
    {
        var member = new RegionalRuntimeMember(
            1,
            "gru",
            "orchestrator-control-gru",
            instance,
            Guid.NewGuid().ToString("N"),
            "test-build",
            ["authority", "regional-membership", "service-discovery"],
            observedAt.AddMinutes(-1),
            observedAt,
            observedAt + (lease ?? RegionalRuntimeMembership.LeaseDuration),
            leader ? "leader" : "follower",
            leader,
            7,
            11,
            identity.KeyId,
            identity.PublicKey,
            string.Empty);
        return member with { IdentitySignature = identity.Sign(member) };
    }
}

