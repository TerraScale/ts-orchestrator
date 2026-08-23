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
        var valid = new RegionalRuntimeMembershipSnapshot(1, "gru", observedAt, [first, second]);
        valid.Validate("gru");

        await Assert.That(() => (valid with { Members = [second, first] }).Validate("gru"))
            .Throws<InvalidOperationException>();
        await Assert.That(() => (valid with { Members = [first, first] }).Validate("gru"))
            .Throws<InvalidOperationException>();
        await Assert.That(() => (valid with { Members = [] }).Validate("gru"))
            .Throws<InvalidOperationException>();
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
