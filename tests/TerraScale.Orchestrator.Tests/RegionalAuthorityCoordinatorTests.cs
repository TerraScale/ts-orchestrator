using TerraScale.Orchestrator.ControlPlane.Authority;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

public sealed class RegionalAuthorityCoordinatorTests
{
    [Test]
    public async Task LeaseDocumentRoundTripsExactFencingIdentity()
    {
        var issuedAt = DateTimeOffset.UtcNow.AddSeconds(-1);
        var lease = new AuthorityLease(
            "gru-controller-2",
            "lease-123",
            issuedAt,
            TimeSpan.FromSeconds(15));

        var document = RegionalAuthorityLeaseDocument.From("gru-regional", 7, lease);
        document.Validate();

        await Assert.That(document.Epoch).IsEqualTo(7);
        await Assert.That(document.ToLease()).IsEqualTo(lease);
    }

    [Test]
    public async Task LeaseDocumentRejectsCrossBoundaryAndUnboundedValues()
    {
        var valid = RegionalAuthorityLeaseDocument.From(
            "gru-regional",
            1,
            new AuthorityLease(
                "gru-controller-1",
                "lease-1",
                DateTimeOffset.UtcNow,
                TimeSpan.FromSeconds(15)));

        await Assert.That(() => (valid with { Epoch = 0 }).Validate())
            .Throws<InvalidOperationException>();
        await Assert.That(() => (valid with { DurationMilliseconds = 60_001 }).Validate())
            .Throws<InvalidOperationException>();
        await Assert.That(() => (valid with { CandidateId = "" }).Validate())
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task AuthorityReadinessRequiresFreshNonFencedObservation()
    {
        var future = DateTimeOffset.UtcNow.AddSeconds(10);
        var leader = new RegionalAuthoritySnapshot(
            "leader", true, 2, 3, future, DateTimeOffset.UtcNow, null);

        await Assert.That(leader.Ready).IsTrue();
        await Assert.That((leader with { State = "follower", IsLeader = false }).Ready).IsTrue();
        await Assert.That((leader with { State = "fenced", IsLeader = false }).Ready).IsFalse();
        await Assert.That((leader with { State = "held", IsLeader = false }).Ready).IsFalse();
        await Assert.That((leader with { ObservedAt = DateTimeOffset.UtcNow.AddMinutes(-1) }).Ready).IsFalse();
        await Assert.That((leader with { Error = "uncertain" }).Ready).IsFalse();
        await Assert.That((leader with { LeaseExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-1) }).Ready)
            .IsFalse();
    }
}

