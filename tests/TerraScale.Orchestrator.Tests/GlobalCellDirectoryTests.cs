using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

public sealed class GlobalCellDirectoryTests
{
    [Test]
    public async Task ThreeRegionalAdvertisementsConvergeToOneEntryPerCell()
    {
        var observedAt = DateTimeOffset.UtcNow;
        var directory = new GlobalCellDirectory();

        await Assert.That(directory.Apply(Advertisement("gru", observedAt)))
            .IsEqualTo(GlobalCellAdvertisementDisposition.Accepted);
        await Assert.That(directory.Apply(Advertisement("sfo", observedAt)))
            .IsEqualTo(GlobalCellAdvertisementDisposition.Accepted);
        await Assert.That(directory.Apply(Advertisement("fra", observedAt)))
            .IsEqualTo(GlobalCellAdvertisementDisposition.Accepted);

        var snapshot = directory.Snapshot(observedAt.AddSeconds(1));
        snapshot.Validate();
        await Assert.That(snapshot.Cells.Select(static cell => cell.Cell))
            .IsEquivalentTo(["fra", "gru", "sfo"]);
        await Assert.That(snapshot.ActiveCells).IsEqualTo(3);
        await Assert.That(snapshot.StaleCells).IsEqualTo(0);
    }

    [Test]
    public async Task RedeliveryOfTheSameWireAdvertisementIsADuplicate()
    {
        var observedAt = DateTimeOffset.UtcNow;
        var directory = new GlobalCellDirectory();
        var advertisement = Advertisement("gru", observedAt);

        await Assert.That(directory.Apply(advertisement))
            .IsEqualTo(GlobalCellAdvertisementDisposition.Accepted);
        await Assert.That(directory.Apply(advertisement with
            {
                Capabilities = advertisement.Capabilities.ToArray()
            }))
            .IsEqualTo(GlobalCellAdvertisementDisposition.Duplicate);

        await Assert.That(directory.Snapshot().Cells.Count).IsEqualTo(1);
    }

    [Test]
    public async Task AdvertisementCannotClaimAnotherCellsDurableKey()
    {
        var directory = new GlobalCellDirectory();

        await Assert.That(directory.Apply("cell.gru", Advertisement("sfo", DateTimeOffset.UtcNow)))
            .IsEqualTo(GlobalCellAdvertisementDisposition.Rejected);
        await Assert.That(directory.Snapshot().Cells).IsEmpty();
        await Assert.That(directory.Snapshot().RejectedAdvertisements).IsEqualTo(1);
    }

    [Test]
    public async Task NullMembershipIsRejectedWithoutFaultingTheDirectory()
    {
        var directory = new GlobalCellDirectory();

        await Assert.That(directory.Apply(Advertisement("gru", DateTimeOffset.UtcNow) with
            {
                Membership = null!
            })).IsEqualTo(GlobalCellAdvertisementDisposition.Rejected);
        await Assert.That(directory.Snapshot().RejectedAdvertisements).IsEqualTo(1);
    }

    [Test]
    public async Task ExpiredHigherVersionCannotReplaceAnActiveAdvertisement()
    {
        var observedAt = DateTimeOffset.UtcNow;
        var directory = new GlobalCellDirectory();
        var active = Advertisement("gru", observedAt);
        var expiredAt = observedAt.AddSeconds(-30);
        var expired = Advertisement("gru", expiredAt) with
        {
            AuthorityEpoch = active.AuthorityEpoch + 1,
            AuthorityRevision = active.AuthorityRevision + 1
        };

        await Assert.That(directory.Apply(active, observedAt)).IsEqualTo(GlobalCellAdvertisementDisposition.Accepted);
        await Assert.That(directory.Apply(expired, observedAt)).IsEqualTo(GlobalCellAdvertisementDisposition.Stale);
        await Assert.That(directory.Snapshot(observedAt).Cells.Single().AuthorityEpoch)
            .IsEqualTo(active.AuthorityEpoch);
    }

    [Test]
    public async Task NewAuthorityRevisionSupersedesSequenceAndExpiryMarksTheCellStale()
    {
        var observedAt = DateTimeOffset.UtcNow;
        var directory = new GlobalCellDirectory();
        var original = Advertisement("gru", observedAt) with { Sequence = 100 };
        var nextObservedAt = observedAt.AddSeconds(1);
        var newer = original with
        {
            AuthorityRevision = 12,
            Sequence = 1,
            Membership = original.Membership with { ObservedAt = nextObservedAt },
            ObservedAt = nextObservedAt,
            LeaseExpiresAt = nextObservedAt.AddSeconds(20)
        };

        await Assert.That(directory.Apply(original)).IsEqualTo(GlobalCellAdvertisementDisposition.Accepted);
        await Assert.That(directory.Apply(newer)).IsEqualTo(GlobalCellAdvertisementDisposition.Accepted);
        await Assert.That(directory.Apply(original with { Sequence = 101 }))
            .IsEqualTo(GlobalCellAdvertisementDisposition.Stale);

        var expired = directory.Snapshot(nextObservedAt.AddSeconds(21));
        expired.Validate();
        await Assert.That(expired.ActiveCells).IsEqualTo(0);
        await Assert.That(expired.StaleCells).IsEqualTo(1);
        await Assert.That(expired.Condition).IsEqualTo(GlobalCellDirectoryCondition.Unavailable);
        await Assert.That(expired.Cells.Single().AuthorityRevision).IsEqualTo(12);
        await Assert.That(expired.RejectedAdvertisements).IsEqualTo(1);
    }

    private static GlobalCellAdvertisement Advertisement(string cell, DateTimeOffset observedAt) => new(
        1,
        cell,
        $"orchestrator-control-{cell}",
        $"{cell}-regional",
        7,
        11,
        1,
        ["authority", "regional-membership", "service-discovery"],
        new(3, 3, 0, 0, 0, 0, 1, true, 100,
            RegionalRuntimeMembershipCondition.Healthy, observedAt),
        observedAt,
        observedAt.AddSeconds(20));
}
