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

    [Test]
    public async Task AdvertisementsBindValidatedEndpoints()
    {
        var observedAt = DateTimeOffset.UtcNow;
        var valid = Advertisement("gru", observedAt);
        await Assert.That(valid.IsValid(observedAt)).IsTrue();
        await Assert.That(valid.Endpoints).IsEquivalentTo(["tls://control-gru.internal:4222"]);

        // Empty, absent, malformed, credentialed, unsorted, and duplicate endpoint
        // sets all fail the advertisement contract. (Uri normalizes scheme/host
        // case, so case is not an observable failure mode.)
        await Assert.That((valid with { Endpoints = [] }).IsValid(observedAt)).IsFalse();
        await Assert.That((valid with { Endpoints = null }).IsValid(observedAt)).IsFalse();
        await Assert.That((valid with { Endpoints = ["control-gru.internal"] }).IsValid(observedAt)).IsFalse();
        await Assert.That((valid with { Endpoints = ["tls://control-gru.internal"] }).IsValid(observedAt)).IsFalse();
        await Assert.That((valid with { Endpoints = ["tls://control-gru.internal:99999"] }).IsValid(observedAt)).IsFalse();
        await Assert.That((valid with { Endpoints = ["tls://control-gru.internal:4222/path"] }).IsValid(observedAt)).IsFalse();
        await Assert.That((valid with { Endpoints = ["https://user:secret@control-gru.internal:4222"] }).IsValid(observedAt)).IsFalse();
        await Assert.That((valid with { Endpoints = ["tls://b.internal:4222", "tls://a.internal:4222"] }).IsValid(observedAt)).IsFalse();
        await Assert.That((valid with { Endpoints = ["tls://a.internal:4222", "tls://a.internal:4222"] }).IsValid(observedAt)).IsFalse();
        await Assert.That((valid with
            {
                Endpoints = Enumerable.Range(0, 9).Select(index => $"tls://c{index}.internal:4222").ToArray()
            }).IsValid(observedAt)).IsFalse();

        // An endpoint change is content, not a duplicate: the same ordering key with
        // different endpoints is rejected as conflicting rather than ignored.
        var directory = new GlobalCellDirectory();
        await Assert.That(directory.Apply(valid, observedAt)).IsEqualTo(GlobalCellAdvertisementDisposition.Accepted);
        await Assert.That(directory.Apply(valid with
            {
                Endpoints = ["tls://control-gru-alt.internal:4222"]
            }, observedAt)).IsEqualTo(GlobalCellAdvertisementDisposition.Rejected);
    }

    [Test]
    public async Task DelayedAndReplayedAdvertisementsNeverResurrectOrDuplicate()
    {
        var observedAt = DateTimeOffset.UtcNow;
        var directory = new GlobalCellDirectory();
        var first = Advertisement("sfo", observedAt);

        await Assert.That(directory.Apply(first, observedAt)).IsEqualTo(GlobalCellAdvertisementDisposition.Accepted);

        // Reordered arrival: an older generation delivered after a newer one is stale.
        var newer = first with
        {
            AuthorityEpoch = first.AuthorityEpoch + 1,
            Sequence = 1,
        };
        await Assert.That(directory.Apply(newer, observedAt)).IsEqualTo(GlobalCellAdvertisementDisposition.Accepted);
        await Assert.That(directory.Apply(first, observedAt)).IsEqualTo(GlobalCellAdvertisementDisposition.Stale);

        // Delayed replay after the whole cell went stale cannot resurrect it: the
        // projection keeps the newest generation and stays stale by lease. The
        // replay time stays within the projection's wall-clock guard (snapshots
        // may never be observed in the future).
        var later = observedAt.AddSeconds(25);
        await Assert.That(directory.Apply(newer, later)).IsEqualTo(GlobalCellAdvertisementDisposition.Duplicate);
        var replayed = directory.Snapshot(later);
        replayed.Validate();
        await Assert.That(replayed.ActiveCells).IsEqualTo(0);
        await Assert.That(replayed.StaleCells).IsEqualTo(1);
        await Assert.That(replayed.Cells.Count(static cell => cell.Cell == "sfo")).IsEqualTo(1);
    }

    private static GlobalCellAdvertisement Advertisement(
        string cell,
        DateTimeOffset observedAt,
        IReadOnlyList<string>? endpoints = null) => new(
        1,
        cell,
        $"orchestrator-control-{cell}",
        $"{cell}-regional",
        7,
        11,
        1,
        ["authority", "regional-membership", "service-discovery"],
        new(3, 3, 0, 0, 0, 0, 0, 1, true, 100,
            RegionalRuntimeMembershipCondition.Healthy, observedAt),
        observedAt,
        observedAt.AddSeconds(20),
        endpoints ?? [$"tls://control-{cell}.internal:4222"]);
}

