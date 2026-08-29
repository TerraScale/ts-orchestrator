using System.Reflection;
using TerraScale.Orchestrator.ControlPlane.DatabasePlacement;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class DatabasePlacementEvaluatorTests
{
    [Test]
    public async Task Initial_catalog_accepts_one_two_three_and_twenty_region_shapes()
    {
        foreach (var count in new[] { 1, 2, 3, 20 })
        {
            var regions = Regions(count);
            var decision = Evaluate(Valid(regions), Catalog(regions));
            await Assert.That(decision.Accepted).IsTrue();
            await Assert.That(decision.Errors).IsEmpty();
            await Assert.That(decision.Facts.Single(fact => fact.Code == DatabasePlacementFactCode.EveryPartitionHasExactReplicationFactor).Satisfied).IsTrue();
        }
    }

    [Test]
    public async Task Region_count_and_identity_admission_is_fail_closed()
    {
        var zero = Evaluate(Valid([]));
        var twentyOne = Evaluate(Valid(Regions(21)), Catalog(Regions(21)));
        var duplicate = Evaluate(Valid([new("gru"), new("GRU")]), Catalog([new("gru"), new("sfo")]));

        await Assert.That(Codes(zero)).Contains(DatabasePlacementErrorCode.ActiveRegionCountOutOfRange);
        await Assert.That(Codes(twentyOne)).Contains(DatabasePlacementErrorCode.ActiveRegionCountOutOfRange);
        await Assert.That(Codes(duplicate)).Contains(DatabasePlacementErrorCode.DuplicateActiveRegion);
    }

    [Test]
    public async Task Unknown_unavailable_and_residency_denied_regions_are_rejected()
    {
        var unavailable = new RegionCatalogEntry(new("sfo"), Available: false, Permitted: true, ResidencyAllowed: true);
        var denied = new RegionCatalogEntry(new("fra"), Available: true, Permitted: false, ResidencyAllowed: false);
        var decision = Evaluate(Valid([new("sfo"), new("fra"), new("unknown")]),
            new RegionCatalog([unavailable, denied, new("unknown", true, true, false)]));
        var codes = Codes(decision);

        await Assert.That(codes).Contains(DatabasePlacementErrorCode.RegionUnavailable);
        await Assert.That(codes).Contains(DatabasePlacementErrorCode.RegionNotPermitted);
        await Assert.That(codes).Contains(DatabasePlacementErrorCode.ResidencyDenied);
        await Assert.That(codes).Contains(DatabasePlacementErrorCode.UnknownRegion);
    }

    [Test]
    public async Task Each_partition_requires_exactly_the_selected_region_entries()
    {
        var regions = new[] { new RegionId("gru"), new RegionId("sfo") };
        var partition = new LogicalPartitionPlacement(new("p0"), [
            Placement(regions[0], "p0"),
            Placement(regions[0], "p0"),
            Placement(new("fra"), "p0"),
        ]);
        var decision = Evaluate(new DatabasePlacementRequest(regions, [partition]));
        var codes = Codes(decision);

        await Assert.That(codes).Contains(DatabasePlacementErrorCode.PartitionRegionMissing);
        await Assert.That(codes).Contains(DatabasePlacementErrorCode.DuplicatePartitionRegion);
        await Assert.That(codes).Contains(DatabasePlacementErrorCode.PartitionRegionExtra);
    }

    [Test]
    public async Task Replica_factor_and_seat_identity_are_exact()
    {
        var region = new RegionId("gru");
        var partition = new PartitionId("p0");
        var missing = Evaluate(new DatabasePlacementRequest([region], [
            new LogicalPartitionPlacement(partition, [new PartitionRegionPlacement(region, [Seat("a", region, partition)])]),
        ]));
        var extra = Evaluate(new DatabasePlacementRequest([region], [
            new LogicalPartitionPlacement(partition, [new PartitionRegionPlacement(region, [
                Seat("a", region, partition), Seat("b", region, partition), Seat("c", region, partition),
            ])]),
        ]));
        var duplicate = Evaluate(new DatabasePlacementRequest([region], [
            new LogicalPartitionPlacement(partition, [new PartitionRegionPlacement(region, [
                Seat("a", region, partition), Seat("a", region, partition),
            ])]),
        ]));

        await Assert.That(Codes(missing)).Contains(DatabasePlacementErrorCode.SeatMissing);
        await Assert.That(Codes(extra)).Contains(DatabasePlacementErrorCode.SeatExtra);
        await Assert.That(Codes(duplicate)).Contains(DatabasePlacementErrorCode.DuplicateSeat);
        await Assert.That(missing.Facts.Single(fact => fact.Code == DatabasePlacementFactCode.EveryPartitionHasExactReplicationFactor).Satisfied).IsFalse();
    }

    [Test]
    public async Task Seats_must_match_their_partition_region_be_active_and_use_independent_domains()
    {
        var region = new RegionId("gru");
        var partition = new PartitionId("p0");
        var decision = Evaluate(new DatabasePlacementRequest([region], [
            new LogicalPartitionPlacement(partition, [new PartitionRegionPlacement(region, [
                new ActiveMemberSeat(new("a"), new("sfo"), partition, new("domain-a")),
                new ActiveMemberSeat(new("b"), region, new("other-partition"), new("domain-a")),
            ])]),
        ]));
        var codes = Codes(decision);

        await Assert.That(codes).Contains(DatabasePlacementErrorCode.SeatRegionMismatch);
        await Assert.That(codes).Contains(DatabasePlacementErrorCode.SeatPartitionMismatch);
        await Assert.That(codes).Contains(DatabasePlacementErrorCode.FailureDomainNotIndependent);

        var inactive = Evaluate(new DatabasePlacementRequest([region], [
            new LogicalPartitionPlacement(partition, [new PartitionRegionPlacement(region, [
                new ActiveMemberSeat(new("a"), region, partition, new("domain-a"), IsActive: false),
                Seat("b", region, partition, "domain-b"),
            ])]),
        ]));
        await Assert.That(Codes(inactive)).Contains(DatabasePlacementErrorCode.SeatInactive);
    }

    [Test]
    public async Task Backup_is_optional_independent_and_cannot_become_active()
    {
        var regions = new[] { new RegionId("gru"), new RegionId("sfo") };
        var noBackup = Evaluate(Valid(regions));
        var validBackup = Evaluate(Valid(regions, new BackupPlacement(new("b0"), new("fra"))));
        var overlap = Evaluate(Valid(regions, new BackupPlacement(new("b0"), new("SFO"))));
        var invalid = Evaluate(Valid(regions, new BackupPlacement(new("b0"), new("fra"),
            IsReadOnly: false, IsImmutable: false, IsVoting: true,
            PromotionPolicy: BackupPromotionPolicy.PromoteInPlace)));

        await Assert.That(noBackup.Accepted).IsTrue();
        await Assert.That(validBackup.Accepted).IsTrue();
        await Assert.That(Codes(overlap)).Contains(DatabasePlacementErrorCode.BackupOverlapsActiveRegion);
        await Assert.That(Codes(invalid)).Contains(DatabasePlacementErrorCode.BackupMustBeReadOnly);
        await Assert.That(Codes(invalid)).Contains(DatabasePlacementErrorCode.BackupMustBeImmutable);
        await Assert.That(Codes(invalid)).Contains(DatabasePlacementErrorCode.BackupMustBeNonVoting);
        await Assert.That(Codes(invalid)).Contains(DatabasePlacementErrorCode.BackupPromotionForbidden);
    }

    [Test]
    public async Task Decisions_are_permutation_and_culture independent_with_stable_typed_reasons()
    {
        var regions = new[] { new RegionId("gru"), new RegionId("sfo"), new RegionId("fra") };
        var first = Evaluate(new DatabasePlacementRequest(regions, [
            Partition(new("p0"), regions), Partition(new("p1"), regions),
        ], new BackupPlacement(new("b"), new("iad"))));
        var permuted = new DatabasePlacementRequest(regions.Reverse(), [
            Partition(new("p1"), regions.Reverse()), Partition(new("p0"), regions.Reverse()),
        ], new BackupPlacement(new("b"), new("iad")));
        var replay = Evaluate(permuted);

        await Assert.That(first.Fingerprint).IsEqualTo(replay.Fingerprint);
        await Assert.That(first.Errors.Select(error => error.Code)).IsEquivalentTo(replay.Errors.Select(error => error.Code));
    }

    [Test]
    public async Task Placement_model_has_no_leadership_or_coordination_concepts()
    {
        var placementTypes = new[] {
            typeof(DatabasePlacementRequest), typeof(LogicalPartitionPlacement),
            typeof(PartitionRegionPlacement), typeof(ActiveMemberSeat), typeof(BackupPlacement),
        };
        var forbidden = new[] { "leader", "primary", "owner", "coordinator" };
        var names = placementTypes.SelectMany(type => type.GetProperties().Select(property => property.Name)
                .Concat(type.GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)
                    .Select(field => field.Name)))
            .Select(static name => name.ToLowerInvariant()).ToArray();

        await Assert.That(names.Any(name => forbidden.Any(name.Contains))).IsFalse();
    }

    private static DatabasePlacementDecision Evaluate(DatabasePlacementRequest request, RegionCatalog? catalog = null) =>
        DatabasePlacementEvaluator.Evaluate(request, catalog);

    private static DatabasePlacementRequest Valid(IReadOnlyList<RegionId> regions, BackupPlacement? backup = null) =>
        new(regions, [Partition(new("p0"), regions)], backup);

    private static LogicalPartitionPlacement Partition(PartitionId id, IEnumerable<RegionId> regions) =>
        new(id, regions.Select(region => Placement(region, id.Value)));

    private static PartitionRegionPlacement Placement(RegionId region, string partition) =>
        new(region, [Seat("member-a-" + region.Value, region, new(partition), "domain-a-" + region.Value),
            Seat("member-b-" + region.Value, region, new(partition), "domain-b-" + region.Value)]);

    private static ActiveMemberSeat Seat(string member, RegionId region, PartitionId partition, string domain = "domain-a") =>
        new(new(member), region, partition, new(domain));

    private static RegionId[] Regions(int count) =>
        Enumerable.Range(0, count).Select(index => new RegionId(index switch {
            0 => "gru", 1 => "sfo", 2 => "fra", _ => "region-" + index,
        })).ToArray();

    private static RegionCatalog Catalog(IEnumerable<RegionId> regions) =>
        new(regions.Select(region => new RegionCatalogEntry(region, true, true, true)));

    private static HashSet<DatabasePlacementErrorCode> Codes(DatabasePlacementDecision decision) =>
        decision.Errors.Select(static error => error.Code).ToHashSet();
}
