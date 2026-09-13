using System.Globalization;
using System.Reflection;
using TerraScale.Orchestrator.ControlPlane.DatabasePlacement;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class DatabasePlacementEvaluatorTests
{
    [Test]
    public async Task Initial_catalog_accepts_one_two_three_and_twenty_region_shapes()
    {
        await Assert.That(DatabasePlacementPolicy.InitialCatalog.Regions.Select(entry => entry!.Region.Value))
            .IsEquivalentTo(new[] { "GRU", "SFO", "FRA" });
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
    public async Task Region_code_is_exact_uppercase_airport_text_and_never_normalized()
    {
        foreach (var value in new string?[]
                 {
                     null, "", "gru", "Gru", " GRU", "GRU ", "GR", "GRUU", "GRÜ", "G1U", "G-U", "G\0U",
                 })
        {
            await Assert.That(RegionCode.TryCreate(value, out var refused)).IsFalse();
            await Assert.That(refused.IsValid).IsFalse();
        }

        foreach (var value in new[] { "GRU", "SFO", "FRA", "IAD" })
        {
            await Assert.That(RegionCode.TryCreate(value, out var accepted)).IsTrue();
            await Assert.That(accepted.IsValid).IsTrue();
            await Assert.That(accepted.Value).IsEqualTo(value);
        }

        await Assert.That(() => RegionCode.FromValue("gru")).Throws<ArgumentException>();
    }

    [Test]
    public async Task Region_count_and_identity_admission_is_fail_closed()
    {
        var zero = Evaluate(Valid([]));
        var twentyOne = Evaluate(Valid(Regions(21)), Catalog(Regions(21)));
        var duplicate = Evaluate(Valid([Code("GRU"), Code("GRU")]), Catalog([Code("GRU"), Code("SFO")]));

        await Assert.That(Codes(zero)).Contains(DatabasePlacementErrorCode.ActiveRegionCountOutOfRange);
        await Assert.That(Codes(twentyOne)).Contains(DatabasePlacementErrorCode.ActiveRegionCountOutOfRange);
        await Assert.That(Codes(duplicate)).Contains(DatabasePlacementErrorCode.DuplicateActiveRegion);
    }

    [Test]
    public async Task Unknown_unavailable_and_residency_denied_regions_are_rejected()
    {
        var unavailable = new RegionCatalogEntry(Code("SFO"), Available: false, Permitted: true, ResidencyAllowed: true);
        var denied = new RegionCatalogEntry(Code("FRA"), Available: true, Permitted: false, ResidencyAllowed: false);
        var decision = Evaluate(Valid([Code("SFO"), Code("FRA"), Code("IAD")]),
            new RegionCatalog([unavailable, denied]));
        var codes = Codes(decision);

        await Assert.That(codes).Contains(DatabasePlacementErrorCode.RegionUnavailable);
        await Assert.That(codes).Contains(DatabasePlacementErrorCode.RegionNotPermitted);
        await Assert.That(codes).Contains(DatabasePlacementErrorCode.ResidencyDenied);
        await Assert.That(codes).Contains(DatabasePlacementErrorCode.UnknownRegion);
    }

    [Test]
    public async Task Conflicting_duplicate_catalog_entries_are_permutation_independent()
    {
        var first = new RegionCatalogEntry(Code("GRU"), Available: true, Permitted: false, ResidencyAllowed: true);
        var second = new RegionCatalogEntry(Code("GRU"), Available: false, Permitted: true, ResidencyAllowed: false);
        var request = Valid([Code("GRU")]);

        var forward = Evaluate(request, new RegionCatalog([first, second]));
        var reverse = Evaluate(request, new RegionCatalog([second, first]));

        await Assert.That(forward.Fingerprint).IsEqualTo(reverse.Fingerprint);
        await Assert.That(forward.Errors).IsEquivalentTo(reverse.Errors);
        await Assert.That(Codes(forward)).Contains(DatabasePlacementErrorCode.CatalogDuplicateRegion);
    }

    [Test]
    public async Task Each_partition_requires_exactly_the_selected_region_entries()
    {
        var regions = new[] { Code("GRU"), Code("SFO") };
        var partition = new LogicalPartitionPlacement(new("p0"), [
            Placement(regions[0], "p0"),
            Placement(regions[0], "p0"),
            Placement(Code("FRA"), "p0"),
        ]);
        var decision = Evaluate(new DatabasePlacementRequest(regions, [partition]));
        var codes = Codes(decision);

        await Assert.That(codes).Contains(DatabasePlacementErrorCode.PartitionRegionMissing);
        await Assert.That(codes).Contains(DatabasePlacementErrorCode.DuplicatePartitionRegion);
        await Assert.That(codes).Contains(DatabasePlacementErrorCode.PartitionRegionExtra);
    }

    [Test]
    public async Task Conflicting_duplicate_partition_regions_are_permutation_independent()
    {
        var region = Code("GRU");
        var partition = new PartitionId("p0");
        var first = new PartitionRegionPlacement(Code("GRU"), [Seat("a", region, partition)]);
        var second = new PartitionRegionPlacement(region, [
            Seat("b", region, partition, "domain-b"),
            Seat("c", region, partition, "domain-c"),
        ]);

        var forward = Evaluate(new DatabasePlacementRequest([region], [
            new LogicalPartitionPlacement(partition, [first, second]),
        ]));
        var reverse = Evaluate(new DatabasePlacementRequest([region], [
            new LogicalPartitionPlacement(partition, [second, first]),
        ]));

        await Assert.That(forward.Fingerprint).IsEqualTo(reverse.Fingerprint);
        await Assert.That(forward.Errors).IsEquivalentTo(reverse.Errors);
        await Assert.That(Codes(forward)).Contains(DatabasePlacementErrorCode.DuplicatePartitionRegion);
    }

    [Test]
    public async Task Replica_factor_and_seat_identity_are_exact()
    {
        var region = Code("GRU");
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
        var region = Code("GRU");
        var partition = new PartitionId("p0");
        var decision = Evaluate(new DatabasePlacementRequest([region], [
            new LogicalPartitionPlacement(partition, [new PartitionRegionPlacement(region, [
                new ActiveMemberSeat(new("a"), Code("SFO"), partition, new("domain-a")),
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
        var regions = new[] { Code("GRU"), Code("SFO") };
        var noBackup = Evaluate(Valid(regions));
        var validBackup = Evaluate(Valid(regions, new BackupPlacement(new("b0"), Code("FRA"))));
        var overlap = Evaluate(Valid(regions, new BackupPlacement(new("b0"), Code("SFO"))));
        var invalid = Evaluate(Valid(regions, new BackupPlacement(new("b0"), Code("FRA"),
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
    public async Task Decisions_are_permutation_and_culture_independent_with_stable_typed_reasons()
    {
        var regions = new[] { Code("GRU"), Code("SFO"), Code("FRA") };
        var request = new DatabasePlacementRequest(
            regions,
            [Partition(new("p0"), regions), Partition(new("p1"), regions)],
            new BackupPlacement(new("b"), Code("IAD")));
        var permuted = new DatabasePlacementRequest(
            regions.Reverse(),
            [Partition(new("p1"), regions.Reverse()), Partition(new("p0"), regions.Reverse())],
            new BackupPlacement(new("b"), Code("IAD")));
        var originalCulture = CultureInfo.CurrentCulture;
        DatabasePlacementDecision first;
        DatabasePlacementDecision replay;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("tr-TR");
            first = Evaluate(request);
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("ar-SA");
            replay = Evaluate(permuted);
        }
        finally
        {
            CultureInfo.CurrentCulture = originalCulture;
        }

        await Assert.That(first.Fingerprint).IsEqualTo(replay.Fingerprint);
        await Assert.That(first.Errors.Select(error => error.Code))
            .IsEquivalentTo(replay.Errors.Select(error => error.Code));
    }

    [Test]
    public async Task Placement_model_has_no_leadership_or_coordination_concepts()
    {
        var placementTypes = new[]
        {
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

    private static DatabasePlacementRequest Valid(IReadOnlyList<RegionCode> regions, BackupPlacement? backup = null) =>
        new(regions, [Partition(new("p0"), regions)], backup);

    private static LogicalPartitionPlacement Partition(PartitionId id, IEnumerable<RegionCode> regions) =>
        new(id, regions.Select(region => Placement(region, id.Value)));

    private static PartitionRegionPlacement Placement(RegionCode region, string partition) =>
        new(region, [Seat("member-a-" + region.Value, region, new(partition), "domain-a-" + region.Value),
            Seat("member-b-" + region.Value, region, new(partition), "domain-b-" + region.Value)]);

    private static ActiveMemberSeat Seat(string member, RegionCode region, PartitionId partition, string domain = "domain-a") =>
        new(new(member), region, partition, new(domain));

    private static RegionCode[] Regions(int count) =>
        Enumerable.Range(0, count).Select(index => index switch
        {
            0 => RegionCode.Gru,
            1 => RegionCode.Sfo,
            2 => RegionCode.Fra,
            _ => Code($"R{(char)('A' + ((index - 3) / 26))}{(char)('A' + ((index - 3) % 26))}"),
        }).ToArray();

    private static RegionCatalog Catalog(IEnumerable<RegionCode> regions) =>
        new(regions.Select(region => new RegionCatalogEntry(region, true, true, true)));

    private static RegionCode Code(string value) => RegionCode.FromValue(value);

    private static HashSet<DatabasePlacementErrorCode> Codes(DatabasePlacementDecision decision) =>
        decision.Errors.Select(static error => error.Code).ToHashSet();
}

