using System.Collections.Immutable;
using System.Globalization;
using System.Text;

namespace TerraScale.Orchestrator.ControlPlane.DatabasePlacement;

/// <summary>Pure, deterministic admission of a database placement intent.</summary>
public static class DatabasePlacementEvaluator
{
    public static DatabasePlacementDecision Evaluate(
        DatabasePlacementRequest? request,
        RegionCatalog? catalog = null)
    {
        var errors = new List<DatabasePlacementError>();
        var facts = new List<DatabasePlacementQualificationFact>();
        var effectiveCatalog = catalog ?? DatabasePlacementPolicy.InitialCatalog;

        if (request is null)
        {
            errors.Add(new(DatabasePlacementErrorCode.RequestMissing));
            AddFacts(facts, requestPresent: false, regionCount: false, uniqueRegions: false,
                catalogQualified: false, partitionsPresent: false, regionsComplete: false,
                replicasExact: false, domainsIndependent: false, backupQualified: false);
            return Finish(errors, facts);
        }

        var catalogEntries = effectiveCatalog.Regions;
        var catalogByKey = new Dictionary<string, RegionCatalogEntry>(StringComparer.Ordinal);
        if (catalogEntries.Any(static entry => entry is null))
            errors.Add(new(DatabasePlacementErrorCode.CatalogEntryMissing));
        foreach (var group in catalogEntries.Where(static entry => entry is not null).Cast<RegionCatalogEntry>()
                     .GroupBy(static entry => Key(entry.Region), StringComparer.Ordinal)
                     .OrderBy(static group => group.Key, StringComparer.Ordinal))
        {
            if (group.Count() != 1)
            {
                errors.Add(new(DatabasePlacementErrorCode.CatalogDuplicateRegion, group.First().Region));
                continue;
            }

            catalogByKey.Add(group.Key, group.Single());
        }

        var activeRegions = request.ActiveRegions;
        var activeKeys = activeRegions.Select(Key).ToArray();
        var activeRegionCountValid = activeRegions.Count is >= DatabasePlacementPolicy.MinimumActiveRegionCount
            and <= DatabasePlacementPolicy.MaximumActiveRegionCount;
        if (!activeRegionCountValid)
            errors.Add(new(DatabasePlacementErrorCode.ActiveRegionCountOutOfRange,
                Detail: activeRegions.Count.ToString(CultureInfo.InvariantCulture)));

        foreach (var region in activeRegions.OrderBy(Key, StringComparer.Ordinal))
        {
            if (!region.IsValid)
                errors.Add(new(DatabasePlacementErrorCode.ActiveRegionIdMissing, region));
        }

        foreach (var group in activeRegions.GroupBy(Key, StringComparer.Ordinal).OrderBy(static group => group.Key, StringComparer.Ordinal))
        {
            if (group.Count() > 1)
                errors.Add(new(DatabasePlacementErrorCode.DuplicateActiveRegion,
                    group.OrderBy(static region => region.Value ?? string.Empty, StringComparer.Ordinal).First()));
        }

        var uniqueRegions = activeKeys.Distinct(StringComparer.Ordinal).Count() == activeRegions.Count &&
            activeRegions.All(static region => region.IsValid);
        var catalogQualified = true;
        foreach (var region in activeRegions.OrderBy(Key, StringComparer.Ordinal))
        {
            var key = Key(region);
            if (!catalogByKey.TryGetValue(key, out var entry))
            {
                errors.Add(new(DatabasePlacementErrorCode.UnknownRegion, region));
                catalogQualified = false;
                continue;
            }

            if (!entry.Available)
            {
                errors.Add(new(DatabasePlacementErrorCode.RegionUnavailable, region));
                catalogQualified = false;
            }
            if (!entry.Permitted)
            {
                errors.Add(new(DatabasePlacementErrorCode.RegionNotPermitted, region));
                catalogQualified = false;
            }
            if (!entry.ResidencyAllowed)
            {
                errors.Add(new(DatabasePlacementErrorCode.ResidencyDenied, region));
                catalogQualified = false;
            }
        }
        catalogQualified &= !errors.Any(static error => error.Code is
            DatabasePlacementErrorCode.CatalogDuplicateRegion or DatabasePlacementErrorCode.CatalogEntryMissing);

        var partitions = request.Partitions;
        var partitionsPresent = partitions.Count > 0 && partitions.All(static partition => partition is not null);
        if (!partitionsPresent)
            errors.Add(new(DatabasePlacementErrorCode.LogicalPartitionMissing));

        foreach (var group in partitions.Where(static partition => partition is not null).Cast<LogicalPartitionPlacement>()
                     .GroupBy(static partition => Key(partition.Partition), StringComparer.Ordinal)
                     .OrderBy(static group => group.Key, StringComparer.Ordinal))
        {
            if (group.Count() > 1)
                errors.Add(new(DatabasePlacementErrorCode.DuplicateLogicalPartition,
                    Partition: group.OrderBy(static partition => partition.Partition.Value ?? string.Empty, StringComparer.Ordinal)
                        .First().Partition));
        }

        var regionsComplete = partitionsPresent;
        var replicasExact = partitionsPresent;
        var domainsIndependent = partitionsPresent;
        foreach (var partition in partitions.Where(static partition => partition is not null).Cast<LogicalPartitionPlacement>()
                     .OrderBy(static partition => Key(partition.Partition), StringComparer.Ordinal))
        {
            if (string.IsNullOrWhiteSpace(partition.Partition.Value))
            {
                errors.Add(new(DatabasePlacementErrorCode.PartitionIdMissing, Partition: partition.Partition));
                regionsComplete = false;
            }

            var placements = partition.Regions;
            foreach (var placement in placements.Where(static placement => placement is null))
            {
                _ = placement;
                errors.Add(new(DatabasePlacementErrorCode.PartitionRegionExtra, Partition: partition.Partition));
                regionsComplete = false;
            }

            var validPlacements = placements.Where(static placement => placement is not null).Cast<PartitionRegionPlacement>().ToArray();
            foreach (var group in validPlacements.GroupBy(static placement => Key(placement.Region), StringComparer.Ordinal)
                         .OrderBy(static group => group.Key, StringComparer.Ordinal))
            {
                if (group.Count() > 1)
                {
                    errors.Add(new(DatabasePlacementErrorCode.DuplicatePartitionRegion,
                        group.First().Region,
                        partition.Partition));
                    regionsComplete = false;
                }
            }

            var expected = activeRegions.OrderBy(Key, StringComparer.Ordinal).ToArray();
            var expectedKeys = expected.Select(Key).ToHashSet(StringComparer.Ordinal);
            foreach (var region in expected)
            {
                var matches = validPlacements.Where(placement => StringComparer.Ordinal.Equals(Key(placement.Region), Key(region))).ToArray();
                if (matches.Length == 0)
                {
                    errors.Add(new(DatabasePlacementErrorCode.PartitionRegionMissing, region, partition.Partition));
                    regionsComplete = false;
                    continue;
                }

                if (matches.Length == 1)
                {
                    EvaluateSeats(matches[0], partition.Partition, region, errors, ref replicasExact,
                        ref domainsIndependent);
                }
                else
                {
                    replicasExact = false;
                    domainsIndependent = false;
                }
            }

            foreach (var placement in validPlacements.OrderBy(static placement => Key(placement.Region), StringComparer.Ordinal))
            {
                if (!expectedKeys.Contains(Key(placement.Region)))
                {
                    errors.Add(new(DatabasePlacementErrorCode.PartitionRegionExtra, placement.Region, partition.Partition));
                    regionsComplete = false;
                }
            }
        }

        var backupQualified = EvaluateBackup(request.Backup, activeKeys, errors);
        AddFacts(facts, requestPresent: true, activeRegionCountValid, uniqueRegions, catalogQualified,
            partitionsPresent, regionsComplete, replicasExact, domainsIndependent, backupQualified);
        return Finish(errors, facts);
    }

    private static void EvaluateSeats(
        PartitionRegionPlacement placement,
        PartitionId partition,
        RegionCode region,
        ICollection<DatabasePlacementError> errors,
        ref bool replicasExact,
        ref bool domainsIndependent)
    {
        var seats = placement.Seats;
        if (seats.Count < DatabasePlacementPolicy.ActiveReplicationFactor)
        {
            errors.Add(new(DatabasePlacementErrorCode.SeatMissing, region, partition,
                Detail: seats.Count.ToString(CultureInfo.InvariantCulture)));
            replicasExact = false;
        }
        else if (seats.Count > DatabasePlacementPolicy.ActiveReplicationFactor)
        {
            errors.Add(new(DatabasePlacementErrorCode.SeatExtra, region, partition,
                Detail: seats.Count.ToString(CultureInfo.InvariantCulture)));
            replicasExact = false;
        }

        var concrete = new List<ActiveMemberSeat>();
        foreach (var seat in seats)
        {
            if (seat is null)
            {
                errors.Add(new(DatabasePlacementErrorCode.SeatNull, region, partition));
                replicasExact = false;
                domainsIndependent = false;
                continue;
            }
            concrete.Add(seat);
            if (string.IsNullOrWhiteSpace(seat.Member.Value))
            {
                errors.Add(new(DatabasePlacementErrorCode.SeatIdMissing, region, partition, seat.Member));
                replicasExact = false;
            }
            if (!StringComparer.Ordinal.Equals(Key(seat.Region), Key(region)))
            {
                errors.Add(new(DatabasePlacementErrorCode.SeatRegionMismatch, region, partition, seat.Member));
                replicasExact = false;
            }
            if (!StringComparer.Ordinal.Equals(Key(seat.Partition), Key(partition)))
            {
                errors.Add(new(DatabasePlacementErrorCode.SeatPartitionMismatch, region, partition, seat.Member));
                replicasExact = false;
            }
            if (!seat.IsActive)
            {
                errors.Add(new(DatabasePlacementErrorCode.SeatInactive, region, partition, seat.Member));
                replicasExact = false;
                domainsIndependent = false;
            }
            if (string.IsNullOrWhiteSpace(seat.FailureDomain.Value))
            {
                errors.Add(new(DatabasePlacementErrorCode.FailureDomainMissing, region, partition, seat.Member));
                replicasExact = false;
                domainsIndependent = false;
            }
        }

        foreach (var group in concrete.GroupBy(static seat => Key(seat.Member), StringComparer.Ordinal)
                     .OrderBy(static group => group.Key, StringComparer.Ordinal))
        {
            if (group.Count() > 1)
            {
                errors.Add(new(DatabasePlacementErrorCode.DuplicateSeat, region, partition,
                    group.OrderBy(static seat => seat.Member.Value ?? string.Empty, StringComparer.Ordinal).First().Member));
                replicasExact = false;
            }
        }

        var activeDomains = concrete.Where(static seat => seat.IsActive && !string.IsNullOrWhiteSpace(seat.FailureDomain.Value))
            .Select(static seat => Key(seat.FailureDomain)).ToArray();
        if (activeDomains.Length != activeDomains.Distinct(StringComparer.Ordinal).Count())
        {
            errors.Add(new(DatabasePlacementErrorCode.FailureDomainNotIndependent, region, partition));
            domainsIndependent = false;
        }
    }

    private static bool EvaluateBackup(
        BackupPlacement? backup,
        IReadOnlyList<string> activeKeys,
        ICollection<DatabasePlacementError> errors)
    {
        if (backup is null)
            return true;

        var qualified = true;
        if (string.IsNullOrWhiteSpace(backup.Backup.Value))
        {
            errors.Add(new(DatabasePlacementErrorCode.BackupIdMissing));
            qualified = false;
        }
        if (string.IsNullOrWhiteSpace(backup.Region.Value))
        {
            errors.Add(new(DatabasePlacementErrorCode.BackupRegionMissing));
            qualified = false;
        }
        if (activeKeys.Contains(Key(backup.Region), StringComparer.Ordinal))
        {
            errors.Add(new(DatabasePlacementErrorCode.BackupOverlapsActiveRegion, backup.Region));
            qualified = false;
        }
        if (!backup.IsReadOnly)
        {
            errors.Add(new(DatabasePlacementErrorCode.BackupMustBeReadOnly, backup.Region));
            qualified = false;
        }
        if (!backup.IsImmutable)
        {
            errors.Add(new(DatabasePlacementErrorCode.BackupMustBeImmutable, backup.Region));
            qualified = false;
        }
        if (backup.IsVoting)
        {
            errors.Add(new(DatabasePlacementErrorCode.BackupMustBeNonVoting, backup.Region));
            qualified = false;
        }
        if (backup.PromotionPolicy != BackupPromotionPolicy.NeverPromote)
        {
            errors.Add(new(DatabasePlacementErrorCode.BackupPromotionForbidden, backup.Region));
            qualified = false;
        }
        return qualified;
    }

    private static void AddFacts(
        ICollection<DatabasePlacementQualificationFact> facts,
        bool requestPresent,
        bool regionCount,
        bool uniqueRegions,
        bool catalogQualified,
        bool partitionsPresent,
        bool regionsComplete,
        bool replicasExact,
        bool domainsIndependent,
        bool backupQualified)
    {
        facts.Add(new(DatabasePlacementFactCode.RequestPresent, requestPresent));
        facts.Add(new(DatabasePlacementFactCode.ActiveRegionCountWithinBounds, regionCount));
        facts.Add(new(DatabasePlacementFactCode.ActiveRegionsUnique, uniqueRegions));
        facts.Add(new(DatabasePlacementFactCode.ActiveRegionsCatalogQualified, catalogQualified));
        facts.Add(new(DatabasePlacementFactCode.LogicalPartitionsPresent, partitionsPresent));
        facts.Add(new(DatabasePlacementFactCode.EveryPartitionHasExactlySelectedRegions, regionsComplete));
        facts.Add(new(DatabasePlacementFactCode.EveryPartitionHasExactReplicationFactor, replicasExact));
        facts.Add(new(DatabasePlacementFactCode.SeatsIndependentlyFailureDomainPlaced, domainsIndependent));
        facts.Add(new(DatabasePlacementFactCode.BackupPolicyQualified, backupQualified));
    }

    private static DatabasePlacementDecision Finish(
        IReadOnlyList<DatabasePlacementError> errors,
        IReadOnlyList<DatabasePlacementQualificationFact> facts)
    {
        var orderedErrors = errors
            .OrderBy(static error => error.Code)
            .ThenBy(static error => Key(error.Region), StringComparer.Ordinal)
            .ThenBy(static error => Key(error.Partition), StringComparer.Ordinal)
            .ThenBy(static error => Key(error.Member), StringComparer.Ordinal)
            .ThenBy(static error => error.Detail, StringComparer.Ordinal)
            .ToImmutableArray();
        var builder = new StringBuilder("accepted=").Append(orderedErrors.IsEmpty ? '1' : '0');
        foreach (var error in orderedErrors)
            builder.Append('|').Append(error.Code).Append(':').Append(Key(error.Region)).Append(':')
                .Append(Key(error.Partition)).Append(':').Append(Key(error.Member)).Append(':').Append(error.Detail ?? string.Empty);
        foreach (var fact in facts)
            builder.Append('|').Append(fact.Code).Append('=').Append(fact.Satisfied ? '1' : '0');
        return new DatabasePlacementDecision(orderedErrors, facts, builder.ToString());
    }

    private static string Key(RegionCode id) => id.Value;
    private static string Key(PartitionId id) => Key(id.Value);
    private static string Key(MemberId id) => Key(id.Value);
    private static string Key(FailureDomainId id) => Key(id.Value);
    private static string Key(RegionCode? id) => id.HasValue ? Key(id.Value) : string.Empty;
    private static string Key(PartitionId? id) => id.HasValue ? Key(id.Value) : string.Empty;
    private static string Key(MemberId? id) => id.HasValue ? Key(id.Value) : string.Empty;
    private static string Key(string? value) => value?.Trim().ToUpperInvariant() ?? string.Empty;
}
