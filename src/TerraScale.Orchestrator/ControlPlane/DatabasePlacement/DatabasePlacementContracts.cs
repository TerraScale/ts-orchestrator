using System.Collections.Immutable;

namespace TerraScale.Orchestrator.ControlPlane.DatabasePlacement;

/// <summary>The fixed replication and active-Region limits for a production database.</summary>
public static class DatabasePlacementPolicy
{
    public const int MinimumActiveRegionCount = 1;
    public const int MaximumActiveRegionCount = 20;
    public const int ActiveReplicationFactor = 2;

    public static RegionCatalog InitialCatalog { get; } = RegionCatalog.CreateInitial();
}

public readonly record struct RegionId(string Value);
public readonly record struct PartitionId(string Value);
public readonly record struct MemberId(string Value);
public readonly record struct FailureDomainId(string Value);
public readonly record struct BackupId(string Value);

public sealed record RegionCatalogEntry(
    RegionId Region,
    bool Available,
    bool Permitted,
    bool ResidencyAllowed);

/// <summary>An immutable snapshot of the catalog used for one pure placement evaluation.</summary>
public sealed class RegionCatalog
{
    private readonly ImmutableArray<RegionCatalogEntry?> _regions;

    public RegionCatalog(IEnumerable<RegionCatalogEntry?>? regions) =>
        _regions = regions?.ToImmutableArray() ?? ImmutableArray<RegionCatalogEntry?>.Empty;

    public IReadOnlyList<RegionCatalogEntry?> Regions => _regions;

    internal static RegionCatalog CreateInitial() => new([
        new RegionCatalogEntry(new RegionId("gru"), true, true, true),
        new RegionCatalogEntry(new RegionId("sfo"), true, true, true),
        new RegionCatalogEntry(new RegionId("fra"), true, true, true),
    ]);
}

public sealed record ActiveMemberSeat(
    MemberId Member,
    RegionId Region,
    PartitionId Partition,
    FailureDomainId FailureDomain,
    bool IsActive = true);

public sealed class PartitionRegionPlacement
{
    private readonly ImmutableArray<ActiveMemberSeat?> _seats;

    public PartitionRegionPlacement(RegionId region, IEnumerable<ActiveMemberSeat?>? seats)
    {
        Region = region;
        _seats = seats?.ToImmutableArray() ?? ImmutableArray<ActiveMemberSeat?>.Empty;
    }

    public RegionId Region { get; }
    public IReadOnlyList<ActiveMemberSeat?> Seats => _seats;
}

public sealed class LogicalPartitionPlacement
{
    private readonly ImmutableArray<PartitionRegionPlacement?> _regions;

    public LogicalPartitionPlacement(PartitionId partition, IEnumerable<PartitionRegionPlacement?>? regions)
    {
        Partition = partition;
        _regions = regions?.ToImmutableArray() ?? ImmutableArray<PartitionRegionPlacement?>.Empty;
    }

    public PartitionId Partition { get; }
    public IReadOnlyList<PartitionRegionPlacement?> Regions => _regions;
}

public enum BackupPromotionPolicy
{
    NeverPromote = 0,
    PromoteInPlace = 1,
}

public sealed record BackupPlacement(
    BackupId Backup,
    RegionId Region,
    bool IsReadOnly = true,
    bool IsImmutable = true,
    bool IsVoting = false,
    BackupPromotionPolicy PromotionPolicy = BackupPromotionPolicy.NeverPromote);

/// <summary>An immutable customer placement intent; null Backup means no backup is requested.</summary>
public sealed class DatabasePlacementRequest
{
    private readonly ImmutableArray<RegionId> _activeRegions;
    private readonly ImmutableArray<LogicalPartitionPlacement?> _partitions;

    public DatabasePlacementRequest(
        IEnumerable<RegionId>? activeRegions,
        IEnumerable<LogicalPartitionPlacement?>? partitions,
        BackupPlacement? backup = null)
    {
        _activeRegions = activeRegions?.ToImmutableArray() ?? ImmutableArray<RegionId>.Empty;
        _partitions = partitions?.ToImmutableArray() ?? ImmutableArray<LogicalPartitionPlacement?>.Empty;
        Backup = backup;
    }

    public IReadOnlyList<RegionId> ActiveRegions => _activeRegions;
    public IReadOnlyList<LogicalPartitionPlacement?> Partitions => _partitions;
    public BackupPlacement? Backup { get; }
}

public enum DatabasePlacementErrorCode
{
    RequestMissing = 1,
    CatalogDuplicateRegion,
    ActiveRegionCountOutOfRange,
    ActiveRegionIdMissing,
    DuplicateActiveRegion,
    UnknownRegion,
    RegionUnavailable,
    RegionNotPermitted,
    ResidencyDenied,
    LogicalPartitionMissing,
    PartitionIdMissing,
    DuplicateLogicalPartition,
    PartitionRegionMissing,
    PartitionRegionExtra,
    DuplicatePartitionRegion,
    SeatMissing,
    SeatExtra,
    SeatNull,
    SeatIdMissing,
    DuplicateSeat,
    SeatRegionMismatch,
    SeatPartitionMismatch,
    SeatInactive,
    FailureDomainMissing,
    FailureDomainNotIndependent,
    BackupIdMissing,
    BackupRegionMissing,
    BackupOverlapsActiveRegion,
    BackupMustBeReadOnly,
    BackupMustBeImmutable,
    BackupMustBeNonVoting,
    BackupPromotionForbidden,
}

public sealed record DatabasePlacementError(
    DatabasePlacementErrorCode Code,
    RegionId? Region = null,
    PartitionId? Partition = null,
    MemberId? Member = null,
    string? Detail = null);

public enum DatabasePlacementFactCode
{
    RequestPresent = 1,
    ActiveRegionCountWithinBounds,
    ActiveRegionsUnique,
    ActiveRegionsCatalogQualified,
    LogicalPartitionsPresent,
    EveryPartitionHasExactlySelectedRegions,
    EveryPartitionHasExactReplicationFactor,
    SeatsIndependentlyFailureDomainPlaced,
    BackupPolicyQualified,
}

public sealed record DatabasePlacementQualificationFact(DatabasePlacementFactCode Code, bool Satisfied);

public sealed class DatabasePlacementDecision
{
    private readonly ImmutableArray<DatabasePlacementError> _errors;
    private readonly ImmutableArray<DatabasePlacementQualificationFact> _facts;

    internal DatabasePlacementDecision(
        IEnumerable<DatabasePlacementError> errors,
        IEnumerable<DatabasePlacementQualificationFact> facts,
        string fingerprint)
    {
        _errors = errors.ToImmutableArray();
        _facts = facts.ToImmutableArray();
        Fingerprint = fingerprint;
    }

    public bool Accepted => _errors.IsEmpty;
    public bool IsAccepted => Accepted;
    public IReadOnlyList<DatabasePlacementError> Errors => _errors;
    public IReadOnlyList<DatabasePlacementQualificationFact> Facts => _facts;
    public IReadOnlyList<DatabasePlacementQualificationFact> QualificationFacts => _facts;
    public string Fingerprint { get; }
    public string PlacementFingerprint => Fingerprint;
}
