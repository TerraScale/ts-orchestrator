using System.Collections.Immutable;
using TerraScale.Orchestrator.ControlPlane.DatabasePlacement;

namespace TerraScale.Orchestrator.ControlPlane.EdgeRouting;

/// <summary>
/// The producer database and branch name format shared by the edge routing contracts: 1–63
/// lowercase ASCII letters, digits, or hyphens, starting and ending with an alphanumeric.
/// </summary>
public static class EdgeNameFormat
{
    public const int MaximumLength = 63;

    public static bool IsValid(string? value) =>
        value is { Length: >= 1 and <= MaximumLength } &&
        IsAlphanumeric(value[0]) && IsAlphanumeric(value[^1]) &&
        value.All(static character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-');

    private static bool IsAlphanumeric(char character) =>
        character is >= 'a' and <= 'z' or >= '0' and <= '9';
}

/// <summary>One Region's health entry of the <c>REGIONS</c> namespace document (ts-proxy HealthDoc).</summary>
public sealed record EdgeRegionHealth(
    RegionCode Region,
    bool Ok,
    int? LagMilliseconds,
    double Latitude,
    double Longitude);

/// <summary>One admitted public catalog entry published alongside the health map.</summary>
public sealed record EdgeRegionCatalogEntry(
    RegionCode Region,
    string Name,
    string Country,
    double Latitude,
    double Longitude);

/// <summary>
/// The value of the <c>REGIONS</c> namespace key <c>regions</c>: version 1, a writer-clock
/// update timestamp, the Region health map, and the immutable admitted catalog.
/// </summary>
public sealed class EdgeHealthDocument
{
    public EdgeHealthDocument(
        long updatedUnixSeconds,
        IEnumerable<EdgeRegionHealth>? regions,
        IEnumerable<EdgeRegionCatalogEntry>? catalog)
    {
        UpdatedUnixSeconds = updatedUnixSeconds;
        Regions = regions?.ToImmutableArray() ?? [];
        Catalog = catalog?.ToImmutableArray() ?? [];
    }

    public long UpdatedUnixSeconds { get; }
    public ImmutableArray<EdgeRegionHealth> Regions { get; }
    public ImmutableArray<EdgeRegionCatalogEntry> Catalog { get; }
}

/// <summary>
/// A database residency constraint: an opaque policy label (for example <c>eu-only</c>), an
/// explicit Region allow-list, or no constraint at all (a null <see cref="EdgeResidency"/>).
/// </summary>
public sealed class EdgeResidency
{
    private EdgeResidency(string? label, ImmutableArray<RegionCode> regions, bool isRegionList)
    {
        Label = label;
        Regions = regions;
        IsRegionList = isRegionList;
    }

    public string? Label { get; }
    public ImmutableArray<RegionCode> Regions { get; }
    public bool IsRegionList { get; }

    public static EdgeResidency FromLabel(string label) =>
        new(label ?? throw new ArgumentNullException(nameof(label)), [], false);

    public static EdgeResidency FromRegions(IEnumerable<RegionCode>? regions) =>
        new(null, (regions ?? []).ToImmutableArray(), true);
}

/// <summary>One ordered Region entry of a branch placement list; the home Region comes first.</summary>
public sealed record EdgeBranchPlacement(RegionCode Region, bool Read, bool Write);

/// <summary>The control-plane desired placement of one database, branch aware, default branch <c>main</c>.</summary>
public sealed class EdgeDatabasePlacement
{
    public EdgeDatabasePlacement(
        string databaseName,
        EdgeResidency? residency,
        int revision,
        IReadOnlyDictionary<string, IReadOnlyList<EdgeBranchPlacement>>? branches)
    {
        DatabaseName = databaseName ?? string.Empty;
        Residency = residency;
        Revision = revision;
        Branches = branches?.ToImmutableDictionary(static pair => pair.Key, static pair => pair.Value) ??
                   ImmutableDictionary<string, IReadOnlyList<EdgeBranchPlacement>>.Empty;
    }

    public string DatabaseName { get; }
    public EdgeResidency? Residency { get; }
    public int Revision { get; }
    public ImmutableDictionary<string, IReadOnlyList<EdgeBranchPlacement>> Branches { get; }
}

/// <summary>The versioned value of a <c>PLACEMENT</c> namespace key <c>db:&lt;name&gt;</c> (ADR 0050 §3, schema v2).</summary>
public sealed record EdgePlacementDocument(
    int Revision,
    long UpdatedUnixSeconds,
    EdgeResidency? Residency,
    ImmutableDictionary<string, IReadOnlyList<EdgeBranchPlacement>> Branches);

/// <summary>
/// The full desired edge-routing state of one pass: the health document plus every database
/// placement. This is the control-plane projection the publisher turns into KV writes.
/// </summary>
public sealed class EdgePlacementSnapshot
{
    public EdgePlacementSnapshot(
        EdgeHealthDocument health,
        IReadOnlyDictionary<string, EdgeDatabasePlacement>? databases)
    {
        Health = health ?? throw new ArgumentNullException(nameof(health));
        Databases = databases?.ToImmutableDictionary() ?? ImmutableDictionary<string, EdgeDatabasePlacement>.Empty;
    }

    public EdgeHealthDocument Health { get; }
    public ImmutableDictionary<string, EdgeDatabasePlacement> Databases { get; }
}

public enum EdgePlacementErrorCode
{
    SnapshotMissing = 1,
    DatabasesEmpty,
    HealthRegionInvalid,
    HealthRegionDuplicate,
    HealthLagInvalid,
    HealthCoordinatesInvalid,
    CatalogEmpty,
    CatalogTooLarge,
    CatalogEntryInvalid,
    CatalogDuplicateRegion,
    CatalogRegionSetMismatch,
    DatabaseNameInvalid,
    RevisionNegative,
    ResidencyLabelInvalid,
    ResidencyRegionsEmpty,
    ResidencyRegionInvalid,
    ResidencyRegionDuplicate,
    BranchNameInvalid,
    BranchRegionListEmpty,
    BranchRegionListTooLarge,
    BranchMapTooLarge,
    BranchRegionDuplicate,
    BranchRegionNotInCatalog,
}

/// <summary>One fail-closed rejection reason for an <see cref="EdgePlacementSnapshot"/>.</summary>
public sealed record EdgePlacementValidationError(
    EdgePlacementErrorCode Code,
    string? Database = null,
    string? Branch = null,
    RegionCode? Region = null,
    string? Detail = null);

/// <summary>
/// Fail-closed validation of a desired snapshot before anything is published: no residency
/// widening, no invented Regions, and no name outside the producer format is representable.
/// Every rule mirrors the ts-proxy consumer (placement.ts <c>normalizeHealth</c> and
/// <c>parseV2Placement</c>) exactly, so a validated document can never be one the consumer
/// rejects wholesale — a catalog/health split or an out-of-range coordinate nulls the ENTIRE
/// health document at the edge, and an over-sized branch map makes the placement record
/// unreadable, so each of those is rejected here before a byte reaches KV.
/// </summary>
public static class EdgePlacementValidation
{
    /// <summary>ts-proxy rejects a health document whose catalog is empty or longer than this.</summary>
    public const int MaximumCatalogEntries = 20;

    /// <summary>ts-proxy (parseV2Placement) fails closed above this many branches per database.</summary>
    public const int MaximumBranchesPerDatabase = 16;

    /// <summary>ts-proxy (parseV2Placement) fails closed above this many entries per branch list.</summary>
    public const int MaximumRegionsPerBranch = 20;

    public static ImmutableArray<EdgePlacementValidationError> Validate(EdgePlacementSnapshot? snapshot)
    {
        var errors = ImmutableArray.CreateBuilder<EdgePlacementValidationError>();
        if (snapshot is null)
        {
            errors.Add(new(EdgePlacementErrorCode.SnapshotMissing));
            return errors.ToImmutable();
        }

        // An empty databases collection is an operator error, never a full drain: a truncated,
        // wrong, or partially written file must not mass-delete every db: key of the namespace.
        if (snapshot.Databases.IsEmpty)
            errors.Add(new(EdgePlacementErrorCode.DatabasesEmpty));

        var catalogRegions = ValidateHealth(snapshot.Health, errors);
        foreach (var placement in snapshot.Databases.Values)
            ValidateDatabase(placement, catalogRegions, errors);
        return errors.ToImmutable();
    }

    private static HashSet<RegionCode> ValidateHealth(
        EdgeHealthDocument health,
        ImmutableArray<EdgePlacementValidationError>.Builder errors)
    {
        var seenHealthRegions = new HashSet<RegionCode>();
        foreach (var region in health.Regions)
        {
            if (!region.Region.IsValid)
                errors.Add(new(EdgePlacementErrorCode.HealthRegionInvalid, Region: region.Region));
            else if (!seenHealthRegions.Add(region.Region))
                errors.Add(new(EdgePlacementErrorCode.HealthRegionDuplicate, Region: region.Region));
            if (region.LagMilliseconds is < 0)
                errors.Add(new(EdgePlacementErrorCode.HealthLagInvalid, Region: region.Region));
            if (!IsLatitude(region.Latitude) || !IsLongitude(region.Longitude))
                errors.Add(new(EdgePlacementErrorCode.HealthCoordinatesInvalid, Region: region.Region));
        }

        if (health.Catalog.IsEmpty)
            errors.Add(new(EdgePlacementErrorCode.CatalogEmpty));
        else if (health.Catalog.Length > MaximumCatalogEntries)
            errors.Add(new(EdgePlacementErrorCode.CatalogTooLarge));

        var catalogRegions = new HashSet<RegionCode>();
        foreach (var entry in health.Catalog)
        {
            if (!entry.Region.IsValid ||
                string.IsNullOrEmpty(entry.Name) || entry.Name.Length > 128 || entry.Name.Trim() != entry.Name ||
                !IsCountryCode(entry.Country) ||
                !IsLatitude(entry.Latitude) || !IsLongitude(entry.Longitude))
                errors.Add(new(EdgePlacementErrorCode.CatalogEntryInvalid, Region: entry.Region));
            else if (!catalogRegions.Add(entry.Region))
                errors.Add(new(EdgePlacementErrorCode.CatalogDuplicateRegion, Region: entry.Region));
        }

        // The producer publishes one complete snapshot: ts-proxy nulls the ENTIRE health
        // document when the catalog and the regions map do not cover the same Region set.
        if (!catalogRegions.SetEquals(seenHealthRegions))
            errors.Add(new(EdgePlacementErrorCode.CatalogRegionSetMismatch));

        return catalogRegions;
    }

    private static void ValidateDatabase(
        EdgeDatabasePlacement placement,
        HashSet<RegionCode> catalogRegions,
        ImmutableArray<EdgePlacementValidationError>.Builder errors)
    {
        var database = placement.DatabaseName;
        if (!EdgeNameFormat.IsValid(database))
            errors.Add(new(EdgePlacementErrorCode.DatabaseNameInvalid, Database: database));
        if (placement.Revision < 0)
            errors.Add(new(EdgePlacementErrorCode.RevisionNegative, Database: database));

        if (placement.Residency is { } residency)
        {
            if (!residency.IsRegionList)
            {
                if (string.IsNullOrWhiteSpace(residency.Label) || residency.Label.Length > 64 ||
                    residency.Label.Any(static character =>
                        character is not (>= 'a' and <= 'z' or >= '0' and <= '9' or '-')))
                    errors.Add(new(EdgePlacementErrorCode.ResidencyLabelInvalid, Database: database));
            }
            else
            {
                var seen = new HashSet<RegionCode>();
                if (residency.Regions.IsEmpty)
                    errors.Add(new(EdgePlacementErrorCode.ResidencyRegionsEmpty, Database: database));
                foreach (var region in residency.Regions)
                {
                    if (!region.IsValid)
                        errors.Add(new(EdgePlacementErrorCode.ResidencyRegionInvalid, Database: database, Region: region));
                    else if (!seen.Add(region))
                        errors.Add(new(EdgePlacementErrorCode.ResidencyRegionDuplicate, Database: database, Region: region));
                }
            }
        }

        if (placement.Branches.Count == 0)
        {
            errors.Add(new(EdgePlacementErrorCode.BranchRegionListEmpty, Database: database, Branch: "(none)"));
            return;
        }

        if (placement.Branches.Count > MaximumBranchesPerDatabase)
            errors.Add(new(EdgePlacementErrorCode.BranchMapTooLarge, Database: database));

        foreach (var branch in placement.Branches)
        {
            if (!EdgeNameFormat.IsValid(branch.Key))
                errors.Add(new(EdgePlacementErrorCode.BranchNameInvalid, Database: database, Branch: branch.Key));
            if (branch.Value.Count == 0)
            {
                errors.Add(new(EdgePlacementErrorCode.BranchRegionListEmpty, Database: database, Branch: branch.Key));
                continue;
            }

            if (branch.Value.Count > MaximumRegionsPerBranch)
                errors.Add(new(EdgePlacementErrorCode.BranchRegionListTooLarge,
                    Database: database, Branch: branch.Key, Detail: $"{branch.Value.Count} entries"));

            var seen = new HashSet<RegionCode>();
            foreach (var entry in branch.Value)
            {
                if (!entry.Region.IsValid || !catalogRegions.Contains(entry.Region))
                    errors.Add(new(EdgePlacementErrorCode.BranchRegionNotInCatalog,
                        Database: database, Branch: branch.Key, Region: entry.Region));
                else if (!seen.Add(entry.Region))
                    errors.Add(new(EdgePlacementErrorCode.BranchRegionDuplicate,
                        Database: database, Branch: branch.Key, Region: entry.Region));
            }
        }
    }

    private static bool IsLatitude(double value) => double.IsFinite(value) && value is >= -90 and <= 90;

    private static bool IsLongitude(double value) => double.IsFinite(value) && value is >= -180 and <= 180;

    /// <summary>ts-proxy admits exactly two uppercase ASCII letters as a catalog country.</summary>
    private static bool IsCountryCode(string? value) =>
        value is { Length: 2 } && value[0] is >= 'A' and <= 'Z' && value[1] is >= 'A' and <= 'Z';
}
