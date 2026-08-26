using System.Collections.Concurrent;
using System.Text.Json.Serialization;

namespace TerraScale.Orchestrator.Messaging;

internal sealed record GlobalCellAdvertisement(
    int SchemaVersion,
    string Cell,
    string Cluster,
    string AuthorityId,
    long AuthorityEpoch,
    long AuthorityRevision,
    long Sequence,
    IReadOnlyList<string> Capabilities,
    RegionalRuntimeMembershipHealth Membership,
    DateTimeOffset ObservedAt,
    DateTimeOffset LeaseExpiresAt,
    IReadOnlyList<string>? Endpoints = null)
{
    internal static readonly TimeSpan SemanticLease = TimeSpan.FromSeconds(20);

    internal bool IsValid(DateTimeOffset now)
    {
        if (Membership is null) return false;
        try
        {
            Membership.Validate();
        }
        catch (InvalidOperationException)
        {
            return false;
        }

        return SchemaVersion == 1 &&
               GlobalNatsTopology.IsCellToken(Cell) &&
               Cluster == $"orchestrator-control-{Cell}" &&
               AuthorityId == $"{Cell}-regional" &&
               AuthorityEpoch > 0 && AuthorityRevision > 0 && Sequence > 0 &&
               Capabilities is { Count: > 0 and <= 64 } &&
               Capabilities.All(IsCapabilityToken) &&
               Capabilities.SequenceEqual(Capabilities.Order(StringComparer.Ordinal), StringComparer.Ordinal) &&
               Capabilities.Distinct(StringComparer.Ordinal).Count() == Capabilities.Count &&
               Membership.ObservedAt == ObservedAt &&
               Membership.ActiveControllers > 0 && Membership.AuthorityLeaders == 1 &&
               ObservedAt <= now.AddMinutes(1) &&
               LeaseExpiresAt == ObservedAt + SemanticLease &&
               Endpoints is { Count: >= 1 and <= 8 } &&
               Endpoints.All(IsControlEndpoint) &&
               Endpoints.SequenceEqual(Endpoints.Order(StringComparer.Ordinal), StringComparer.Ordinal) &&
               Endpoints.Distinct(StringComparer.Ordinal).Count() == Endpoints.Count;
    }

    private static bool IsCapabilityToken(string capability) =>
        capability is { Length: >= 1 and <= 63 } &&
        capability[0] != '-' && capability[^1] != '-' &&
        capability.All(static character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-');

    /// <summary>
    /// A cell advertisement endpoint: an absolute lowercase URI with an explicit port,
    /// no path, query, fragment, or user information. These are the cell's control-plane
    /// endpoints as composition supplies them — never invented by the runtime.
    /// </summary>
    internal static bool IsControlEndpoint(string? endpoint)
    {
        if (endpoint is not { Length: >= 8 and <= 253 }) return false;
        if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var uri)) return false;
        return uri.Scheme is { Length: >= 3 and <= 16 } &&
               uri.Scheme.All(static character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '+') &&
               uri.Scheme == uri.Scheme.ToLowerInvariant() &&
               !string.IsNullOrEmpty(uri.Host) &&
               uri.Host == uri.Host.ToLowerInvariant() &&
               uri.Port is > 0 and < 65536 &&
               uri.PathAndQuery is "" or "/" &&
               string.IsNullOrEmpty(uri.Query) &&
               string.IsNullOrEmpty(uri.Fragment) &&
               string.IsNullOrEmpty(uri.UserInfo);
    }
}

internal enum GlobalCellAdvertisementDisposition
{
    Accepted = 0,
    Duplicate = 1,
    Stale = 2,
    Rejected = 3
}

[JsonConverter(typeof(JsonStringEnumConverter<GlobalCellDirectoryCondition>))]
internal enum GlobalCellDirectoryCondition
{
    Unavailable = 0,
    Degraded = 1,
    Healthy = 2
}

internal sealed record GlobalCellDirectoryEntry(
    string Cell,
    string Cluster,
    string AuthorityId,
    long AuthorityEpoch,
    long AuthorityRevision,
    long Sequence,
    IReadOnlyList<string> Capabilities,
    RegionalRuntimeMembershipHealth Membership,
    DateTimeOffset ObservedAt,
    DateTimeOffset LeaseExpiresAt,
    bool IsStale,
    IReadOnlyList<string> Endpoints);

internal sealed record GlobalCellDirectorySnapshot(
    int SchemaVersion,
    DateTimeOffset ObservedAt,
    int ActiveCells,
    int StaleCells,
    long RejectedAdvertisements,
    GlobalCellDirectoryCondition Condition,
    IReadOnlyList<GlobalCellDirectoryEntry> Cells)
{
    internal void Validate()
    {
        var active = Cells.Count(static cell => !cell.IsStale);
        var stale = Cells.Count - active;
        var condition = active == 0
            ? GlobalCellDirectoryCondition.Unavailable
            : stale == 0 && Cells.All(static cell =>
                cell.Membership.Condition == RegionalRuntimeMembershipCondition.Healthy)
                ? GlobalCellDirectoryCondition.Healthy
                : GlobalCellDirectoryCondition.Degraded;
        if (SchemaVersion != 1 || ObservedAt == default ||
            ObservedAt > DateTimeOffset.UtcNow.AddMinutes(1) ||
            ActiveCells != active || StaleCells != stale || RejectedAdvertisements < 0 ||
            Condition != condition ||
            Cells.Any(cell =>
                cell.IsStale != (cell.LeaseExpiresAt <= ObservedAt) ||
                !new GlobalCellAdvertisement(
                    1,
                    cell.Cell,
                    cell.Cluster,
                    cell.AuthorityId,
                    cell.AuthorityEpoch,
                    cell.AuthorityRevision,
                    cell.Sequence,
                    cell.Capabilities,
                    cell.Membership,
                    cell.ObservedAt,
                    cell.LeaseExpiresAt,
                    cell.Endpoints).IsValid(ObservedAt)) ||
            Cells.Select(static cell => cell.Cell).Distinct(StringComparer.Ordinal).Count() != Cells.Count ||
            !Cells.SequenceEqual(Cells.OrderBy(static cell => cell.Cell, StringComparer.Ordinal)))
        {
            throw new InvalidOperationException("The global cell directory projection is invalid.");
        }
    }
}

/// <summary>
/// Converges durable regional advertisements into a read-only global projection.
/// Regional state remains authoritative; expiry only marks a projection stale.
/// </summary>
internal sealed class GlobalCellDirectory
{
    private readonly ConcurrentDictionary<string, GlobalCellAdvertisement> advertisements =
        new(StringComparer.Ordinal);
    private long rejectedAdvertisements;

    internal GlobalCellAdvertisementDisposition Apply(
        string sourceKey,
        GlobalCellAdvertisement advertisement,
        DateTimeOffset? appliedAt = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceKey);
        ArgumentNullException.ThrowIfNull(advertisement);
        if (!GlobalNatsTopology.IsCellToken(advertisement.Cell) ||
            sourceKey != GlobalNatsTopology.CellAdvertisementKey(advertisement.Cell))
        {
            Interlocked.Increment(ref rejectedAdvertisements);
            return GlobalCellAdvertisementDisposition.Rejected;
        }
        return Apply(advertisement, appliedAt);
    }

    internal GlobalCellAdvertisementDisposition Apply(
        GlobalCellAdvertisement advertisement,
        DateTimeOffset? appliedAt = null)
    {
        ArgumentNullException.ThrowIfNull(advertisement);
        var now = appliedAt ?? DateTimeOffset.UtcNow;
        if (!advertisement.IsValid(now))
        {
            Interlocked.Increment(ref rejectedAdvertisements);
            return GlobalCellAdvertisementDisposition.Rejected;
        }

        while (true)
        {
            if (!advertisements.TryGetValue(advertisement.Cell, out var current))
            {
                if (advertisements.TryAdd(advertisement.Cell, advertisement))
                    return GlobalCellAdvertisementDisposition.Accepted;
                continue;
            }

            var order = Compare(advertisement, current);
            if (advertisement.LeaseExpiresAt <= now && current.LeaseExpiresAt > now)
            {
                Interlocked.Increment(ref rejectedAdvertisements);
                return GlobalCellAdvertisementDisposition.Stale;
            }
            if (order < 0)
            {
                Interlocked.Increment(ref rejectedAdvertisements);
                return GlobalCellAdvertisementDisposition.Stale;
            }
            if (order == 0)
            {
                if (Same(advertisement, current)) return GlobalCellAdvertisementDisposition.Duplicate;
                Interlocked.Increment(ref rejectedAdvertisements);
                return GlobalCellAdvertisementDisposition.Rejected;
            }
            if (advertisements.TryUpdate(advertisement.Cell, advertisement, current))
                return GlobalCellAdvertisementDisposition.Accepted;
        }
    }

    internal GlobalCellDirectorySnapshot Snapshot(DateTimeOffset? observedAt = null)
    {
        var now = observedAt ?? DateTimeOffset.UtcNow;
        var cells = advertisements.Values
            .OrderBy(static advertisement => advertisement.Cell, StringComparer.Ordinal)
            .Select(advertisement => new GlobalCellDirectoryEntry(
                advertisement.Cell,
                advertisement.Cluster,
                advertisement.AuthorityId,
                advertisement.AuthorityEpoch,
                advertisement.AuthorityRevision,
                advertisement.Sequence,
                advertisement.Capabilities,
                advertisement.Membership,
                advertisement.ObservedAt,
                advertisement.LeaseExpiresAt,
                advertisement.LeaseExpiresAt <= now,
                advertisement.Endpoints ?? Array.Empty<string>()))
            .ToArray();
        var active = cells.Count(static cell => !cell.IsStale);
        var stale = cells.Length - active;
        var condition = active == 0
            ? GlobalCellDirectoryCondition.Unavailable
            : stale == 0 && cells.All(static cell =>
                cell.Membership.Condition == RegionalRuntimeMembershipCondition.Healthy)
                ? GlobalCellDirectoryCondition.Healthy
                : GlobalCellDirectoryCondition.Degraded;
        return new(1, now, active, stale, Interlocked.Read(ref rejectedAdvertisements), condition, cells);
    }

    internal void Remove(string cell) => advertisements.TryRemove(cell, out _);

    internal void Reject() => Interlocked.Increment(ref rejectedAdvertisements);

    private static int Compare(GlobalCellAdvertisement left, GlobalCellAdvertisement right)
    {
        var epoch = left.AuthorityEpoch.CompareTo(right.AuthorityEpoch);
        if (epoch != 0) return epoch;
        var revision = left.AuthorityRevision.CompareTo(right.AuthorityRevision);
        if (revision != 0) return revision;
        return left.Sequence.CompareTo(right.Sequence);
    }

    private static bool Same(GlobalCellAdvertisement left, GlobalCellAdvertisement right) =>
        left.SchemaVersion == right.SchemaVersion &&
        left.Cell == right.Cell &&
        left.Cluster == right.Cluster &&
        left.AuthorityId == right.AuthorityId &&
        left.AuthorityEpoch == right.AuthorityEpoch &&
        left.AuthorityRevision == right.AuthorityRevision &&
        left.Sequence == right.Sequence &&
        left.Capabilities.SequenceEqual(right.Capabilities, StringComparer.Ordinal) &&
        left.Membership == right.Membership &&
        left.ObservedAt == right.ObservedAt &&
        left.LeaseExpiresAt == right.LeaseExpiresAt &&
        (left.Endpoints ?? Array.Empty<string>()).SequenceEqual(
            right.Endpoints ?? Array.Empty<string>(), StringComparer.Ordinal);
}

[JsonSerializable(typeof(GlobalCellAdvertisement))]
[JsonSerializable(typeof(GlobalCellDirectorySnapshot))]
internal sealed partial class GlobalCellDirectoryJsonContext : JsonSerializerContext;
