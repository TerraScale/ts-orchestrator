using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NATS.Client.KeyValueStore;
using TerraScale.Orchestrator.ControlPlane.DatabasePlacement;
using TerraScale.Orchestrator.ControlPlane.EdgeRouting;
using TerraScale.Orchestrator.Nodes;

namespace TerraScale.Orchestrator.ControlPlane.TerraBase;

/// <summary>
/// The edge-routing projection of live placement state (ADR 0050 §6): branch placements
/// from the accepted evaluator decision of every intent, filtered by live member health —
/// a Region serves reads with at least one healthy seat and writes only while its leader
/// is healthy. The fail-closed output contract of <see cref="EdgePlacementValidation"/>
/// is the boundary: a snapshot this class cannot build honestly is never handed to the
/// publisher.
/// </summary>
internal sealed class TerraBasePlacementEdgeSource(Func<CancellationToken, Task<PlacementWorldSnapshot>> readWorld) : IEdgePlacementSource
{
    /// <summary>The fixed public catalog: the three canonical Regions with their coordinates.</summary>
    private static readonly (string Name, string Country, double Latitude, double Longitude)[] Catalog =
    [
        ("Sao Paulo", "BR", -23.55, -46.63),
        ("San Francisco", "US", 37.77, -122.42),
        ("Frankfurt", "DE", 50.11, 8.68),
    ];

    public async Task<EdgePlacementSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default) =>
        Project(await readWorld(cancellationToken).ConfigureAwait(false));

    /// <summary>
    /// The deterministic projection the reconciler also fingerprints: every database's
    /// <c>main</c> branch lists each active Region with its read/write eligibility, and
    /// the health document covers exactly the catalog Regions.
    /// </summary>
    internal static EdgePlacementSnapshot Project(PlacementWorldSnapshot world)
    {
        var regionsByDatabase = new Dictionary<string, HashSet<RegionCode>>(StringComparer.Ordinal);
        var healthyByDatabaseAndRegion = new Dictionary<(string Database, RegionCode Region), (bool Read, bool Write)>();
        foreach (var database in world.Databases)
        {
            var intent = database.Intent;
            var regions = PlacementTopology.CanonicalRegions
                .Where(region => intent.ActiveRegions.Contains(region.Value, StringComparer.Ordinal))
                .ToArray();
            regionsByDatabase[intent.Database] = [.. regions];
            foreach (var region in regions)
            {
                var seats = database.Members
                    .Where(member => member.Seat?.Region == region)
                    .ToArray();
                var read = seats.Any(static member => member.Healthy);
                var write = seats.Any(static member => member.Healthy && member.IsLeader);
                healthyByDatabaseAndRegion[(intent.Database, region)] = (read, write);
            }
        }

        var catalog = PlacementTopology.CanonicalRegions.Select((region, index) => new EdgeRegionCatalogEntry(
            region,
            Catalog[index].Name,
            Catalog[index].Country,
            Catalog[index].Latitude,
            Catalog[index].Longitude));
        var health = new EdgeHealthDocument(
            DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            PlacementTopology.CanonicalRegions.Select((region, index) => new EdgeRegionHealth(
                region,
                healthyByDatabaseAndRegion.Any(pair => pair.Key.Region == region && pair.Value.Read),
                0,
                Catalog[index].Latitude,
                Catalog[index].Longitude)),
            catalog);

        var databases = new Dictionary<string, EdgeDatabasePlacement>(StringComparer.Ordinal);
        foreach (var pair in regionsByDatabase)
        {
            var intent = world.Databases.Single(database => database.Intent.Database == pair.Key).Intent;
            // Every active Region stays listed even when unhealthy: the entry routes
            // nothing (read=false, write=false) instead of shrinking the placement.
            var branches = new Dictionary<string, IReadOnlyList<EdgeBranchPlacement>>(StringComparer.Ordinal)
            {
                ["main"] = PlacementTopology.CanonicalRegions
                    .Where(region => intent.ActiveRegions.Contains(region.Value, StringComparer.Ordinal))
                    .Select(region =>
                    {
                        var (read, write) = healthyByDatabaseAndRegion[(pair.Key, region)];
                        return new EdgeBranchPlacement(region, read, write);
                    })
                    .ToArray(),
            };
            databases[pair.Key] = new(
                pair.Key,
                EdgeResidency.FromRegions(pair.Value),
                checked((int)Math.Min(int.MaxValue, intent.Revision)),
                branches);
        }
        return new(health, databases);
    }

    private static IEnumerable<string> ResidencyRegions(EdgeDatabasePlacement database)
    {
        if (database.Residency is null)
            return [];
        return database.Residency.Regions.Select(static region => region.Value).Order(StringComparer.Ordinal);
    }

    /// <summary>
    /// The change-detection fingerprint of one projected snapshot: the health clock and
    /// writer timestamps are excluded, so only placement-affecting change republishes.
    /// </summary>
    internal static string Fingerprint(EdgePlacementSnapshot snapshot)
    {
        var builder = new StringBuilder();
        foreach (var database in snapshot.Databases.Values.OrderBy(static value => value.DatabaseName, StringComparer.Ordinal))
        {
            builder.Append(database.DatabaseName).Append('\n')
                .Append("rev:").Append(database.Revision).Append('\n')
                .Append("res:").Append(string.Join(",", ResidencyRegions(database))).Append('\n');
            foreach (var branch in database.Branches.OrderBy(static pair => pair.Key, StringComparer.Ordinal))
            {
                builder.Append("br:").Append(branch.Key).Append('\n');
                foreach (var entry in branch.Value)
                    builder.Append(entry.Region.Value).Append(entry.Read ? 'r' : '-').Append(entry.Write ? 'w' : '-').Append('\n');
            }
        }
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(builder.ToString())));
    }
}

/// <summary>
/// Reads the complete placement world — intents plus fleet observations, attributed to
/// members through the durable instance records — for one reconciler tick or edge pass.
/// </summary>
internal static class PlacementWorld
{
    public static async Task<PlacementWorldSnapshot> ReadAsync(
        INatsKVStore delivery,
        IMemberHostFleet fleet,
        CancellationToken cancellationToken)
    {
        var intents = await ReadIntentsAsync(delivery, cancellationToken).ConfigureAwait(false);
        var observations = await fleet.ObserveAsync(cancellationToken).ConfigureAwait(false);
        var byInstance = observations
            .GroupBy(static observation => observation.ResourceId.InstanceId, StringComparer.Ordinal)
            .ToDictionary(static group => group.Key, static group => group.First(), StringComparer.Ordinal);
        var databases = new List<PlacementDatabaseSnapshot>(intents.Count);
        foreach (var intent in intents)
        {
            var seats = PlacementTopology.Seats(intent).ToDictionary(static seat => seat.MemberId, StringComparer.Ordinal);
            var members = new List<PlacementMemberSnapshot>();
            foreach (var member in await ReadMemberStatesAsync(delivery, intent.Database, cancellationToken).ConfigureAwait(false))
            {
                var observation = member.Document.InstanceId is { } instance && byInstance.TryGetValue(instance, out var attributed)
                    ? attributed
                    : null;
                members.Add(new(
                    member.Document,
                    member.Revision,
                    observation,
                    seats.GetValueOrDefault(member.Document.MemberId),
                    observation is { State: MemberHostState.Running, MemberHealth.Up: true },
                    observation?.MemberHealth.Role is "leader"));
            }
            databases.Add(new(intent, members));
        }
        return new(databases, observations);
    }

    /// <summary>Enumerates and parses every <c>placement.intent.*</c> key; invalid documents are skipped.</summary>
    public static async Task<IReadOnlyList<PlacementIntentDocument>> ReadIntentsAsync(
        INatsKVStore delivery,
        CancellationToken cancellationToken)
    {
        var intents = new List<(long Revision, PlacementIntentDocument Intent)>();
        await foreach (var key in delivery.GetKeysAsync(
            ["placement.intent.>"],
            new NATS.Client.KeyValueStore.NatsKVWatchOpts { IgnoreDeletes = true },
            cancellationToken).ConfigureAwait(false))
        {
            PlacementIntentDocument? intent;
            try
            {
                var entry = await delivery.GetEntryAsync<string>(key, cancellationToken: cancellationToken).ConfigureAwait(false);
                entry.EnsureSuccess();
                intent = JsonSerializer.Deserialize(
                    entry.Value ?? string.Empty, TerraBasePlacementJsonContext.Default.PlacementIntentDocument);
                intent?.Validate();
            }
            catch (Exception exception) when (
                exception is NatsKVException or JsonException or InvalidOperationException)
            {
                continue;
            }
            if (intent is { } valid)
                intents.Add((valid.Revision, valid));
        }
        return intents
            .OrderBy(static intent => intent.Revision)
            .ThenBy(static intent => intent.Intent.Database, StringComparer.Ordinal)
            .Select(static intent => intent.Intent)
            .ToList();
    }

    /// <summary>Reads every <c>placement.state.{database}.*</c> record with its KV revision for CAS writes.</summary>
    public static async Task<IReadOnlyList<PlacementMemberRecord>> ReadMemberStatesAsync(
        INatsKVStore delivery,
        string database,
        CancellationToken cancellationToken)
    {
        var records = new List<PlacementMemberRecord>();
        var prefix = $"placement.state.{database}.";
        await foreach (var key in delivery.GetKeysAsync(
            [prefix + ">"],
            new NatsKVWatchOpts { IgnoreDeletes = true },
            cancellationToken).ConfigureAwait(false))
        {
            PlacementMemberStateDocument? document;
            ulong revision;
            try
            {
                var entry = await delivery.GetEntryAsync<string>(key, cancellationToken: cancellationToken).ConfigureAwait(false);
                entry.EnsureSuccess();
                revision = entry.Revision;
                document = JsonSerializer.Deserialize(
                    entry.Value ?? string.Empty, TerraBasePlacementJsonContext.Default.PlacementMemberStateDocument);
                document?.Validate();
            }
            catch (Exception exception) when (
                exception is NatsKVException or JsonException or InvalidOperationException)
            {
                continue;
            }
            if (document is { } valid)
                records.Add(new(valid, revision));
        }
        return records;
    }
}

/// <summary>One database's intent plus its attributed member views for one pass.</summary>
internal sealed record PlacementWorldSnapshot(
    IReadOnlyList<PlacementDatabaseSnapshot> Databases,
    IReadOnlyList<MemberHostObservation> Observations);

internal sealed record PlacementDatabaseSnapshot(
    PlacementIntentDocument Intent,
    IReadOnlyList<PlacementMemberSnapshot> Members);

/// <summary>
/// One member's durable state joined with its live observation. <see cref="Observation"/>
/// null means the fleet no longer reports the recorded instance — the death signal.
/// </summary>
internal sealed record PlacementMemberSnapshot(
    PlacementMemberStateDocument State,
    ulong Revision,
    MemberHostObservation? Observation,
    PlacementTopology.DesiredSeat? Seat,
    bool Healthy,
    bool IsLeader);
