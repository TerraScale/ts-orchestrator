using System.Text;
using System.Text.Json;
using TerraScale.Orchestrator.ControlPlane.DatabasePlacement;

namespace TerraScale.Orchestrator.ControlPlane.EdgeRouting;

/// <summary>
/// Exact wire serialization of the two KV documents. The health document mirrors the ts-proxy
/// <c>HealthDoc</c> shape; the placement document is ADR 0050 §3 schema v2. Maps and catalog
/// entries are written in Region-code order and branches in name order so the output bytes are
/// deterministic; branch Region entries preserve placement order (home Region first).
/// </summary>
internal static class EdgePlacementJson
{
    public const int HealthSchemaVersion = 1;
    public const int PlacementSchemaVersion = 2;

    private static readonly JsonWriterOptions WriterOptions = new() { Indented = false };
    private static readonly JsonDocumentOptions ReaderOptions = new()
    {
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Disallow,
        MaxDepth = 16,
    };

    public static string WriteHealthDocument(EdgeHealthDocument document)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer, WriterOptions))
        {
            writer.WriteStartObject();
            writer.WriteNumber("v", HealthSchemaVersion);
            writer.WriteNumber("updated", document.UpdatedUnixSeconds);

            writer.WriteStartObject("regions");
            foreach (var region in document.Regions.OrderBy(static entry => entry.Region.Value, StringComparer.Ordinal))
            {
                writer.WritePropertyName(region.Region.Value);
                writer.WriteStartObject();
                writer.WriteBoolean("ok", region.Ok);
                if (region.LagMilliseconds is { } lagMilliseconds)
                    writer.WriteNumber("lag_ms", lagMilliseconds);
                writer.WriteNumber("lat", region.Latitude);
                writer.WriteNumber("lon", region.Longitude);
                writer.WriteEndObject();
            }

            writer.WriteEndObject();
            writer.WriteStartArray("catalog");
            foreach (var entry in document.Catalog.OrderBy(static entry => entry.Region.Value, StringComparer.Ordinal))
            {
                writer.WriteStartObject();
                writer.WriteString("code", entry.Region.Value);
                writer.WriteString("name", entry.Name);
                writer.WriteString("country", entry.Country);
                writer.WriteNumber("lat", entry.Latitude);
                writer.WriteNumber("lon", entry.Longitude);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    public static string WritePlacementDocument(EdgePlacementDocument document)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer, WriterOptions))
        {
            writer.WriteStartObject();
            writer.WriteNumber("v", PlacementSchemaVersion);
            writer.WriteNumber("rev", document.Revision);
            writer.WriteNumber("u", document.UpdatedUnixSeconds);

            if (document.Residency is { } residency)
            {
                if (residency.IsRegionList)
                {
                    writer.WriteStartArray("res");
                    foreach (var region in residency.Regions.OrderBy(static code => code.Value, StringComparer.Ordinal))
                        writer.WriteStringValue(region.Value);
                    writer.WriteEndArray();
                }
                else
                {
                    writer.WriteString("res", residency.Label);
                }
            }
            else
            {
                writer.WriteNull("res");
            }

            writer.WritePropertyName("br");
            writer.WriteStartObject();
            foreach (var branch in document.Branches.OrderBy(static pair => pair.Key, StringComparer.Ordinal))
            {
                writer.WritePropertyName(branch.Key);
                writer.WriteStartArray();
                foreach (var entry in branch.Value)
                {
                    writer.WriteStartObject();
                    writer.WriteString("region", entry.Region.Value);
                    writer.WriteBoolean("read", entry.Read);
                    writer.WriteBoolean("write", entry.Write);
                    writer.WriteEndObject();
                }

                writer.WriteEndArray();
            }

            writer.WriteEndObject();
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    /// <summary>
    /// Reads the routing revision of a currently published <c>db:&lt;name&gt;</c> value when it is a
    /// readable v2 document. Legacy v1 values and unreadable values carry no revision and never
    /// constrain the source.
    /// </summary>
    public static bool TryReadPublishedRevision(string? value, out int revision)
    {
        revision = 0;
        if (string.IsNullOrEmpty(value)) return false;
        try
        {
            using var document = JsonDocument.Parse(value, ReaderOptions);
            var root = document.RootElement;
            return root.ValueKind == JsonValueKind.Object &&
                   root.TryGetProperty("v", out var version) &&
                   version.ValueKind == JsonValueKind.Number &&
                   version.TryGetInt32(out var schemaVersion) &&
                   schemaVersion == PlacementSchemaVersion &&
                   root.TryGetProperty("rev", out var revisionValue) &&
                   revisionValue.ValueKind == JsonValueKind.Number &&
                   revisionValue.TryGetInt32(out revision) &&
                   revision >= 0;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    /// <summary>
    /// Reads a JSON edge placement snapshot document — the operational input of the
    /// <c>edge-routing-publish</c> command. The shape mirrors the two wire documents: the health
    /// document (<c>updated</c>, <c>regions</c>, <c>catalog</c>) plus a <c>databases</c> map of
    /// placement documents keyed by database name. Malformed input throws
    /// (<see cref="JsonException"/> for invalid JSON, <see cref="FormatException"/> for
    /// well-formed JSON with a wrong shape); semantic acceptance is
    /// <see cref="EdgePlacementValidation"/>'s job, so a parsed snapshot is still validated
    /// fail-closed before anything is published.
    /// </summary>
    public static EdgePlacementSnapshot ReadSnapshot(string json)
    {
        using var document = JsonDocument.Parse(json, ReaderOptions);
        var root = document.RootElement;
        Require(root.ValueKind == JsonValueKind.Object, "the root must be an object");
        Require(root.TryGetProperty("updated", out var updated) && updated.ValueKind == JsonValueKind.Number,
            "'updated' (unix seconds) must be a number");

        var regions = new List<EdgeRegionHealth>();
        if (root.TryGetProperty("regions", out var regionsValue) && regionsValue.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in regionsValue.EnumerateObject())
            {
                Require(RegionCode.TryCreate(property.Name, out var region),
                    $"region key '{property.Name}' must be a canonical Region code");
                var entry = property.Value;
                Require(entry.ValueKind == JsonValueKind.Object, $"region '{property.Name}' must be an object");
                regions.Add(new EdgeRegionHealth(
                    region,
                    RequireBoolean(entry, "ok"),
                    entry.TryGetProperty("lag_ms", out var lag) && lag.ValueKind == JsonValueKind.Number
                        ? lag.GetInt32()
                        : null,
                    RequireDouble(entry, "lat"),
                    RequireDouble(entry, "lon")));
            }
        }

        var catalog = new List<EdgeRegionCatalogEntry>();
        if (root.TryGetProperty("catalog", out var catalogValue) && catalogValue.ValueKind == JsonValueKind.Array)
        {
            foreach (var entry in catalogValue.EnumerateArray())
            {
                Require(entry.ValueKind == JsonValueKind.Object, "each catalog entry must be an object");
                Require(RegionCode.TryCreate(RequireString(entry, "code"), out var region),
                    $"catalog code '{RequireString(entry, "code")}' must be a canonical Region code");
                catalog.Add(new EdgeRegionCatalogEntry(
                    region,
                    RequireString(entry, "name"),
                    RequireString(entry, "country"),
                    RequireDouble(entry, "lat"),
                    RequireDouble(entry, "lon")));
            }
        }

        var databases = new Dictionary<string, EdgeDatabasePlacement>(StringComparer.Ordinal);
        if (root.TryGetProperty("databases", out var databasesValue) && databasesValue.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in databasesValue.EnumerateObject())
                databases[property.Name] = ReadDatabase(property.Name, property.Value);
        }

        return new EdgePlacementSnapshot(new EdgeHealthDocument(updated.GetInt64(), regions, catalog), databases);
    }

    private static EdgeDatabasePlacement ReadDatabase(string name, JsonElement value)
    {
        Require(value.ValueKind == JsonValueKind.Object, $"database '{name}' must be an object");
        Require(value.TryGetProperty("revision", out var revision) && revision.ValueKind == JsonValueKind.Number,
            $"database '{name}' 'revision' must be a number");
        var branches = new Dictionary<string, IReadOnlyList<EdgeBranchPlacement>>(StringComparer.Ordinal);
        if (value.TryGetProperty("branches", out var branchesValue))
        {
            Require(branchesValue.ValueKind == JsonValueKind.Object, $"database '{name}' branches must be an object");
            foreach (var branch in branchesValue.EnumerateObject())
            {
                Require(branch.Value.ValueKind == JsonValueKind.Array,
                    $"database '{name}' branch '{branch.Name}' must be an array");
                var entries = new List<EdgeBranchPlacement>();
                foreach (var entry in branch.Value.EnumerateArray())
                {
                    Require(entry.ValueKind == JsonValueKind.Object,
                        $"database '{name}' branch '{branch.Name}' entries must be objects");
                    var region = RequireString(entry, "region");
                    Require(RegionCode.TryCreate(region, out var parsed),
                        $"database '{name}' branch '{branch.Name}' region '{region}' must be a canonical Region code");
                    entries.Add(new EdgeBranchPlacement(parsed, RequireBoolean(entry, "read"), RequireBoolean(entry, "write")));
                }

                branches[branch.Name] = entries;
            }
        }

        return new EdgeDatabasePlacement(name, ReadResidency(name, value), revision.GetInt32(), branches);
    }

    private static EdgeResidency? ReadResidency(string database, JsonElement value)
    {
        if (!value.TryGetProperty("residency", out var residency) || residency.ValueKind == JsonValueKind.Null)
            return null;
        if (residency.ValueKind == JsonValueKind.String)
            return EdgeResidency.FromLabel(residency.GetString()!);
        Require(residency.ValueKind == JsonValueKind.Array,
            $"database '{database}' 'residency' must be a label, a Region array, or null");
        var regions = new List<RegionCode>();
        foreach (var entry in residency.EnumerateArray())
        {
            Require(entry.ValueKind == JsonValueKind.String,
                $"database '{database}' 'residency' entries must be Region code strings");
            Require(RegionCode.TryCreate(entry.GetString()!, out var region),
                $"database '{database}' residency entry '{entry.GetString()}' must be a canonical Region code");
            regions.Add(region);
        }

        return EdgeResidency.FromRegions(regions);
    }

    private static string RequireString(JsonElement element, string name)
    {
        Require(element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String,
            $"'{name}' must be a string");
        return value.GetString()!;
    }

    private static bool RequireBoolean(JsonElement element, string name)
    {
        Require(element.TryGetProperty(name, out var value) &&
                value.ValueKind is JsonValueKind.True or JsonValueKind.False,
            $"'{name}' must be a boolean");
        return value.GetBoolean();
    }

    private static double RequireDouble(JsonElement element, string name)
    {
        Require(element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Number,
            $"'{name}' must be a number");
        return value.GetDouble();
    }

    private static void Require(bool condition, string detail)
    {
        if (!condition)
            throw new FormatException($"The edge placement snapshot document is malformed: {detail}.");
    }
}
