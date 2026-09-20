using System.Text.Json;
using System.Text.Json.Serialization;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Nodes;

namespace TerraScale.Orchestrator.Bootstrap;

/// <summary>
/// The public supported-region contract emitted by ts-infra. This authorizes
/// regions at startup; it never asserts cluster admission or provider readiness.
/// Updates require a reviewed file and controller restart until live intent
/// distribution and durable generation fencing are composed.
/// </summary>
internal sealed class OciRegionIntent
{
    private const int MaximumBytes = 16 * 1024;
    private readonly IReadOnlyDictionary<string, string> regions;

    private OciRegionIntent(long generation, IReadOnlyDictionary<string, string> regions)
    {
        Generation = generation;
        this.regions = regions;
    }

    internal long Generation { get; }

    internal static OciRegionIntent Load(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("TS_ORCH_REGION_INTENT_FILE is required before OCI fleets can start.");
        var resolved = NatsFileResolver.Resolve(path, "OCI region intent", MaximumBytes, ownerPrivate: true);
        using var stream = File.OpenRead(resolved);
        var bytes = new byte[MaximumBytes + 1];
        var length = stream.ReadAtLeast(bytes, bytes.Length, throwOnEndOfStream: false);
        if (length is < 1 or > MaximumBytes)
            throw new InvalidDataException("The OCI region intent exceeds its bounds.");
        return Parse(bytes.AsSpan(0, length));
    }

    internal static OciRegionIntent Parse(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length is < 1 or > MaximumBytes)
            throw new InvalidDataException("The OCI region intent exceeds its bounds.");
        var document = JsonSerializer.Deserialize<Document>(bytes, JsonOptions);
        if (document is not { SchemaVersion: 1, Generation: > 0, BootstrapRegion: "GRU", Regions.Length: >= 1 and <= 3 })
            throw new InvalidDataException("The OCI region intent has an unsupported shape.");
        var regions = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var region in document.Regions)
        {
            if (region is null || !TerraScaleRegion.IsValid(region.Cell) ||
                region.OciRegion != TerraScaleRegion.OciName(region.Cell) ||
                !regions.TryAdd(region.Cell, region.OciRegion))
                throw new InvalidDataException("The OCI region intent has an invalid or duplicate region mapping.");
        }
        if (!regions.ContainsKey(document.BootstrapRegion))
            throw new InvalidDataException("The OCI region intent must include the GRU bootstrap region.");
        return new(document.Generation, regions);
    }

    internal void RequireCell(string cell)
    {
        if (!regions.ContainsKey(cell.ToUpperInvariant()))
            throw new InvalidDataException("The controller cell is not supported by the ts-infra region intent.");
    }

    internal void RequireEndpoint(string cell, Uri endpoint)
    {
        RequireCell(cell);
        if (!endpoint.IsAbsoluteUri || endpoint.Scheme != Uri.UriSchemeHttps || !endpoint.IsDefaultPort ||
            endpoint.UserInfo.Length != 0 || endpoint.AbsolutePath != "/" ||
            endpoint.Query.Length != 0 || endpoint.Fragment.Length != 0 ||
            endpoint.Host != $"iaas.{regions[cell.ToUpperInvariant()]}.oraclecloud.com")
            throw new InvalidDataException("The OCI fleet endpoint does not match its supported controller cell.");
    }

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        AllowDuplicateProperties = false,
        MaxDepth = 8,
    };

    private sealed record Document(int SchemaVersion, long Generation, string BootstrapRegion, Region[] Regions);
    private sealed record Region(string Cell, string OciRegion);
}
