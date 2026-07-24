using System.Collections.ObjectModel;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Cysharp.Text;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties;

internal enum DeliveryTerraBaseCorpusCode { Accepted, Missing, TooLarge, InvalidJson, InvalidSchema, InvalidDigest }
internal sealed record DeliveryTerraBaseCorpusEntry(string Family, long Seed, string Mutation, long Delta, string Expected, string Digest);
internal sealed record DeliveryTerraBaseCorpusResult(DeliveryTerraBaseCorpusCode Code, IReadOnlyList<DeliveryTerraBaseCorpusEntry> Entries);

internal static class DeliveryTerraBaseCorpus
{
    private const string Resource = "TerraScale.Orchestrator.ControlPlane.Tests.Properties.DeliveryTerraBaseReplayCorpus.v1.json";
    private const string ResourceDigest = "c54487a136d08abab940410d3c936bcbe8ca7d659435e41753c0039581013ed4";
    private const int MaximumBytes = 32_768;
    private const int MaximumEntries = 64;
    private const int MaximumText = 96;
    private static readonly HashSet<string> RootFields = new(StringComparer.Ordinal) { "version", "entries" };
    private static readonly HashSet<string> EntryFields = new(StringComparer.Ordinal)
        { "family", "seed", "mutation", "delta", "expected", "digest" };

    internal static DeliveryTerraBaseCorpusResult LoadEmbedded()
    {
        using var stream = typeof(DeliveryTerraBaseCorpus).Assembly.GetManifestResourceStream(Resource);
        if (stream is null) return Result(DeliveryTerraBaseCorpusCode.Missing, []);
        if (!stream.CanSeek || stream.Length is <= 0 or > MaximumBytes) return Result(DeliveryTerraBaseCorpusCode.TooLarge, []);
        var bytes = new byte[checked((int)stream.Length)]; stream.ReadExactly(bytes);
        if (!string.Equals(Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(), ResourceDigest, StringComparison.Ordinal))
            return Result(DeliveryTerraBaseCorpusCode.InvalidDigest, []);
        try { return Load(new UTF8Encoding(false, true).GetString(bytes)); }
        catch (DecoderFallbackException) { return Result(DeliveryTerraBaseCorpusCode.InvalidJson, []); }
    }

    internal static DeliveryTerraBaseCorpusResult Load(string source)
    {
        if (string.IsNullOrEmpty(source) || Encoding.UTF8.GetByteCount(source) > MaximumBytes)
            return Result(DeliveryTerraBaseCorpusCode.TooLarge, []);
        try
        {
            using var document = JsonDocument.Parse(source, new()
            {
                MaxDepth = 8,
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow
            });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !Exact(root, RootFields) ||
                !root.GetProperty("version").TryGetInt32(out var version) || version != 1)
                return Result(DeliveryTerraBaseCorpusCode.InvalidSchema, []);
            var items = root.GetProperty("entries");
            if (items.ValueKind != JsonValueKind.Array || items.GetArrayLength() is 0 or > MaximumEntries)
                return Result(DeliveryTerraBaseCorpusCode.InvalidSchema, []);
            var entries = new List<DeliveryTerraBaseCorpusEntry>();
            foreach (var item in items.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.Object || !Exact(item, EntryFields) ||
                    !item.GetProperty("seed").TryGetInt64(out var seed) || seed is <= 0 or > 1_000_000 ||
                    !item.GetProperty("delta").TryGetInt64(out var delta) || delta is <= 0 or > 64)
                    return Result(DeliveryTerraBaseCorpusCode.InvalidSchema, []);
                var family = item.GetProperty("family").GetString(); var mutation = item.GetProperty("mutation").GetString();
                var expected = item.GetProperty("expected").GetString(); var digest = item.GetProperty("digest").GetString();
                if (!Text(family) || !Text(mutation) || !Text(expected) || !DigestText(digest))
                    return Result(DeliveryTerraBaseCorpusCode.InvalidSchema, []);
                var entry = new DeliveryTerraBaseCorpusEntry(family!, seed, mutation!, delta, expected!, digest!);
                if (!Known(entry)) return Result(DeliveryTerraBaseCorpusCode.InvalidSchema, []);
                if (!string.Equals(Digest(entry), digest, StringComparison.Ordinal))
                    return Result(DeliveryTerraBaseCorpusCode.InvalidDigest, []);
                entries.Add(entry);
            }
            if (entries.Select(static entry => (entry.Family, entry.Seed)).Distinct().Count() != entries.Count)
                return Result(DeliveryTerraBaseCorpusCode.InvalidSchema, []);
            return Result(DeliveryTerraBaseCorpusCode.Accepted, entries);
        }
        catch (JsonException) { return Result(DeliveryTerraBaseCorpusCode.InvalidJson, []); }
        catch (InvalidOperationException) { return Result(DeliveryTerraBaseCorpusCode.InvalidJson, []); }
    }

    internal static DeliveryTerraBaseCorpusEntry WithDigest(DeliveryTerraBaseCorpusEntry entry) => entry with { Digest = Digest(entry) };
    internal static string Json(DeliveryTerraBaseCorpusEntry entry) => JsonSerializer.Serialize(new
    {
        version = 1,
        entries = new[]
        { new { family = entry.Family, seed = entry.Seed, mutation = entry.Mutation, delta = entry.Delta, expected = entry.Expected, digest = entry.Digest } }
    });
    internal static string Canonical(DeliveryTerraBaseCorpusEntry entry)
    {
        using var builder = ZString.CreateStringBuilder();
        builder.Append("v1|family=");
        builder.Append(Bytes(entry.Family));
        builder.Append(':');
        builder.Append(entry.Family);
        builder.Append("|seed=");
        builder.Append(entry.Seed.ToString(CultureInfo.InvariantCulture));
        builder.Append("|mutation=");
        builder.Append(Bytes(entry.Mutation));
        builder.Append(':');
        builder.Append(entry.Mutation);
        builder.Append("|delta=");
        builder.Append(entry.Delta.ToString(CultureInfo.InvariantCulture));
        builder.Append("|expected=");
        builder.Append(Bytes(entry.Expected));
        builder.Append(':');
        builder.Append(entry.Expected);
        return builder.ToString();
    }
    internal static string Digest(DeliveryTerraBaseCorpusEntry entry) => Convert.ToHexString(SHA256.HashData(
        Encoding.UTF8.GetBytes(Canonical(entry)))).ToLowerInvariant();
    private static int Bytes(string value) => Encoding.UTF8.GetByteCount(value);
    private static bool Exact(JsonElement element, HashSet<string> fields)
    {
        var properties = element.EnumerateObject().ToArray();
        return properties.Length == fields.Count && properties.All(property => fields.Contains(property.Name)) &&
            properties.Select(static property => property.Name).Distinct(StringComparer.Ordinal).Count() == properties.Length;
    }
    private static bool Text(string? value) => value is { Length: > 0 and <= MaximumText } && value.All(static c =>
        c is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '-');
    private static bool DigestText(string? value) => value is { Length: 64 } && value.All(static c =>
        c is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static bool Known(DeliveryTerraBaseCorpusEntry entry) => (entry.Family, entry.Mutation, entry.Expected) is
        ("delivery-source", "stale-generation", "StaleGeneration") or
        ("delivery-source", "stale-generation", "Idempotent") or
        ("terrabase-backup", "chain-gap", "ChainGap") or
        ("terrabase-backup", "chain-gap", "Completed");
    private static DeliveryTerraBaseCorpusResult Result(DeliveryTerraBaseCorpusCode code,
        IEnumerable<DeliveryTerraBaseCorpusEntry> entries) => new(code,
        new ReadOnlyCollection<DeliveryTerraBaseCorpusEntry>(entries.ToArray()));
}
