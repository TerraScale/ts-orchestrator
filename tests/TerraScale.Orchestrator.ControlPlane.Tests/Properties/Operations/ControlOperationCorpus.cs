using System.Collections.ObjectModel;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Cysharp.Text;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties.Operations;

internal enum CorpusCode { Accepted, Missing, TooLarge, InvalidJson, InvalidSchema, InvalidDigest }
internal sealed record CorpusEntry(string Family, long Seed, string Mutation, long Delta, string Expected, string Digest);
internal sealed record CorpusResult(CorpusCode Code, IReadOnlyList<CorpusEntry> Entries);

internal static class ControlOperationCorpus
{
    private const string Resource =
        "TerraScale.Orchestrator.ControlPlane.Tests.Properties.Operations.Corpus.minimal-counterexamples.json";
    private const string ResourceDigest = "42ef7f191583e894bf82a1391d5d6818aa844bfa0f5f0073bd7ee489aac51a44";
    private const int MaximumBytes = 32_768;
    private const int MaximumEntries = 64;
    private const int MaximumText = 96;
    private static readonly HashSet<string> RootFields = new(StringComparer.Ordinal) { "version", "entries" };
    private static readonly HashSet<string> EntryFields = new(StringComparer.Ordinal)
        { "family", "seed", "mutation", "delta", "expected", "digest" };

    internal static CorpusResult LoadEmbedded()
    {
        using var stream = typeof(ControlOperationCorpus).Assembly.GetManifestResourceStream(Resource);
        if (stream is null) return Result(CorpusCode.Missing, []);
        if (!stream.CanSeek || stream.Length is <= 0 or > MaximumBytes) return Result(CorpusCode.TooLarge, []);
        var bytes = new byte[checked((int)stream.Length)];
        stream.ReadExactly(bytes);
        var digest = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        if (!string.Equals(digest, ResourceDigest, StringComparison.Ordinal))
            return Result(CorpusCode.InvalidDigest, []);
        try { return Load(new UTF8Encoding(false, true).GetString(bytes)); }
        catch (DecoderFallbackException) { return Result(CorpusCode.InvalidJson, []); }
    }

    internal static CorpusResult Load(string source)
    {
        if (string.IsNullOrEmpty(source) || Encoding.UTF8.GetByteCount(source) > MaximumBytes)
            return Result(CorpusCode.TooLarge, []);
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
                return Result(CorpusCode.InvalidSchema, []);
            var items = root.GetProperty("entries");
            if (items.ValueKind != JsonValueKind.Array || items.GetArrayLength() is 0 or > MaximumEntries)
                return Result(CorpusCode.InvalidSchema, []);
            var entries = new List<CorpusEntry>();
            foreach (var item in items.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.Object || !Exact(item, EntryFields) ||
                    !item.GetProperty("seed").TryGetInt64(out var seed) || seed is <= 0 or > 1_000_000 ||
                    !item.GetProperty("delta").TryGetInt64(out var delta) || delta is <= 0 or > 64)
                    return Result(CorpusCode.InvalidSchema, []);
                var family = item.GetProperty("family").GetString(); var mutation = item.GetProperty("mutation").GetString();
                var expected = item.GetProperty("expected").GetString(); var digest = item.GetProperty("digest").GetString();
                if (!Text(family) || !Text(mutation) || !Text(expected) || !DigestText(digest))
                    return Result(CorpusCode.InvalidSchema, []);
                var entry = new CorpusEntry(family!, seed, mutation!, delta, expected!, digest!);
                if (!Known(entry)) return Result(CorpusCode.InvalidSchema, []);
                if (!string.Equals(Digest(entry), digest, StringComparison.Ordinal)) return Result(CorpusCode.InvalidDigest, []);
                entries.Add(entry);
            }
            if (entries.Select(static entry => (entry.Family, entry.Seed)).Distinct().Count() != entries.Count)
                return Result(CorpusCode.InvalidSchema, []);
            return Result(CorpusCode.Accepted, entries);
        }
        catch (JsonException) { return Result(CorpusCode.InvalidJson, []); }
        catch (InvalidOperationException) { return Result(CorpusCode.InvalidJson, []); }
    }

    internal static string Canonical(CorpusEntry entry)
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
    internal static string Digest(CorpusEntry entry) => Convert.ToHexString(SHA256.HashData(
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
    private static bool Known(CorpusEntry entry) => (entry.Family, entry.Mutation, entry.Expected) is
        ("authority", "stale-cas-request", "StaleObservation") or
        ("authority", "permit-command-provenance", "ProvenanceDistinct") or
        ("operations", "dispatch-before-authorization", "InvalidTransition") or
        ("reconciliation", "future-observation", "FutureObservation");
    private static CorpusResult Result(CorpusCode code, IEnumerable<CorpusEntry> entries) => new(code,
        new ReadOnlyCollection<CorpusEntry>(entries.ToArray()));
}
