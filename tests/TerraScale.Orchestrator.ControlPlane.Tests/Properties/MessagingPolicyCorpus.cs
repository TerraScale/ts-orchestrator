using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties;

internal enum MessagingCorpusCode { Accepted, Missing, TooLarge, InvalidJson, InvalidSchema, InvalidDigest }
internal sealed record MessagingCorpusEntry(string Id, int Seed, string Family, int Mode, string Expected);
internal sealed record MessagingCorpusResult(MessagingCorpusCode Code, IReadOnlyList<MessagingCorpusEntry> Entries);

internal static class MessagingPolicyCorpus
{
    private const string Resource = "TerraScale.Orchestrator.ControlPlane.Tests.Properties.MessagingPolicyReplayCorpus.v1.json";
    private const string ResourceDigest = "2dbee32886e47ab9ee7a59f515a5183f9db764f10d788f34e2be592399f536af";
    private const int MaximumBytes = 32_768;
    private const int MaximumEntries = 64;
    private const int MaximumIdLength = 64;
    private static readonly HashSet<string> RootFields = new(StringComparer.Ordinal) { "version", "entries" };
    private static readonly HashSet<string> EntryFields = new(StringComparer.Ordinal) { "id", "seed", "family", "mode", "expected" };

    internal static MessagingCorpusResult LoadEmbedded()
    {
        using var stream = typeof(MessagingPolicyCorpus).Assembly.GetManifestResourceStream(Resource);
        if (stream is null) return Result(MessagingCorpusCode.Missing, []);
        if (!stream.CanSeek || stream.Length is <= 0 or > MaximumBytes) return Result(MessagingCorpusCode.TooLarge, []);
        var bytes = new byte[checked((int)stream.Length)];
        stream.ReadExactly(bytes);
        if (!string.Equals(Convert.ToHexStringLower(SHA256.HashData(bytes)), ResourceDigest, StringComparison.Ordinal))
            return Result(MessagingCorpusCode.InvalidDigest, []);
        try { return Parse(new UTF8Encoding(false, true).GetString(bytes)); }
        catch (DecoderFallbackException) { return Result(MessagingCorpusCode.InvalidJson, []); }
    }

    internal static MessagingCorpusResult Parse(string source)
    {
        if (source is null) return Result(MessagingCorpusCode.InvalidJson, []);
        if (Encoding.UTF8.GetByteCount(source) > MaximumBytes) return Result(MessagingCorpusCode.TooLarge, []);
        try
        {
            using var document = JsonDocument.Parse(source, new JsonDocumentOptions
            { MaxDepth = 8, AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !Exact(root, RootFields) ||
                root.GetProperty("version").ValueKind != JsonValueKind.Number ||
                !root.GetProperty("version").TryGetInt32(out var version) || version != 1)
                return Result(MessagingCorpusCode.InvalidSchema, []);
            var items = root.GetProperty("entries");
            if (items.ValueKind != JsonValueKind.Array || items.GetArrayLength() is 0 or > MaximumEntries)
                return Result(MessagingCorpusCode.InvalidSchema, []);
            var entries = new List<MessagingCorpusEntry>(items.GetArrayLength());
            foreach (var item in items.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.Object || !Exact(item, EntryFields) ||
                    item.GetProperty("id").ValueKind != JsonValueKind.String ||
                    item.GetProperty("family").ValueKind != JsonValueKind.String ||
                    item.GetProperty("expected").ValueKind != JsonValueKind.String ||
                    item.GetProperty("seed").ValueKind != JsonValueKind.Number ||
                    item.GetProperty("mode").ValueKind != JsonValueKind.Number ||
                    !item.GetProperty("seed").TryGetInt32(out var seed) || seed is <= 0 or > 1_000_000 ||
                    !item.GetProperty("mode").TryGetInt32(out var mode))
                    return Result(MessagingCorpusCode.InvalidSchema, []);
                var entry = new MessagingCorpusEntry(item.GetProperty("id").GetString()!, seed,
                    item.GetProperty("family").GetString()!, mode, item.GetProperty("expected").GetString()!);
                if (!CanonicalId(entry.Id) || !Known(entry)) return Result(MessagingCorpusCode.InvalidSchema, []);
                entries.Add(entry);
            }
            if (entries.Select(static entry => entry.Id).Distinct(StringComparer.Ordinal).Count() != entries.Count ||
                entries.Select(static entry => (entry.Family, entry.Seed)).Distinct().Count() != entries.Count)
                return Result(MessagingCorpusCode.InvalidSchema, []);
            return Result(MessagingCorpusCode.Accepted, entries);
        }
        catch (JsonException) { return Result(MessagingCorpusCode.InvalidJson, []); }
        catch (InvalidOperationException) { return Result(MessagingCorpusCode.InvalidJson, []); }
    }

    internal static string Json(MessagingCorpusEntry entry) => JsonSerializer.Serialize(new { version = 1, entries = new[]
        { new { id = entry.Id, seed = entry.Seed, family = entry.Family, mode = entry.Mode, expected = entry.Expected } } });

    private static bool Exact(JsonElement element, HashSet<string> fields)
    {
        var properties = element.EnumerateObject().ToArray();
        return properties.Length == fields.Count && properties.All(property => fields.Contains(property.Name)) &&
            properties.Select(static property => property.Name).Distinct(StringComparer.Ordinal).Count() == properties.Length;
    }

    private static bool CanonicalId(string value) => value.Length is > 0 and <= MaximumIdLength && value[0] != '-' &&
        value[^1] != '-' && !value.Contains("--", StringComparison.Ordinal) && value.All(static character =>
            character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-');
    private static bool Known(MessagingCorpusEntry entry) => (entry.Family, entry.Mode, entry.Expected) is
        ("replacement", 0, "Observe") or ("replacement", 2, "AddPeer") or
        ("replacement", 5, "RemovePeer") or ("replacement", 7, "ReattachStore") or
        ("partition", 0, "StaleAuthority") or ("partition", 3, "FutureEvidence") or
        ("partition", 8, "ContinueRegional") or ("partition", 9, "ContinueGlobal") or
        ("isolation", 0, "Configure") or ("isolation", 2, "IsolationViolation") or
        ("isolation", 7, "IsolationViolation") or ("isolation", 9, "IsolationViolation");
    private static MessagingCorpusResult Result(MessagingCorpusCode code, IEnumerable<MessagingCorpusEntry> entries) =>
        new(code, new ReadOnlyCollection<MessagingCorpusEntry>(entries.ToArray()));
}

