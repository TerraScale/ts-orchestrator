using System.Collections.ObjectModel;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace TerraScale.Orchestrator.Protocol.Tests.Fuzz;

internal enum CorpusLoadCode { Accepted, MissingResource, TooLarge, InvalidJson, InvalidSchema, InvalidDigest }
internal sealed record ProtocolCorpusEntry(string Family, long Seed, string Input, string Expected, string Digest);
internal sealed record CorpusLoadResult(CorpusLoadCode Code, IReadOnlyList<ProtocolCorpusEntry> Entries);

internal static class ProtocolRegressionCorpus
{
    private const string ResourceName =
        "TerraScale.Orchestrator.Protocol.Tests.Fuzz.Corpus.minimal-fail-closed-seeds.json";
    private const int MaximumBytes = 32_768;
    private const int MaximumEntries = 64;
    private const int MaximumTextLength = 256;
    private static readonly HashSet<string> RootFields = new(StringComparer.Ordinal) { "version", "entries" };
    private static readonly HashSet<string> EntryFields = new(StringComparer.Ordinal)
        { "family", "seed", "input", "expected", "digest" };

    internal static CorpusLoadResult LoadEmbedded()
    {
        using var stream = typeof(ProtocolRegressionCorpus).Assembly.GetManifestResourceStream(ResourceName);
        if (stream is null) return Result(CorpusLoadCode.MissingResource, []);
        if (!stream.CanSeek || stream.Length > MaximumBytes) return Result(CorpusLoadCode.TooLarge, []);
        using var reader = new StreamReader(stream, Encoding.UTF8, false, 1024, false);
        var buffer = new char[MaximumBytes + 1];
        var count = reader.ReadBlock(buffer, 0, buffer.Length);
        if (count > MaximumBytes) return Result(CorpusLoadCode.TooLarge, []);
        return Load(new string(buffer, 0, count));
    }

    internal static CorpusLoadResult Load(string source)
    {
        if (string.IsNullOrEmpty(source) || Encoding.UTF8.GetByteCount(source) > MaximumBytes)
            return Result(CorpusLoadCode.TooLarge, []);
        try
        {
            using var document = JsonDocument.Parse(source, new()
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 8,
            });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !ExactFields(root, RootFields) ||
                !root.GetProperty("version").TryGetInt32(out var version) || version != 1)
                return Result(CorpusLoadCode.InvalidSchema, []);
            var entriesElement = root.GetProperty("entries");
            if (entriesElement.ValueKind != JsonValueKind.Array || entriesElement.GetArrayLength() > MaximumEntries)
                return Result(CorpusLoadCode.InvalidSchema, []);
            var entries = new List<ProtocolCorpusEntry>();
            foreach (var item in entriesElement.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.Object || !ExactFields(item, EntryFields) ||
                    !item.GetProperty("seed").TryGetInt64(out var seed) || seed <= 0)
                    return Result(CorpusLoadCode.InvalidSchema, []);
                var family = item.GetProperty("family").GetString();
                var input = item.GetProperty("input").GetString();
                var expected = item.GetProperty("expected").GetString();
                var digest = item.GetProperty("digest").GetString();
                if (!CanonicalText(family) || !BoundedText(input) || !CanonicalText(expected) || !DigestText(digest))
                    return Result(CorpusLoadCode.InvalidSchema, []);
                var entry = new ProtocolCorpusEntry(family!, seed, input!, expected!, digest!);
                if (!string.Equals(Digest(entry), digest, StringComparison.Ordinal))
                    return Result(CorpusLoadCode.InvalidDigest, []);
                entries.Add(entry);
            }
            if (entries.Select(static entry => (entry.Family, entry.Seed)).Distinct().Count() != entries.Count)
                return Result(CorpusLoadCode.InvalidSchema, []);
            return Result(CorpusLoadCode.Accepted, entries);
        }
        catch (JsonException) { return Result(CorpusLoadCode.InvalidJson, []); }
        catch (InvalidOperationException) { return Result(CorpusLoadCode.InvalidJson, []); }
    }

    internal static string Digest(ProtocolCorpusEntry entry) => Convert.ToHexString(SHA256.HashData(
        Encoding.UTF8.GetBytes(Canonical(entry)))).ToLowerInvariant();
    internal static string Canonical(ProtocolCorpusEntry entry) => new StringBuilder("v1|family=")
        .Append(Utf8Length(entry.Family)).Append(':').Append(entry.Family)
        .Append("|seed=").Append(entry.Seed.ToString(CultureInfo.InvariantCulture))
        .Append("|input=").Append(Utf8Length(entry.Input)).Append(':').Append(entry.Input)
        .Append("|expected=").Append(Utf8Length(entry.Expected)).Append(':').Append(entry.Expected).ToString();
    private static int Utf8Length(string value) => Encoding.UTF8.GetByteCount(value);

    private static bool ExactFields(JsonElement element, HashSet<string> expected)
    {
        var properties = element.EnumerateObject().ToArray();
        return properties.Length == expected.Count && properties.All(property => expected.Contains(property.Name)) &&
            properties.Select(static property => property.Name).Distinct(StringComparer.Ordinal).Count() == properties.Length;
    }
    private static bool CanonicalText(string? value) => BoundedText(value) && value!.All(static character =>
        character is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '-');
    private static bool BoundedText(string? value) => value is { Length: > 0 and <= MaximumTextLength };
    private static bool DigestText(string? value) => value is { Length: 64 } && value.All(static character =>
        character is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static CorpusLoadResult Result(CorpusLoadCode code, IEnumerable<ProtocolCorpusEntry> entries) =>
        new(code, new ReadOnlyCollection<ProtocolCorpusEntry>(entries.ToArray()));
}
