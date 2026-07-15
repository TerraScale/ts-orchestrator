using System.Collections.ObjectModel;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace TerraScale.Orchestrator.Protocol.Tests.Fuzz;

internal enum CorpusLoadCode
{
    Accepted,
    MissingResource,
    TooLarge,
    InvalidJson,
    InvalidSchema,
    InvalidDigest,
    ContentAddressMismatch,
}
internal sealed record ProtocolCorpusEntry(string Family, long Seed, string Input, string Expected, string Digest);
internal sealed record CorpusLoadResult(CorpusLoadCode Code, IReadOnlyList<ProtocolCorpusEntry> Entries);

internal static class ProtocolRegressionCorpus
{
    private const string ResourceName =
        "TerraScale.Orchestrator.Protocol.Tests.Fuzz.Corpus.minimal-fail-closed-seeds.json";
    private const int MaximumBytes = 32_768;
    private const int MaximumEntries = 64;
    private const int MaximumTextLength = 256;
    private const string ContentSha256 = "4f08f00d68bb88e2a935dcef54f80f0048a93ca455afd8bdd97ceebd6d2f363d";
    private static readonly HashSet<string> RootFields = new(StringComparer.Ordinal) { "version", "entries" };
    private static readonly HashSet<string> EntryFields = new(StringComparer.Ordinal)
        { "family", "seed", "input", "expected", "digest" };
    private static readonly IReadOnlyDictionary<string, HashSet<string>> ExpectedByFamily =
        new Dictionary<string, HashSet<string>>(StringComparer.Ordinal)
        {
            ["concrete-subject"] = GrammarErrors(),
            ["permission-pattern"] = GrammarErrors(),
            ["command-envelope"] = new(StringComparer.Ordinal)
            {
                "InvalidValidationContext", "MalformedEnvelope", "UnsupportedProtocolVersion",
                "InvalidValidityWindow", "NotYetValid", "Expired", "WrongCell", "WrongAggregateIdentity",
                "StaleGeneration", "StaleWriterEpoch", "PayloadDigestMismatch",
                "PayloadDigestVerificationFailed", "InvalidSignature", "SignatureVerificationFailed",
            },
        };
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    internal static CorpusLoadResult LoadEmbedded()
    {
        using var stream = typeof(ProtocolRegressionCorpus).Assembly.GetManifestResourceStream(ResourceName);
        if (stream is null) return Result(CorpusLoadCode.MissingResource, []);
        var bytes = ReadBounded(stream);
        if (bytes is null) return Result(CorpusLoadCode.TooLarge, []);
        return Load(bytes, requireContentAddress: true);
    }

    internal static CorpusLoadResult Load(string source)
    {
        if (string.IsNullOrEmpty(source)) return Result(CorpusLoadCode.TooLarge, []);
        try { return Load(StrictUtf8.GetBytes(source), requireContentAddress: false); }
        catch (EncoderFallbackException) { return Result(CorpusLoadCode.InvalidJson, []); }
    }

    internal static CorpusLoadResult Load(ReadOnlySpan<byte> source, bool requireContentAddress = false)
    {
        if (source.IsEmpty || source.Length > MaximumBytes) return Result(CorpusLoadCode.TooLarge, []);
        if (requireContentAddress && !string.Equals(
            Convert.ToHexString(SHA256.HashData(source)).ToLowerInvariant(), ContentSha256, StringComparison.Ordinal))
            return Result(CorpusLoadCode.ContentAddressMismatch, []);
        try
        {
            using var document = JsonDocument.Parse(source.ToArray(), new()
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
                if (!CanonicalText(family) || !BoundedText(input) || !CanonicalText(expected) || !DigestText(digest)
                    || !ExpectedByFamily.TryGetValue(family!, out var allowedExpected)
                    || !allowedExpected.Contains(expected!))
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

    internal static byte[]? ReadBounded(Stream stream)
    {
        var buffer = new byte[MaximumBytes + 1];
        var count = 0;
        while (count < buffer.Length)
        {
            var read = stream.Read(buffer, count, buffer.Length - count);
            if (read == 0) break;
            count += read;
        }

        return count > MaximumBytes ? null : buffer.AsSpan(0, count).ToArray();
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
    private static HashSet<string> GrammarErrors() => new(StringComparer.Ordinal)
    {
        "InvalidLimits", "Empty", "SubjectTooLong", "TooManyTokens", "EmptyToken", "TokenTooLong",
        "WhitespaceNotAllowed", "ControlCharacterNotAllowed", "InvalidUnicodeScalarSequence",
        "WildcardNotAllowed", "InvalidWildcard", "TerminalWildcardMustBeFinal",
    };
    private static CorpusLoadResult Result(CorpusLoadCode code, IEnumerable<ProtocolCorpusEntry> entries) =>
        new(code, new ReadOnlyCollection<ProtocolCorpusEntry>(entries.ToArray()));
}
