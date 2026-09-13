using System.Collections.ObjectModel;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TerraScale.Orchestrator.ModelTests.Simulation;
using Cysharp.Text;

namespace TerraScale.Orchestrator.ModelTests.RegressionCorpus;

public enum CorpusLoadCode { Unspecified, Accepted, InvalidJson, UnsupportedVersion, UnknownField, DuplicateId, InvalidId, InvalidDigest, InvalidSchedule, InvalidExpectation }
public sealed record CorpusEntry(int Version, string Id, long Seed, SafetyInvariant ExpectedInvariant,
    SimulationFailureCode ExpectedError, IReadOnlyList<FailureDirective> Schedule, string Digest);
public sealed record CorpusLoadResult(CorpusLoadCode Code, IReadOnlyList<CorpusEntry> Entries);

public static class RegressionCorpusLoader
{
    private const int MaximumSourceBytes = 65_536;
    private const int MaximumEntries = 256;
    private const int MaximumScheduleLength = 128;
    private const string StaleLeaderResource =
        "TerraScale.Orchestrator.ModelTests.RegressionCorpus.entries.stale-leader-late-completion.json";
    private static readonly HashSet<string> RootFields = new(StringComparer.Ordinal)
    { "version", "id", "seed", "expectedInvariant", "expectedError", "schedule", "digest" };
    private static readonly HashSet<string> ScheduleFields = new(StringComparer.Ordinal) { "kind", "node", "delay" };

    public static CorpusLoadResult LoadMany(IEnumerable<string> sources)
    {
        if (sources is null) return Result(CorpusLoadCode.InvalidJson, []);
        string[] boundedSources;
        try { boundedSources = sources.Take(MaximumEntries + 1).ToArray(); }
        catch (Exception) { return Result(CorpusLoadCode.InvalidJson, []); }
        if (boundedSources.Length > MaximumEntries) return Result(CorpusLoadCode.InvalidSchedule, []);
        var entries = new List<CorpusEntry>();
        foreach (var source in boundedSources)
        {
            var loaded = Load(source);
            if (loaded.Code != CorpusLoadCode.Accepted) return loaded;
            entries.Add(loaded.Entries[0]);
        }
        if (entries.Select(static item => item.Id).Distinct(StringComparer.Ordinal).Count() != entries.Count)
            return Result(CorpusLoadCode.DuplicateId, []);
        return Result(CorpusLoadCode.Accepted, entries.OrderBy(static item => item.Id, StringComparer.Ordinal));
    }

    public static CorpusLoadResult Load(string source)
    {
        if (string.IsNullOrEmpty(source) || Encoding.UTF8.GetByteCount(source) > MaximumSourceBytes)
            return Result(CorpusLoadCode.InvalidJson, []);
        try
        {
            using var document = JsonDocument.Parse(source, new() { AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return Result(CorpusLoadCode.InvalidJson, []);
            var rootProperties = root.EnumerateObject().ToArray();
            if (rootProperties.Any(property => !RootFields.Contains(property.Name)) ||
                rootProperties.Select(static property => property.Name).Distinct(StringComparer.Ordinal).Count() != rootProperties.Length ||
                RootFields.Any(field => !root.TryGetProperty(field, out _)))
                return Result(CorpusLoadCode.UnknownField, []);
            if (!root.GetProperty("version").TryGetInt32(out var version) || version != 1)
                return Result(CorpusLoadCode.UnsupportedVersion, []);
            var id = root.GetProperty("id").GetString();
            if (!ValidId(id)) return Result(CorpusLoadCode.InvalidId, []);
            if (!root.GetProperty("seed").TryGetInt64(out var seed) || seed <= 0)
                return Result(CorpusLoadCode.InvalidExpectation, []);
            if (!Enum.TryParse<SafetyInvariant>(root.GetProperty("expectedInvariant").GetString(), false, out var invariant) ||
                invariant == SafetyInvariant.Unspecified || !Enum.IsDefined(invariant) ||
                !Enum.TryParse<SimulationFailureCode>(root.GetProperty("expectedError").GetString(), false, out var error) ||
                error == SimulationFailureCode.Unspecified || !Enum.IsDefined(error))
                return Result(CorpusLoadCode.InvalidExpectation, []);
            var scheduleElement = root.GetProperty("schedule");
            if (scheduleElement.ValueKind != JsonValueKind.Array) return Result(CorpusLoadCode.InvalidSchedule, []);
            if (scheduleElement.GetArrayLength() > MaximumScheduleLength) return Result(CorpusLoadCode.InvalidSchedule, []);
            var schedule = new List<FailureDirective>();
            foreach (var element in scheduleElement.EnumerateArray())
            {
                var scheduleProperties = element.ValueKind == JsonValueKind.Object ? element.EnumerateObject().ToArray() : [];
                if (element.ValueKind != JsonValueKind.Object || scheduleProperties.Any(property => !ScheduleFields.Contains(property.Name)) ||
                    scheduleProperties.Select(static property => property.Name).Distinct(StringComparer.Ordinal).Count() != scheduleProperties.Length ||
                    ScheduleFields.Any(field => !element.TryGetProperty(field, out _)))
                    return Result(CorpusLoadCode.InvalidSchedule, []);
                if (!Enum.TryParse<FailureKind>(element.GetProperty("kind").GetString(), false, out var kind) ||
                    kind == FailureKind.Unspecified || !Enum.IsDefined(kind) ||
                    !element.GetProperty("delay").TryGetInt64(out var delay) || delay < 0)
                    return Result(CorpusLoadCode.InvalidSchedule, []);
                var node = element.GetProperty("node").GetString();
                if (node is not ("n1" or "n2" or "n3")) return Result(CorpusLoadCode.InvalidSchedule, []);
                schedule.Add(new(kind, node, delay));
            }
            var digest = root.GetProperty("digest").GetString();
            if (!ValidDigest(digest)) return Result(CorpusLoadCode.InvalidDigest, []);
            var entry = new CorpusEntry(version, id!, seed, invariant, error,
                new ReadOnlyCollection<FailureDirective>(schedule), digest!);
            if (!string.Equals(Digest(entry), digest, StringComparison.Ordinal)) return Result(CorpusLoadCode.InvalidDigest, []);
            return Result(CorpusLoadCode.Accepted, [entry]);
        }
        catch (JsonException) { return Result(CorpusLoadCode.InvalidJson, []); }
        catch (InvalidOperationException) { return Result(CorpusLoadCode.InvalidJson, []); }
    }

    public static CorpusLoadResult LoadCheckedInStaleLeaderLateCompletion() => Load(ReadCheckedInStaleLeaderLateCompletion());
    internal static string ReadCheckedInStaleLeaderLateCompletion()
    {
        using var stream = typeof(RegressionCorpusLoader).Assembly.GetManifestResourceStream(StaleLeaderResource) ??
            throw new InvalidOperationException("Missing checked-in regression corpus resource.");
        if (stream.CanSeek && stream.Length > MaximumSourceBytes)
            throw new InvalidOperationException("Checked-in regression corpus resource exceeds its byte bound.");
        using var reader = new StreamReader(stream, Encoding.UTF8, false, 1024, false);
        var buffer = new char[MaximumSourceBytes + 1];
        var count = reader.ReadBlock(buffer, 0, buffer.Length);
        if (count > MaximumSourceBytes) throw new InvalidOperationException("Checked-in regression corpus resource exceeds its byte bound.");
        return new string(buffer, 0, count);
    }

    public static string Digest(CorpusEntry entry) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(Canonical(entry))));
    public static string Canonical(CorpusEntry entry)
    {
        using var builder = ZString.CreateStringBuilder();
        builder.Append("v1|id=");
        builder.Append(entry.Id);
        builder.Append("|seed=");
        builder.Append(entry.Seed.ToString(CultureInfo.InvariantCulture));
        builder.Append("|invariant=");
        builder.Append(((int)entry.ExpectedInvariant).ToString(CultureInfo.InvariantCulture));
        builder.Append("|error=");
        builder.Append(((int)entry.ExpectedError).ToString(CultureInfo.InvariantCulture));
        foreach (var item in entry.Schedule)
        {
            builder.Append("|s=");
            builder.Append(((int)item.Kind).ToString(CultureInfo.InvariantCulture));
            builder.Append(',');
            builder.Append(item.Node);
            builder.Append(',');
            builder.Append(item.DelayTicks.ToString(CultureInfo.InvariantCulture));
        }
        return builder.ToString();
    }
    private static bool ValidId(string? value) => !string.IsNullOrEmpty(value) && value.Length <= 80 &&
        !value.Contains("..", StringComparison.Ordinal) && !value.Contains('/') && !value.Contains('\\') &&
        value.All(character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-');
    private static bool ValidDigest(string? value) => value is { Length: 64 } &&
        value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static CorpusLoadResult Result(CorpusLoadCode code, IEnumerable<CorpusEntry> entries) => new(code,
        new ReadOnlyCollection<CorpusEntry>(entries.ToArray()));
}

