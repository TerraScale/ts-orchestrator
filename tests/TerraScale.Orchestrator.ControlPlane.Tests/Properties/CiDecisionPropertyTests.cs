using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TerraScale.Orchestrator.ControlPlane.Delivery;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties;

public sealed class CiDecisionPropertyTests
{
    private const int Cases = 1_000;

    [Test]
    public async Task TrustZoneAndCapabilityPropertiesMatchIndependentClosedMatrixFor1000Cases()
    {
        var first = UnderCulture("tr-TR", () => RunTrustMatrix(0xC100_1001));
        var replay = UnderCulture("ar-SA", () => RunTrustMatrix(0xC100_1001));
        await Assert.That(first).IsEqualTo(replay);
        await Assert.That(first.Cases).IsEqualTo(Cases);
        await Assert.That(first.Outcomes).IsEqualTo(2);
        await Assert.That(first.Coverage).IsEqualTo(12);
    }

    [Test]
    public async Task RunnerSelectionPropertiesMatchIndependentFreshCapabilityAndOrdinalOracleFor1000Cases()
    {
        var first = UnderCulture("tr-TR", () => RunSelection(0xC100_1002));
        var replay = UnderCulture("ja-JP", () => RunSelection(0xC100_1002));
        await Assert.That(first).IsEqualTo(replay);
        await Assert.That(first.Cases).IsEqualTo(Cases);
        await Assert.That(first.UniqueSelected).IsGreaterThan(900);
        await Assert.That(first.Coverage).IsEqualTo(5);
    }

    [Test]
    public async Task AttemptRetryGenerationAndIdempotencyPropertiesMatchIndependentPrecedenceFor1000Cases()
    {
        var first = UnderCulture("tr-TR", () => RunRetry(0xC100_1003));
        var replay = UnderCulture("ar-SA", () => RunRetry(0xC100_1003));
        await Assert.That(first).IsEqualTo(replay);
        await Assert.That(first.Cases).IsEqualTo(Cases);
        await Assert.That(first.Outcomes).IsEqualTo(3);
        await Assert.That(first.Coverage).IsEqualTo(5);
    }

    [Test]
    public async Task RunnerEvidenceFailuresMatchIndependentValidationPrecedenceFor1000Cases()
    {
        var first = UnderCulture("tr-TR", () => RunRunnerFailures(0xC100_1004));
        var replay = UnderCulture("ar-SA", () => RunRunnerFailures(0xC100_1004));
        await Assert.That(first).IsEqualTo(replay);
        await Assert.That(first.Cases).IsEqualTo(Cases);
        await Assert.That(first.Outcomes).IsEqualTo(4);
        await Assert.That(first.Coverage).IsEqualTo(5);
    }

    [Test]
    public async Task CiAcceptedOutputsAreConstructionClosedAndCorpusIsPinnedStrictAndInputSensitive()
    {
        foreach (var type in new[] { typeof(DeliveryDecision), typeof(DispatchJobIntent), typeof(HoldDeliveryIntent),
            typeof(DeliveryError), typeof(DeliveryTrace) })
            await Assert.That(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();

        var corpus = CiDecisionCorpus.LoadEmbedded();
        await Assert.That(corpus.Code).IsEqualTo(CiCorpusCode.Accepted);
        await Assert.That(corpus.Entries.Count).IsEqualTo(8);
        foreach (var entry in corpus.Entries)
        {
            var actual = Replay(entry);
            await Assert.That(actual).IsEqualTo(entry.Expected);
            var changed = entry with { Seed = entry.Seed + 100 };
            await Assert.That(Replay(changed)).IsNotEqualTo(actual);
        }

        await Assert.That(CiDecisionCorpus.Parse("{}").Code).IsEqualTo(CiCorpusCode.InvalidSchema);
        await Assert.That(CiDecisionCorpus.Parse("{\"version\":1,\"entries\":[]}").Code).IsEqualTo(CiCorpusCode.InvalidSchema);
        await Assert.That(CiDecisionCorpus.Parse("{\"version\":1,\"version\":1,\"entries\":[]}").Code).IsEqualTo(CiCorpusCode.InvalidSchema);
        await Assert.That(CiDecisionCorpus.Parse("{\"version\":1,\"unknown\":[]}").Code).IsEqualTo(CiCorpusCode.InvalidSchema);
        await Assert.That(CiDecisionCorpus.Parse(new string('x', 32_769)).Code).IsEqualTo(CiCorpusCode.TooLarge);
        await Assert.That(CiDecisionCorpus.Parse(new string('\u00e9', 16_384)).Code).IsEqualTo(CiCorpusCode.InvalidJson);
        await Assert.That(CiDecisionCorpus.Parse(new string('\u00e9', 16_385)).Code).IsEqualTo(CiCorpusCode.TooLarge);
        await Assert.That(CiDecisionCorpus.Parse("{").Code).IsEqualTo(CiCorpusCode.InvalidJson);
        await Assert.That(CiDecisionCorpus.Parse("{/*comment*/\"version\":1,\"entries\":[]}").Code).IsEqualTo(CiCorpusCode.InvalidJson);
        await Assert.That(CiDecisionCorpus.Parse("{\"version\":1,\"entries\":[],}").Code).IsEqualTo(CiCorpusCode.InvalidJson);
        await Assert.That(CiDecisionCorpus.Parse("{\"version\":1,\"entries\":[]} trailing").Code).IsEqualTo(CiCorpusCode.InvalidJson);
        await Assert.That(CiDecisionCorpus.Parse("{\"version\":1,\"entries\":[[[[[[[0]]]]]]]}").Code).IsEqualTo(CiCorpusCode.InvalidJson);
        var first = corpus.Entries[0];
        await Assert.That(CiDecisionCorpus.Parse(CiDecisionCorpus.Json(first with { Expected = "invalid" })).Code)
            .IsEqualTo(CiCorpusCode.InvalidSchema);
        await Assert.That(CiDecisionCorpus.Parse(CiDecisionCorpus.Json(first with { Id = "bad/id" })).Code)
            .IsEqualTo(CiCorpusCode.InvalidSchema);
        await Assert.That(CiDecisionCorpus.Parse(CiDecisionCorpus.Json(first with { Scenario = "unknown" })).Code)
            .IsEqualTo(CiCorpusCode.InvalidSchema);
        await Assert.That(CiDecisionCorpus.Parse(CiDecisionCorpus.Json(first with { Seed = 0 })).Code)
            .IsEqualTo(CiCorpusCode.InvalidSchema);
        await Assert.That(CiDecisionCorpus.Parse(CiDecisionCorpus.Json(first with { Seed = 1_000_000 })).Code)
            .IsEqualTo(CiCorpusCode.Accepted);
        await Assert.That(CiDecisionCorpus.Parse(CiDecisionCorpus.Json(first with { Seed = 1_000_001 })).Code)
            .IsEqualTo(CiCorpusCode.InvalidSchema);
        await Assert.That(CiDecisionCorpus.Parse(CiDecisionCorpus.Json(first with { Id = new string('a', 64) })).Code)
            .IsEqualTo(CiCorpusCode.Accepted);
        foreach (var id in new[] { new string('a', 65), "-leading", "trailing-", "double--hyphen", "bad value", "bad\nvalue", "Upper" })
            await Assert.That(CiDecisionCorpus.Parse(CiDecisionCorpus.Json(first with { Id = id })).Code)
                .IsEqualTo(CiCorpusCode.InvalidSchema);
        var duplicate = $"{{\"version\":1,\"entries\":[{EntryJson(first)},{EntryJson(first)}]}}";
        await Assert.That(CiDecisionCorpus.Parse(duplicate).Code).IsEqualTo(CiCorpusCode.InvalidSchema);
        var duplicateField = $"{{\"version\":1,\"entries\":[{{\"id\":\"x\",\"id\":\"y\",\"seed\":1,\"scenario\":\"build\",\"expected\":\"{first.Expected}\"}}]}}";
        await Assert.That(CiDecisionCorpus.Parse(duplicateField).Code).IsEqualTo(CiCorpusCode.InvalidSchema);
        var extraField = $"{{\"version\":1,\"entries\":[{{\"id\":\"x\",\"seed\":1,\"scenario\":\"build\",\"expected\":\"{first.Expected}\",\"extra\":1}}]}}";
        var missingField = "{\"version\":1,\"entries\":[{\"id\":\"x\",\"seed\":1,\"scenario\":\"build\"}]}";
        var wrongTypes = $"{{\"version\":1,\"entries\":[{{\"id\":1,\"seed\":\"1\",\"scenario\":true,\"expected\":\"{first.Expected}\"}}]}}";
        await Assert.That(CiDecisionCorpus.Parse(extraField).Code).IsEqualTo(CiCorpusCode.InvalidSchema);
        await Assert.That(CiDecisionCorpus.Parse(missingField).Code).IsEqualTo(CiCorpusCode.InvalidSchema);
        await Assert.That(CiDecisionCorpus.Parse(wrongTypes).Code).IsEqualTo(CiCorpusCode.InvalidSchema);
        var sixtyFive = $"{{\"version\":1,\"entries\":[{string.Join(',', Enumerable.Range(1, 65).Select(i => EntryJson(first with { Id = $"id-{i}", Seed = i })))}]}}";
        var sixtyFour = $"{{\"version\":1,\"entries\":[{string.Join(',', Enumerable.Range(1, 64).Select(i => EntryJson(first with { Id = $"id-{i}", Seed = i })))}]}}";
        await Assert.That(CiDecisionCorpus.Parse(sixtyFour).Code).IsEqualTo(CiCorpusCode.Accepted);
        await Assert.That(CiDecisionCorpus.Parse(sixtyFive).Code).IsEqualTo(CiCorpusCode.InvalidSchema);
    }

    private static Summary RunTrustMatrix(ulong seed)
    {
        var generator = new Generator(seed); var outcomes = new HashSet<string>(); var coverage = new HashSet<(JobKind, int)>(); ulong digest = 0;
        for (var index = 0; index < Cases; index++)
        {
            var mode = index % 3; var kind = (JobKind)(1 + ((index / 3) % 4)); var allowed = Allowed(kind); var valid = mode == 0;
            var wrongZone = (TrustZone)(1 + ((int)allowed.Zone % 4));
            var zone = valid || index % 3 == 2 ? allowed.Zone : wrongZone;
            var capabilities = valid || index % 3 == 1 ? allowed.Capabilities : [Forbidden(kind)];
            var job = Job(index, kind, zone, capabilities);
            var runner = Runner($"runner-{index}-{generator.Next(1_000_000)}", zone, 50, capabilities);
            var decision = DeliveryEngine.DecideJob(job, [runner], 96);
            var expected = OracleTrust(kind, [zone], capabilities)
                ? "Dispatch" : "TrustZoneDenied";
            var actual = Outcome(decision);
            Require(actual == expected, "trust", index); outcomes.Add(actual); coverage.Add((kind, mode)); digest = Mix(digest, actual, job.Generation);
        }
        return new(Cases, outcomes.Count, 0, coverage.Count, digest);
    }

    private static Summary RunSelection(ulong seed)
    {
        var generator = new Generator(seed); var selected = new HashSet<string>(StringComparer.Ordinal); var rotations = new HashSet<int>(); ulong digest = 0;
        for (var index = 0; index < Cases; index++)
        {
            var suffix = generator.Next(1_000_000); var job = Job(index, JobKind.TrustedBuild, TrustZone.TrustedBuild,
                [RunnerCapability.Compile, RunnerCapability.Test]);
            var candidates = new[]
            {
                Runner($"z-{index}-{suffix}", TrustZone.TrustedBuild, 50, RunnerCapability.Compile, RunnerCapability.Test),
                Runner($"a-{index}-{suffix}", TrustZone.TrustedBuild, 50, RunnerCapability.Test, RunnerCapability.Compile),
                Runner($"stale-{index}", TrustZone.TrustedBuild, 9, RunnerCapability.Compile, RunnerCapability.Test),
                Runner($"wrong-{index}", TrustZone.UntrustedProduct, 50, RunnerCapability.Compile, RunnerCapability.Test),
                Runner($"missing-{index}", TrustZone.TrustedBuild, 50, RunnerCapability.Compile),
            };
            var offset = generator.Next(candidates.Length); rotations.Add(offset); var permuted = Rotate(candidates, offset);
            var oracle = candidates.Where(r => r.Available && r.Sequence is >= 10 and <= 100 && r.Zone == TrustZone.TrustedBuild &&
                    job.RequiredCapabilities.All(r.Capabilities.Contains))
                .Select(r => r.Runner.Value).Order(StringComparer.Ordinal).First();
            var decision = DeliveryEngine.DecideJob(job, permuted, 96);
            var alternate = DeliveryEngine.DecideJob(job, Rotate(candidates, (offset + 1) % candidates.Length), 96);
            var intent = decision.Intents.Single() as DispatchJobIntent;
            if (intent is null) throw new InvalidOperationException($"selection failed at {index}.");
            Require(intent.Runner.Value == oracle && intent.Job == job.Job && intent.Tree == job.Tree &&
                intent.Generation == job.Generation && intent.Idempotency == job.Idempotency, "selection", index);
            Require(((DispatchJobIntent)alternate.Intents.Single()).Runner.Value == oracle, "selection-permutation", index);
            selected.Add(intent.Runner.Value); digest = Mix(digest, intent.Runner.Value, intent.Generation);
        }
        return new(Cases, 1, selected.Count, rotations.Count, digest);
    }

    private static Summary RunRetry(ulong seed)
    {
        var generator = new Generator(seed); var outcomes = new HashSet<string>(); var coverage = new HashSet<int>(); ulong digest = 0;
        for (var index = 0; index < Cases; index++)
        {
            var mode = index % 5; var (attempt, maximum, authorized) = mode switch
            { 0 => (1, 3, false), 1 => (2, 3, true), 2 => (4, 3, true), 3 => (2, 3, false), _ => (4, 3, false) };
            var job = Job(index, JobKind.TrustedBuild, TrustZone.TrustedBuild, [RunnerCapability.Compile], attempt, maximum, authorized);
            var decision = DeliveryEngine.DecideJob(job, [Runner($"runner-{index}-{generator.Next(1_000_000)}", TrustZone.TrustedBuild, 50, RunnerCapability.Compile)], 96);
            var expected = attempt > 1 && !authorized ? "RetryDenied" : attempt > maximum ? "AttemptsExhausted" : "Dispatch";
            var actual = Outcome(decision); Require(actual == expected, "retry", index);
            if (actual == "Dispatch")
            {
                var intent = (DispatchJobIntent)decision.Intents.Single();
                Require(intent.Attempt == attempt && intent.Idempotency.Value == $"key-{index}" &&
                    intent.Generation == job.Generation, "retry-subject", index);
            }
            outcomes.Add(actual); coverage.Add(mode); digest = Mix(digest, actual, job.Generation);
        }
        return new(Cases, outcomes.Count, 0, coverage.Count, digest);
    }

    private static Summary RunRunnerFailures(ulong seed)
    {
        var generator = new Generator(seed); var outcomes = new HashSet<string>(); var coverage = new HashSet<int>(); ulong digest = 0;
        for (var index = 0; index < Cases; index++)
        {
            var job = Job(index, JobKind.TrustedBuild, TrustZone.TrustedBuild,
                [RunnerCapability.Compile, RunnerCapability.Test]);
            var mode = index % 5; var suffix = generator.Next(1_000_000); RunnerEvidence[] runners; string expected;
            switch (mode)
            {
                case 0:
                    runners = [Runner($"duplicate-{index}-{suffix}", TrustZone.TrustedBuild, 50, RunnerCapability.Compile, RunnerCapability.Test),
                        Runner($"duplicate-{index}-{suffix}", TrustZone.TrustedBuild, 50, RunnerCapability.Compile, RunnerCapability.Test)];
                    expected = "DuplicateEvidence"; break;
                case 1:
                    runners = [Runner($"stale-{index}", TrustZone.TrustedBuild, 9, RunnerCapability.Compile, RunnerCapability.Test)];
                    expected = "RunnerStale"; break;
                case 2:
                    runners = [Runner($"wrong-{index}", TrustZone.UntrustedProduct, 50, RunnerCapability.Compile, RunnerCapability.Test)];
                    expected = "TrustZoneDenied"; break;
                case 3:
                    runners = [Runner($"missing-{index}", TrustZone.TrustedBuild, 50, RunnerCapability.Compile)];
                    expected = "CapabilityMissing"; break;
                default:
                    runners = [new(new($"unavailable-{index}"), TrustZone.TrustedBuild, 50, false,
                        [RunnerCapability.Compile, RunnerCapability.Test])];
                    expected = "RunnerStale"; break;
            }
            var actual = Outcome(DeliveryEngine.DecideJob(job, runners, 96));
            Require(actual == expected, "runner-failure", index); outcomes.Add(actual); coverage.Add(mode); digest = Mix(digest, actual, job.Generation);
        }
        return new(Cases, outcomes.Count, 0, coverage.Count, digest);
    }

    private static string Replay(CiCorpusEntry entry)
    {
        var kind = entry.Scenario switch
        {
            "product" => JobKind.ProductValidation,
            "build" => JobKind.TrustedBuild,
            "promotion" => JobKind.Promotion,
            "recovery" => JobKind.ControlRecovery,
            _ => throw new InvalidOperationException(),
        };
        var allowed = Allowed(kind); var job = Job((int)entry.Seed, kind, allowed.Zone, allowed.Capabilities);
        var decision = DeliveryEngine.DecideJob(job,
            [Runner($"runner-{entry.Scenario}-{entry.Seed}", allowed.Zone, 50, allowed.Capabilities)], 96);
        var intent = (DispatchJobIntent)decision.Intents.Single();
        return Fingerprint(intent);
    }

    private static string Fingerprint(DispatchJobIntent intent)
    {
        var value = $"{intent.Pipeline.Value}|{intent.Job.Value}|{intent.Runner.Value}|{intent.Tree.Value}|{intent.Generation.ToString(CultureInfo.InvariantCulture)}|{intent.Attempt.ToString(CultureInfo.InvariantCulture)}|{intent.Idempotency.Value}";
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    }
    private static string EntryJson(CiCorpusEntry entry) => JsonSerializer.Serialize(new
        { id = entry.Id, seed = entry.Seed, scenario = entry.Scenario, expected = entry.Expected });

    private static (TrustZone Zone, RunnerCapability[] Capabilities) Allowed(JobKind kind) => kind switch
    {
        JobKind.ProductValidation => (TrustZone.UntrustedProduct, [RunnerCapability.Compile, RunnerCapability.Test]),
        JobKind.TrustedBuild => (TrustZone.TrustedBuild, [RunnerCapability.Compile, RunnerCapability.Test, RunnerCapability.Sign]),
        JobKind.Promotion => (TrustZone.ProductionRelease, [RunnerCapability.Promote, RunnerCapability.ProductionDeploy]),
        JobKind.ControlRecovery => (TrustZone.ControlRecovery, [RunnerCapability.ControlRecover]),
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };
    private static RunnerCapability Forbidden(JobKind kind) => kind == JobKind.ControlRecovery ? RunnerCapability.Compile : RunnerCapability.ControlRecover;
    private static bool OracleTrust(JobKind kind, IReadOnlyList<TrustZone> zones, IReadOnlyList<RunnerCapability> capabilities)
    {
        var allowed = Allowed(kind);
        return zones.Count > 0 && zones.All(zone => zone == allowed.Zone) && capabilities.Count > 0 &&
            capabilities.All(allowed.Capabilities.Contains);
    }
    private static JobRequest Job(int index, JobKind kind, TrustZone zone, IEnumerable<RunnerCapability> capabilities,
        int attempt = 1, int maximumAttempts = 3, bool retry = false) => new(new($"pipeline-{index}"), new($"job-{index}"), kind,
        new($"tree-{index}"), index + 1L, attempt, maximumAttempts, new($"key-{index}"), [zone], capabilities, 10, 100, retry);
    private static RunnerEvidence Runner(string id, TrustZone zone, long sequence, params RunnerCapability[] capabilities) =>
        new(new(id), zone, sequence, true, capabilities);
    private static T[] Rotate<T>(T[] values, int offset) => values.Skip(offset).Concat(values.Take(offset)).ToArray();
    private static string Outcome(DeliveryDecision decision) => decision.Errors.Count > 0 ? decision.Errors[0].Code.ToString() : decision.Intents[0].Action.ToString();
    private static T UnderCulture<T>(string name, Func<T> action) { var before = CultureInfo.CurrentCulture; try { CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(name); return action(); } finally { CultureInfo.CurrentCulture = before; } }
    private static void Require(bool condition, string family, int index) { if (!condition) throw new InvalidOperationException($"{family} failed at {index}."); }
    private static ulong Mix(ulong digest, string value, long number) { unchecked { foreach (var c in value) digest = (digest ^ c) * 1099511628211UL; return (digest ^ (ulong)number) * 1099511628211UL; } }
    private sealed record Summary(int Cases, int Outcomes, int UniqueSelected, int Coverage, ulong Digest);
    private sealed class Generator(ulong seed) { private ulong _state = seed; public int Next(int maximum) { _state ^= _state << 13; _state ^= _state >> 7; _state ^= _state << 17; return (int)(_state % (uint)maximum); } }
}

internal enum CiCorpusCode { Accepted, Missing, TooLarge, InvalidJson, InvalidSchema, InvalidDigest }
internal sealed record CiCorpusEntry(string Id, long Seed, string Scenario, string Expected);
internal sealed record CiCorpusResult(CiCorpusCode Code, IReadOnlyList<CiCorpusEntry> Entries);

internal static class CiDecisionCorpus
{
    private const string Resource = "TerraScale.Orchestrator.ControlPlane.Tests.Properties.CiDecisionReplayCorpus.v1.json";
    private const string Digest = "780cc2d0e5ac5298eeec0dfa1b2d937dda844e2a47c5a4e75fa2be092ad7a967";
    private const int MaximumBytes = 32_768;
    private static readonly HashSet<string> RootFields = new(StringComparer.Ordinal) { "version", "entries" };
    private static readonly HashSet<string> EntryFields = new(StringComparer.Ordinal) { "id", "seed", "scenario", "expected" };

    internal static CiCorpusResult LoadEmbedded()
    {
        using var stream = typeof(CiDecisionCorpus).Assembly.GetManifestResourceStream(Resource);
        if (stream is null) return new(CiCorpusCode.Missing, []);
        if (!stream.CanSeek || stream.Length is <= 0 or > MaximumBytes) return new(CiCorpusCode.TooLarge, []);
        var bytes = new byte[checked((int)stream.Length)]; stream.ReadExactly(bytes);
        if (Convert.ToHexStringLower(SHA256.HashData(bytes)) != Digest) return new(CiCorpusCode.InvalidDigest, []);
        try { return Parse(new UTF8Encoding(false, true).GetString(bytes)); }
        catch (DecoderFallbackException) { return new(CiCorpusCode.InvalidJson, []); }
    }

    internal static CiCorpusResult Parse(string source)
    {
        if (string.IsNullOrEmpty(source) || Encoding.UTF8.GetByteCount(source) > MaximumBytes) return new(CiCorpusCode.TooLarge, []);
        try
        {
            using var document = JsonDocument.Parse(source, new() { MaxDepth = 6, AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !Exact(root, RootFields) ||
                !root.GetProperty("version").TryGetInt32(out var version) || version != 1) return new(CiCorpusCode.InvalidSchema, []);
            var items = root.GetProperty("entries");
            if (items.ValueKind != JsonValueKind.Array || items.GetArrayLength() is 0 or > 64) return new(CiCorpusCode.InvalidSchema, []);
            var result = new List<CiCorpusEntry>();
            foreach (var item in items.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.Object || !Exact(item, EntryFields) ||
                    item.GetProperty("id").ValueKind != JsonValueKind.String ||
                    item.GetProperty("scenario").ValueKind != JsonValueKind.String ||
                    item.GetProperty("expected").ValueKind != JsonValueKind.String ||
                    !item.GetProperty("seed").TryGetInt64(out var seed) || seed is <= 0 or > 1_000_000)
                    return new(CiCorpusCode.InvalidSchema, []);
                var id = item.GetProperty("id").GetString(); var scenario = item.GetProperty("scenario").GetString();
                var expected = item.GetProperty("expected").GetString();
                if (!Token(id, 64) || scenario is not ("product" or "build" or "promotion" or "recovery") ||
                    expected is not { Length: 64 } || expected.Any(c => c is not (>= '0' and <= '9' or >= 'a' and <= 'f')))
                    return new(CiCorpusCode.InvalidSchema, []);
                result.Add(new(id!, seed, scenario, expected));
            }
            if (result.Select(x => x.Id).Distinct(StringComparer.Ordinal).Count() != result.Count ||
                result.Select(x => x.Seed).Distinct().Count() != result.Count) return new(CiCorpusCode.InvalidSchema, []);
            return new(CiCorpusCode.Accepted, result.AsReadOnly());
        }
        catch (JsonException) { return new(CiCorpusCode.InvalidJson, []); }
        catch (InvalidOperationException) { return new(CiCorpusCode.InvalidJson, []); }
    }
    internal static string Json(CiCorpusEntry entry) => JsonSerializer.Serialize(new { version = 1, entries = new[]
        { new { id = entry.Id, seed = entry.Seed, scenario = entry.Scenario, expected = entry.Expected } } });
    private static bool Token(string? value, int maximum)
    {
        if (value is not { Length: > 0 } || value.Length > maximum || value[0] == '-' || value[^1] == '-') return false;
        var previousHyphen = false;
        foreach (var c in value)
        {
            if (c == '-') { if (previousHyphen) return false; previousHyphen = true; continue; }
            if (c is not (>= 'a' and <= 'z' or >= '0' and <= '9')) return false;
            previousHyphen = false;
        }
        return true;
    }
    private static bool Exact(JsonElement element, HashSet<string> fields)
    {
        var properties = element.EnumerateObject().ToArray();
        return properties.Length == fields.Count && properties.All(property => fields.Contains(property.Name)) &&
            properties.Select(property => property.Name).Distinct(StringComparer.Ordinal).Count() == properties.Length;
    }
}
