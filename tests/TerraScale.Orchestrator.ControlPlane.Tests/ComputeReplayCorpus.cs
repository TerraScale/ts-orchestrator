using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using TerraScale.Orchestrator.ControlPlane.Compute;
using TerraScale.Orchestrator.ControlPlane.Storage;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

internal sealed record StorageComputeReplayEntry(string Domain, string Property, int Seed, string Expected);

internal static class StorageComputeReplayCorpus
{
    internal const string ResourceName = "TerraScale.Orchestrator.ControlPlane.Tests.Properties.StorageComputeReplayCorpus.v1.json";
    internal const string ContentSha256 = "f0f97770a45ab50329b71b07e8b48921a0ee26d1c3ade443ac8f604b49f557ff";
    internal const int MaximumBytes = 8_192;
    internal const int MaximumEntries = 32;
    internal const int MaximumStringLength = 64;
    private static readonly IReadOnlyDictionary<string, string> ClosedCases = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["storage\0generation"] = "StaleGeneration",
        ["storage\0fence"] = "WrongFence",
        ["storage\0expansion"] = "ShrinkForbidden",
        ["storage\0deletion"] = "DeletionProofMissing",
        ["compute\0capacity"] = "CapacityDenied",
        ["compute\0generation"] = "MissingProof",
        ["compute\0scale-in-floor"] = "FloorDenied",
        ["compute\0survival"] = "BundleIncomplete",
    };

    internal static IReadOnlyList<StorageComputeReplayEntry> Load()
    {
        using var stream = System.Reflection.Assembly.GetExecutingAssembly().GetManifestResourceStream(ResourceName)
            ?? throw new InvalidDataException("The fixed storage/compute replay corpus resource is absent.");
        return Parse(ReadBounded(stream), requireContentAddress: true);
    }

    internal static byte[] ReadBounded(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var buffer = new byte[MaximumBytes + 1];
        var count = 0;
        while (count < buffer.Length)
        {
            var read = stream.Read(buffer, count, buffer.Length - count);
            if (read == 0) break;
            count += read;
        }
        if (count > MaximumBytes) throw new InvalidDataException("Replay corpus byte bound violated.");
        return buffer[..count];
    }

    internal static IReadOnlyList<StorageComputeReplayEntry> Parse(byte[] bytes, bool requireContentAddress = false)
    {
        try { return ParseCore(bytes, requireContentAddress); }
        catch (InvalidDataException) { throw; }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException and not AccessViolationException)
        { throw new InvalidDataException("Replay corpus is malformed."); }
    }

    private static IReadOnlyList<StorageComputeReplayEntry> ParseCore(byte[] bytes, bool requireContentAddress)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        if (bytes.Length is 0 or > MaximumBytes) throw new InvalidDataException("Replay corpus byte bound violated.");
        if (requireContentAddress && !StringComparer.Ordinal.Equals(Convert.ToHexStringLower(SHA256.HashData(bytes)), ContentSha256))
            throw new InvalidDataException("Replay corpus content address mismatch.");
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions
        { AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow, MaxDepth = 8 });
        var root = document.RootElement;
        RequireObjectShape(root, "version", "entries");
        if (root.GetProperty("version").ValueKind != JsonValueKind.Number || root.GetProperty("version").GetInt32() != 1)
            throw new InvalidDataException("Unsupported replay corpus version.");
        var entries = root.GetProperty("entries");
        if (entries.ValueKind != JsonValueKind.Array || entries.GetArrayLength() is 0 or > MaximumEntries)
            throw new InvalidDataException("Replay corpus entry bound violated.");
        var result = new List<StorageComputeReplayEntry>();
        var identities = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in entries.EnumerateArray())
        {
            RequireObjectShape(item, "domain", "property", "seed", "expected");
            var domain = RequiredString(item, "domain");
            var property = RequiredString(item, "property");
            var expected = RequiredString(item, "expected");
            if (domain is not ("storage" or "compute")) throw new InvalidDataException("Replay corpus domain is closed.");
            var seed = item.GetProperty("seed").GetInt32();
            var caseKey = $"{domain}\0{property}";
            if (!ClosedCases.TryGetValue(caseKey, out var closedExpected) ||
                !StringComparer.Ordinal.Equals(expected, closedExpected))
                throw new InvalidDataException("Replay corpus case vocabulary is closed.");
            if (seed <= 0 || !identities.Add($"{caseKey}\0{seed}"))
                throw new InvalidDataException("Replay corpus seed is invalid or duplicated.");
            result.Add(new(domain, property, seed, expected));
        }
        return result.AsReadOnly();
    }

    private static string RequiredString(JsonElement item, string name)
    {
        var value = item.GetProperty(name);
        if (value.ValueKind != JsonValueKind.String || !ValidString(value.GetString()))
            throw new InvalidDataException("Replay corpus string is missing.");
        return value.GetString()!;
    }
    private static bool ValidString(string? value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > MaximumStringLength) return false;
        for (var index = 0; index < value.Length; index++)
        {
            var character = value[index];
            if (char.IsWhiteSpace(character) || char.IsControl(character)) return false;
            if (char.IsHighSurrogate(character))
            {
                if (++index >= value.Length || !char.IsLowSurrogate(value[index])) return false;
            }
            else if (char.IsLowSurrogate(character)) return false;
        }
        return true;
    }
    private static void RequireObjectShape(JsonElement element, params string[] expected)
    {
        if (element.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Replay corpus object expected.");
        var actual = element.EnumerateObject().Select(static property => property.Name).ToArray();
        if (actual.Length != expected.Length || actual.Distinct(StringComparer.Ordinal).Count() != actual.Length ||
            !actual.ToHashSet(StringComparer.Ordinal).SetEquals(expected))
            throw new InvalidDataException("Replay corpus object shape is not exact.");
    }
}

public sealed class ComputeReplayCorpusTests
{
    [Test]
    public async Task Fixed_content_addressed_corpus_strictly_replays_every_saved_failure()
    {
        var entries = StorageComputeReplayCorpus.Load();
        var observed = entries.Select(Replay).ToArray();
        await Assert.That(observed.SequenceEqual(entries.Select(static entry => entry.Expected), StringComparer.Ordinal)).IsTrue();
        await Assert.That(entries.Count).IsEqualTo(8);
    }

    [Test]
    public async Task Corpus_parser_rejects_unknown_duplicate_and_out_of_range_shape()
    {
        var unknown = """{"version":1,"entries":[],"unknown":true}"""u8.ToArray();
        var duplicate = """{"version":1,"version":1,"entries":[]}"""u8.ToArray();
        var oversized = new byte[StorageComputeReplayCorpus.MaximumBytes + 1];
        var unknownProperty = """{"version":1,"entries":[{"domain":"storage","property":"unknown","seed":1,"expected":"StaleGeneration"}]}"""u8.ToArray();
        var wrongExpected = """{"version":1,"entries":[{"domain":"storage","property":"generation","seed":1,"expected":"WrongFence"}]}"""u8.ToArray();
        var wrongSeedType = """{"version":1,"entries":[{"domain":"storage","property":"generation","seed":"1","expected":"StaleGeneration"}]}"""u8.ToArray();
        var outOfRangeSeed = """{"version":1,"entries":[{"domain":"storage","property":"generation","seed":999999999999,"expected":"StaleGeneration"}]}"""u8.ToArray();
        var controlledString = """{"version":1,"entries":[{"domain":"stor\u0001age","property":"generation","seed":1,"expected":"StaleGeneration"}]}"""u8.ToArray();
        var longString = System.Text.Encoding.UTF8.GetBytes($"{{\"version\":1,\"entries\":[{{\"domain\":\"storage\",\"property\":\"{new string('x', StorageComputeReplayCorpus.MaximumStringLength + 1)}\",\"seed\":1,\"expected\":\"StaleGeneration\"}}]}}");
        var wrongEntriesType = """{"version":1,"entries":{}}"""u8.ToArray();
        var tooDeep = System.Text.Encoding.UTF8.GetBytes($"{{\"version\":1,\"entries\":[{new string('[', 9)}{new string(']', 9)}]}}");
        await Assert.That(Capture(() => StorageComputeReplayCorpus.Parse(unknown))).IsTypeOf<InvalidDataException>();
        await Assert.That(Capture(() => StorageComputeReplayCorpus.Parse(duplicate))).IsTypeOf<InvalidDataException>();
        await Assert.That(Capture(() => StorageComputeReplayCorpus.Parse(oversized))).IsTypeOf<InvalidDataException>();
        foreach (var malformed in new[] { unknownProperty, wrongExpected, wrongSeedType, outOfRangeSeed,
                     controlledString, longString, wrongEntriesType, tooDeep })
            await Assert.That(Capture(() => StorageComputeReplayCorpus.Parse(malformed))).IsTypeOf<InvalidDataException>();
    }

    [Test]
    public async Task Corpus_loader_is_maximum_plus_one_bounded_for_non_seekable_partial_reads()
    {
        var exact = Enumerable.Range(0, StorageComputeReplayCorpus.MaximumBytes).Select(static value => (byte)value).ToArray();
        var exactStream = new PartialReadStream(exact, 7);
        var captured = StorageComputeReplayCorpus.ReadBounded(exactStream);
        await Assert.That(captured.SequenceEqual(exact)).IsTrue();
        await Assert.That(exactStream.CanSeek).IsFalse();

        var oversized = new byte[StorageComputeReplayCorpus.MaximumBytes + 1];
        var failure = Capture(() => StorageComputeReplayCorpus.ReadBounded(new PartialReadStream(oversized, 3)));
        await Assert.That(failure).IsTypeOf<InvalidDataException>();
    }

    private static string Replay(StorageComputeReplayEntry entry) => (entry.Domain, entry.Property) switch
    {
        ("storage", "generation") => StorageExpansionPlanner.Plan(StorageTestData.Volume(),
            StorageTestData.Context(generation: StorageTestData.Generation((ulong)entry.Seed)), StorageTestData.Expansion()).Code.ToString(),
        ("storage", "fence") => StorageExpansionPlanner.Plan(StorageTestData.Volume(),
            StorageTestData.Context(fence: StorageTestData.Fence($"fence-{entry.Seed}")), StorageTestData.Expansion()).Code.ToString(),
        ("storage", "expansion") => StorageExpansionPlanner.Plan(StorageTestData.Volume(requested: 90 + entry.Seed % 10),
            StorageTestData.Context(), StorageTestData.Expansion(scope: StorageTestData.Scope(requested: 90 + entry.Seed % 10))).Code.ToString(),
        ("storage", "deletion") => DeletionReplay(entry.Seed).Code.ToString(),
        ("compute", "capacity") => CapacityReplay(entry.Seed).Errors.Single().Code.ToString(),
        ("compute", "generation") => GenerationReplay(entry.Seed).Errors.Single().Code.ToString(),
        ("compute", "scale-in-floor") => FloorReplay(entry.Seed).Errors.Single().Code.ToString(),
        ("compute", "survival") => SurvivalReplay(entry.Seed).Errors.Single().Code.ToString(),
        _ => throw new InvalidDataException("Replay corpus property is closed."),
    };

    private static StorageDecision DeletionReplay(int seed)
    {
        var missing = seed % 8;
        var evidence = StorageTestData.Deletion(
            leadership: missing == 0 ? StorageProof.Unknown : StorageProof.Proven,
            topology: missing == 1 ? StorageProof.Unknown : StorageProof.Proven,
            quorum: missing == 2 ? StorageProof.Unknown : StorageProof.Proven,
            noReference: missing == 3 ? StorageProof.Unknown : StorageProof.Proven,
            backup: missing == 4 ? StorageProof.Unknown : StorageProof.Proven,
            retention: missing == 5 ? StorageProof.Unknown : StorageProof.Proven,
            ownerFence: missing == 6 ? StorageProof.Unknown : StorageProof.Proven,
            auditReady: missing == 7 ? StorageProof.Unknown : StorageProof.Proven);
        return StorageDeletionPlanner.Plan(StorageTestData.Volume(), StorageTestData.Context(), evidence);
    }

    private static ComputeDecision CapacityReplay(int seed)
    {
        var binding = Binding(seed); var plan = Plan(binding);
        return ComputeEngine.DecideScaleOut(new(binding, ScaleOutState.Authorized, Demand(binding), plan,
            new(plan, new("persisted")), Authorization(binding) with { CapacityAvailable = false },
            new(binding, new("key"), ProviderCreateStatus.ProvenAbsent, null, null, new("observed")), null, 50, 64));
    }
    private static ComputeDecision GenerationReplay(int seed)
    {
        var binding = Binding(seed); var plan = Plan(binding); var replay = binding with { Generation = binding.Generation + 1 };
        return ComputeEngine.DecideScaleOut(new(binding, ScaleOutState.Authorized, Demand(binding), plan,
            new(plan, new("persisted")), Authorization(replay),
            new(binding, new("key"), ProviderCreateStatus.ProvenAbsent, null, null, new("observed")), null, 50, 64));
    }
    private static ComputeDecision FloorReplay(int seed)
    {
        var compute = Binding(seed);
        var binding = new ScaleInBinding(compute, new("node"), new("resource"), new("lb"), new("volume"), ComputeNodeRole.TerraBase);
        var authorization = new ScaleInAuthorization(binding, new("low"), 45, 60, 3, 3, 1, 1, new("low-proof"),
            new("cooldown"), new("lifetime"), new("benefit"), new("control"), new("nats"), new("availability"),
            StatefulDisposition.Approved, new("stateful"), true, true, true, true, true, true, false, true);
        var progress = new ScaleInProgress(binding, null, null, null, null, null, null, null, null,
            VolumeDisposition.RetainedStateful, new("owner"), false, false, false, false, false, false, false, false);
        return ComputeEngine.DecideScaleIn(new(binding, ScaleInState.CandidateSelected, authorization, progress, 50, 64));
    }
    private static ComputeDecision SurvivalReplay(int seed)
    {
        var bundle = new RegionalSurvivalBundle(new($"bundle-{seed}"), new($"cell-{seed}"), 2, new("provider"), new("accepted"),
            new("accepted-digest"), new("accepted-signature"), new("rollback"), new("rollback-digest"),
            new("rollback-signature"), [new("secret")], [new(new("class"), new("template"), new("shape"), new("domain"))],
            new("trust"), new("nats"), new("dns"), new("backup"), 7, 90, 80, 150, 200);
        var evidence = new SurvivalBundleEvidence(bundle, new("signature"), new("encryption"), false, true, true, true,
            true, true, true, true, true);
        return ComputeEngine.DecideSurvival(new(bundle, evidence, new(bundle.Cell, 7, 90, new("authority"), true),
            bundle.Generation, 100, false, null, 64));
    }
    private static ComputeBinding Binding(int seed) => new(new($"cell-{seed}"), new("class"), new("template"), new("shape"),
        new("domain"), new("artifact"), new("digest"), new("demand"), new("operation"), new("provider"), 7, 3);
    private static DemandEvidence Demand(ComputeBinding binding) => new(binding, ComputeTrigger.Unschedulable, 45, 60, 1, true, true, false);
    private static ScaleOutPlan Plan(ComputeBinding binding) => new(binding, new(4, 24_576, 100, 120_000), 1, new("plan"));
    private static CapacityAuthorization Authorization(ComputeBinding binding) => new(binding, new(4, 24_576, 100, 120_000),
        1, new("budget"), new("quota"), new("capacity"), new("cost"), new("placement"), true, true, true, true, true);
    private static Exception? Capture(Action action) { try { action(); return null; } catch (Exception exception) { return exception; } }

    private sealed class PartialReadStream(byte[] bytes, int maximumChunk) : Stream
    {
        private int _position;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count)
        {
            var available = bytes.Length - _position;
            if (available == 0) return 0;
            var read = Math.Min(Math.Min(count, maximumChunk), available);
            Array.Copy(bytes, _position, buffer, offset, read);
            _position += read;
            return read;
        }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}

