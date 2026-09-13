using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TerraScale.Orchestrator.ControlPlane.Storage;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties;

internal sealed record StoragePlannerReplayEntry(string Family, int Seed, StorageAction Action,
    StorageIntentTarget Target, StorageDecisionCode Code);

internal static class StoragePlannerReplayCorpus
{
    internal const string ResourceName = "TerraScale.Orchestrator.ControlPlane.Tests.Properties.StoragePlannerReplayCorpus.v1.json";
    internal const string ContentSha256 = "ffe9207a5bc1fa53d9a72bb75c40ca7067b83ccb40426e572469f4970b1b2323";
    internal const int MaximumBytes = 8_192;
    internal const int MaximumEntries = 16;
    internal const int MaximumStringLength = 64;
    private static readonly string[] RequiredFamilies = ["attach", "authority", "create", "delete", "expand", "format"];

    internal static IReadOnlyList<StoragePlannerReplayEntry> Load()
    {
        using var stream = typeof(StoragePlannerReplayCorpus).Assembly.GetManifestResourceStream(ResourceName)
            ?? throw new InvalidDataException("The fixed storage planner replay corpus resource is absent.");
        return Parse(ReadBounded(stream), true);
    }

    internal static byte[] ReadBounded(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        try
        {
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
        catch (InvalidDataException) { throw; }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException and not AccessViolationException)
        { throw new InvalidDataException("Replay corpus could not be read safely."); }
    }

    internal static IReadOnlyList<StoragePlannerReplayEntry> Parse(byte[] bytes, bool requireContentAddress = false)
    {
        try { return ParseCore(bytes, requireContentAddress); }
        catch (InvalidDataException) { throw; }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException and not AccessViolationException)
        { throw new InvalidDataException("Replay corpus is malformed."); }
    }

    private static IReadOnlyList<StoragePlannerReplayEntry> ParseCore(byte[] bytes, bool requireContentAddress)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        if (bytes.Length is 0 or > MaximumBytes) throw new InvalidDataException("Replay corpus byte bound violated.");
        if (requireContentAddress && !StringComparer.Ordinal.Equals(
                Convert.ToHexStringLower(SHA256.HashData(bytes)), ContentSha256))
            throw new InvalidDataException("Replay corpus content address mismatch.");
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions
        { AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow, MaxDepth = 8 });
        var root = document.RootElement;
        RequireShape(root, "version", "entries");
        if (root.GetProperty("version").ValueKind != JsonValueKind.Number || root.GetProperty("version").GetInt32() != 1)
            throw new InvalidDataException("Unsupported replay corpus version.");
        var entries = root.GetProperty("entries");
        if (entries.ValueKind != JsonValueKind.Array || entries.GetArrayLength() is 0 or > MaximumEntries)
            throw new InvalidDataException("Replay corpus entry bound violated.");
        var result = new List<StoragePlannerReplayEntry>();
        var identities = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in entries.EnumerateArray())
        {
            RequireShape(item, "family", "seed", "action", "target", "code");
            var family = RequiredString(item, "family");
            if (!RequiredFamilies.Contains(family, StringComparer.Ordinal)) throw new InvalidDataException("Replay family is closed.");
            var seedElement = item.GetProperty("seed");
            if (seedElement.ValueKind != JsonValueKind.Number) throw new InvalidDataException("Replay seed must be numeric.");
            var seed = seedElement.GetInt32();
            if (seed is <= 0 or > 100_000 || !identities.Add($"{family}\0{seed}"))
                throw new InvalidDataException("Replay seed is invalid or duplicated.");
            var action = ParseEnum<StorageAction>(RequiredString(item, "action"));
            var target = ParseEnum<StorageIntentTarget>(RequiredString(item, "target"));
            var code = ParseEnum<StorageDecisionCode>(RequiredString(item, "code"));
            var expected = Expected(family, seed);
            if ((action, target, code) != expected) throw new InvalidDataException("Replay expectation is not seed-sensitive.");
            result.Add(new(family, seed, action, target, code));
        }
        if (!result.Select(static item => item.Family).Order(StringComparer.Ordinal)
            .SequenceEqual(RequiredFamilies, StringComparer.Ordinal))
            throw new InvalidDataException("Replay corpus must contain every family exactly once.");
        return result.AsReadOnly();
    }

    internal static (StorageAction, StorageIntentTarget, StorageDecisionCode) Expected(string family, int seed) => family switch
    {
        "create" => (StorageCreateCheckpoint)(1 + seed % 10) switch
        {
            StorageCreateCheckpoint.ClaimAccepted => E(StorageAction.Observe, StorageIntentTarget.ProviderVolume, StorageDecisionCode.NextStep),
            StorageCreateCheckpoint.CapacityAndBudgetChecked => E(StorageAction.Create, StorageIntentTarget.ProviderVolume, StorageDecisionCode.NextStep),
            StorageCreateCheckpoint.VolumeCreated => E(StorageAction.Attach, StorageIntentTarget.ProviderAttachment, StorageDecisionCode.NextStep),
            StorageCreateCheckpoint.AttachmentCreated => E(StorageAction.Verify, StorageIntentTarget.DeviceIdentity, StorageDecisionCode.NextStep),
            StorageCreateCheckpoint.DeviceIdentityVerified => E(StorageAction.Classify, StorageIntentTarget.DeviceIdentity, StorageDecisionCode.NextStep),
            StorageCreateCheckpoint.Classified => E(StorageAction.Format, StorageIntentTarget.Filesystem, StorageDecisionCode.NextStep),
            StorageCreateCheckpoint.FormattedIfNew => E(StorageAction.Mount, StorageIntentTarget.Filesystem, StorageDecisionCode.NextStep),
            StorageCreateCheckpoint.Mounted => E(StorageAction.Verify, StorageIntentTarget.Application, StorageDecisionCode.NextStep),
            _ => E(StorageAction.Verify, StorageIntentTarget.Application, StorageDecisionCode.Completed),
        },
        "format" => (seed % 6) switch
        {
            0 => E(StorageAction.Hold, StorageIntentTarget.None, StorageDecisionCode.WrongProviderVolume),
            1 => E(StorageAction.Mount, StorageIntentTarget.Filesystem, StorageDecisionCode.RecognizedVolumeNeverFormats),
            2 => E(StorageAction.Hold, StorageIntentTarget.None, StorageDecisionCode.WrongOwner),
            3 => E(StorageAction.Classify, StorageIntentTarget.DeviceIdentity, StorageDecisionCode.NextStep),
            4 => E(StorageAction.Hold, StorageIntentTarget.None, StorageDecisionCode.BlankProofRequired),
            _ => E(StorageAction.Format, StorageIntentTarget.Filesystem, StorageDecisionCode.NextStep),
        },
        "attach" => (seed % 10) switch
        {
            0 => E(StorageAction.Hold, StorageIntentTarget.None, StorageDecisionCode.DualWriter),
            1 or 7 => E(StorageAction.Detach, StorageIntentTarget.ProviderAttachment, StorageDecisionCode.NextStep),
            2 or 8 => E(StorageAction.Hold, StorageIntentTarget.None, StorageDecisionCode.NewWriterEpochRequired),
            3 or 9 => E(StorageAction.Attach, StorageIntentTarget.ProviderAttachment, StorageDecisionCode.NextStep),
            4 => E(StorageAction.Verify, StorageIntentTarget.Application, StorageDecisionCode.HealthVerificationRequired),
            5 => E(StorageAction.Verify, StorageIntentTarget.Application, StorageDecisionCode.Completed),
            _ => E(StorageAction.Hold, StorageIntentTarget.None, StorageDecisionCode.ReattachProofMissing),
        },
        "expand" => (seed % 13) switch
        {
            0 => E(StorageAction.Observe, StorageIntentTarget.None, StorageDecisionCode.NextStep),
            1 => E(StorageAction.Verify, StorageIntentTarget.Application, StorageDecisionCode.NextStep),
            2 => E(StorageAction.Extend, StorageIntentTarget.ProviderVolume, StorageDecisionCode.NextStep),
            3 => E(StorageAction.Observe, StorageIntentTarget.ProviderVolume, StorageDecisionCode.ProviderConvergencePending),
            4 => E(StorageAction.Rescan, StorageIntentTarget.DeviceIdentity, StorageDecisionCode.NextStep),
            5 => E(StorageAction.Extend, StorageIntentTarget.StorageLayout, StorageDecisionCode.NextStep),
            6 => E(StorageAction.Grow, StorageIntentTarget.Filesystem, StorageDecisionCode.NextStep),
            7 => E(StorageAction.Verify, StorageIntentTarget.Filesystem, StorageDecisionCode.SizeDisagreement),
            8 => E(StorageAction.Verify, StorageIntentTarget.Application, StorageDecisionCode.NextStep),
            9 => E(StorageAction.Observe, StorageIntentTarget.MetricsAndCost, StorageDecisionCode.NextStep),
            10 => E(StorageAction.Verify, StorageIntentTarget.Application, StorageDecisionCode.Completed),
            11 => E(StorageAction.Hold, StorageIntentTarget.None, StorageDecisionCode.ConflictingOperation),
            _ => E(StorageAction.Verify, StorageIntentTarget.ProviderVolume, StorageDecisionCode.NextStep),
        },
        "delete" => (seed % 10) switch
        {
            0 => E(StorageAction.Hold, StorageIntentTarget.None, StorageDecisionCode.PermanentRetention),
            1 => E(StorageAction.Hold, StorageIntentTarget.None, StorageDecisionCode.DeletionProofMissing),
            2 => E(StorageAction.Hold, StorageIntentTarget.None, StorageDecisionCode.QuarantineProofMissing),
            3 => E(StorageAction.Hold, StorageIntentTarget.None, StorageDecisionCode.DisposableProofMissing),
            4 => E(StorageAction.Delete, StorageIntentTarget.ProviderVolume, StorageDecisionCode.NextStep),
            5 => E(StorageAction.Observe, StorageIntentTarget.ProviderVolume, StorageDecisionCode.ProviderConvergencePending),
            6 => E(StorageAction.Observe, StorageIntentTarget.PostDeleteAudit, StorageDecisionCode.PostDeleteAuditRequired),
            7 => E(StorageAction.Verify, StorageIntentTarget.PostDeleteAudit, StorageDecisionCode.Completed),
            8 => E(StorageAction.Hold, StorageIntentTarget.None, StorageDecisionCode.WrongEvidenceScope),
            _ => E(StorageAction.Hold, StorageIntentTarget.None, StorageDecisionCode.StaleGeneration),
        },
        "authority" => (seed % 9) switch
        {
            0 => E(StorageAction.Hold, StorageIntentTarget.None, StorageDecisionCode.WrongProviderVolume),
            1 or 2 or 3 or 4 => E(StorageAction.Hold, StorageIntentTarget.None, StorageDecisionCode.WrongOwner),
            5 => E(StorageAction.Hold, StorageIntentTarget.None, StorageDecisionCode.WrongFence),
            6 => E(StorageAction.Hold, StorageIntentTarget.None, StorageDecisionCode.StaleGeneration),
            7 => E(StorageAction.Hold, StorageIntentTarget.None, StorageDecisionCode.StaleWriterEpoch),
            _ => E(StorageAction.Hold, StorageIntentTarget.None, StorageDecisionCode.WrongEvidenceScope),
        },
        _ => throw new InvalidDataException("Replay family is closed."),
    };

    private static T ParseEnum<T>(string value) where T : struct, Enum =>
        Enum.TryParse<T>(value, false, out var result) && Enum.IsDefined(result) &&
        StringComparer.Ordinal.Equals(Enum.GetName(result), value)
            ? result : throw new InvalidDataException("Replay enum vocabulary is closed.");
    private static string RequiredString(JsonElement item, string name)
    {
        var element = item.GetProperty(name);
        if (element.ValueKind != JsonValueKind.String || !ValidString(element.GetString()))
            throw new InvalidDataException("Replay string is invalid.");
        return element.GetString() ?? throw new InvalidDataException("Replay value must contain text.");
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
    private static void RequireShape(JsonElement element, params string[] expected)
    {
        if (element.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Replay object expected.");
        var names = element.EnumerateObject().Select(static property => property.Name).ToArray();
        if (names.Length != expected.Length || names.Distinct(StringComparer.Ordinal).Count() != names.Length ||
            !names.ToHashSet(StringComparer.Ordinal).SetEquals(expected))
            throw new InvalidDataException("Replay object shape is not exact.");
    }
    private static (StorageAction, StorageIntentTarget, StorageDecisionCode) E(StorageAction action,
        StorageIntentTarget target, StorageDecisionCode code) => (action, target, code);
}

public sealed class StoragePlannerReplayCorpusTests
{
    [Test]
    public async Task Fixed_SHA_pinned_corpus_replays_every_storage_family_exactly()
    {
        var entries = StoragePlannerReplayCorpus.Load();
        foreach (var entry in entries)
        {
            var decision = Replay(entry);
            await Assert.That((decision.Action, decision.Target, decision.Code))
                .IsEqualTo((entry.Action, entry.Target, entry.Code));
            await Assert.That(decision.Trace?.Requested.Value).IsEqualTo(60_000L + entry.Seed);
            await Assert.That(TraceFingerprint(decision)).IsEqualTo(
                $"{entry.Action}|{entry.Target}|{entry.Code}|TerraBase|key-secret|ad-1/fd-1|DatabaseData|ElasticQuarantine|backup-a|operation-a|fence-a");
            await Assert.That(StoragePlannerReplayCorpus.Expected(entry.Family, entry.Seed + 1))
                .IsNotEqualTo(StoragePlannerReplayCorpus.Expected(entry.Family, entry.Seed));
        }
        await Assert.That(entries.Count).IsEqualTo(6);
    }

    [Test]
    public async Task Parser_rejects_shape_vocabulary_range_completeness_and_seed_insensitive_mutations()
    {
        var valid = Encoding.UTF8.GetBytes("""
            {"version":1,"entries":[
            {"family":"create","seed":17,"action":"Verify","target":"Application","code":"NextStep"},
            {"family":"format","seed":19,"action":"Mount","target":"Filesystem","code":"RecognizedVolumeNeverFormats"},
            {"family":"attach","seed":23,"action":"Attach","target":"ProviderAttachment","code":"NextStep"},
            {"family":"expand","seed":29,"action":"Observe","target":"ProviderVolume","code":"ProviderConvergencePending"},
            {"family":"delete","seed":31,"action":"Hold","target":"None","code":"DeletionProofMissing"},
            {"family":"authority","seed":41,"action":"Hold","target":"None","code":"WrongFence"}]}
            """);
        var validText = Encoding.UTF8.GetString(valid);
        var malformed = new[]
        {
            Encoding.UTF8.GetBytes("{\"version\":1,\"entries\":[],\"extra\":true}"),
            Encoding.UTF8.GetBytes("{\"version\":1,\"version\":1,\"entries\":[]}"),
            Encoding.UTF8.GetBytes("{\"version\":2,\"entries\":[]}"),
            Encoding.UTF8.GetBytes("{\"version\":1,\"entries\":{}}"),
            Encoding.UTF8.GetBytes("[]"),
            Encoding.UTF8.GetBytes("{\"version\":1,\"entries\":[[]]}"),
            Encoding.UTF8.GetBytes("{\"version\":1,/*comment*/\"entries\":[]}"),
            Encoding.UTF8.GetBytes("{\"version\":1,\"entries\":[],}"),
            Encoding.UTF8.GetBytes($"{{\"version\":1,\"entries\":[{string.Join(',', Enumerable.Repeat("{}", StoragePlannerReplayCorpus.MaximumEntries + 1))}]}}"),
            valid.AsSpan(0, valid.Length - 2).ToArray(),
            Encoding.UTF8.GetBytes(validText.Replace("\"seed\":17", "\"seed\":18", StringComparison.Ordinal)),
            Encoding.UTF8.GetBytes(validText.Replace("\"action\":\"Verify\"", "\"action\":\"verify\"", StringComparison.Ordinal)),
            Encoding.UTF8.GetBytes(validText.Replace("\"action\":\"Verify\"", "\"action\":\"9\"", StringComparison.Ordinal)),
            Encoding.UTF8.GetBytes(validText.Replace("\"seed\":17", "\"seed\":0", StringComparison.Ordinal)),
            Encoding.UTF8.GetBytes(validText.Replace("\"seed\":17", "\"seed\":100001", StringComparison.Ordinal)),
            Encoding.UTF8.GetBytes(validText.Replace("\"seed\":17", "\"seed\":\"17\"", StringComparison.Ordinal)),
            Encoding.UTF8.GetBytes(validText.Replace("{\"family\":\"create\"", "{\"family\":\"create\",\"extra\":1", StringComparison.Ordinal)),
            Encoding.UTF8.GetBytes(validText.Replace("{\"family\":\"create\"", "{\"family\":\"create\",\"family\":\"create\"", StringComparison.Ordinal)),
            Encoding.UTF8.GetBytes(validText.Replace("\"family\":\"create\"", "\"family\":\"cre\\u0001ate\"", StringComparison.Ordinal)),
            Encoding.UTF8.GetBytes(validText.Replace("\"family\":\"create\"", $"\"family\":\"{new string('x', StoragePlannerReplayCorpus.MaximumStringLength + 1)}\"", StringComparison.Ordinal)),
            Encoding.UTF8.GetBytes(validText.Replace("{\"family\":\"authority\"", "{\"family\":\"create\"", StringComparison.Ordinal)),
        };
        foreach (var item in malformed)
            await Assert.That(Capture(() => StoragePlannerReplayCorpus.Parse(item))).IsTypeOf<InvalidDataException>();
        await Assert.That(Capture(() => StoragePlannerReplayCorpus.Parse(new byte[StoragePlannerReplayCorpus.MaximumBytes + 1])))
            .IsTypeOf<InvalidDataException>();
        await Assert.That(Capture(() => StoragePlannerReplayCorpus.Parse(valid, true))).IsTypeOf<InvalidDataException>();
    }

    [Test]
    public async Task Corpus_stream_capture_is_maximum_plus_one_bounded_and_fatal_safe()
    {
        var exact = new byte[StoragePlannerReplayCorpus.MaximumBytes];
        await Assert.That(StoragePlannerReplayCorpus.ReadBounded(new PartialReadStream(exact, 7)).Length)
            .IsEqualTo(StoragePlannerReplayCorpus.MaximumBytes);
        await Assert.That(Capture(() => StoragePlannerReplayCorpus.ReadBounded(
            new PartialReadStream(new byte[StoragePlannerReplayCorpus.MaximumBytes + 1], 3))))
            .IsTypeOf<InvalidDataException>();
        foreach (var fatal in new Exception[] { new OutOfMemoryException(), new StackOverflowException(), new AccessViolationException() })
            await Assert.That(Capture(() => StoragePlannerReplayCorpus.ReadBounded(new ThrowingStream(fatal)))?.GetType())
                .IsEqualTo(fatal.GetType());
    }

    private static StorageDecision Replay(StoragePlannerReplayEntry entry)
    {
        var requested = 60_000L + entry.Seed;
        var volume = StorageTestData.Volume(requested: requested);
        var scope = StorageTestData.Scope(requested: requested);
        return entry.Family switch
        {
            "create" => StorageCreatePlanner.Plan(volume, StorageTestData.Context(),
                (StorageCreateCheckpoint)(1 + entry.Seed % 10), StorageTestData.Format(scope: scope)),
            "format" => ReplayFormat(entry.Seed, volume, scope),
            "attach" => StorageAttachmentPlanner.Plan(volume, StorageTestData.Context(), StorageTestData.Node($"new-{entry.Seed}"),
                new StorageReattachEvidence(scope, [], StorageProof.Unknown, StorageProof.Unknown, StorageProof.Proven,
                    StorageProof.Unknown, StorageProof.Proven, StorageTestData.Epoch(8), 4)),
            "expand" => StorageExpansionPlanner.Plan(volume, StorageTestData.Context(),
                StorageTestData.Expansion(StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, scope: scope)),
            "delete" => StorageDeletionPlanner.Plan(volume, StorageTestData.Context(), StorageTestData.Deletion(
                leadership: StorageProof.Unknown, scope: scope)),
            "authority" => StorageAttachmentPlanner.Plan(volume,
                AuthorityContext(entry.Seed), StorageTestData.Node($"new-{entry.Seed}"),
                new StorageReattachEvidence(scope, [], StorageProof.Proven, StorageProof.Proven, StorageProof.Proven,
                    StorageProof.Unknown, StorageProof.Proven, StorageTestData.Epoch(8), 4)),
            _ => throw new InvalidDataException("Replay family is closed."),
        };
    }

    private static string TraceFingerprint(StorageDecision decision) =>
        $"{decision.Action}|{decision.Target}|{decision.Code}|{decision.Scope?.Domain}|{decision.Scope?.EncryptionKey.Value}|{decision.Scope?.Placement.Value}|{decision.Scope?.MountPurpose}|{decision.Scope?.Retention}|{decision.Scope?.Backup.Value}|{decision.Scope?.Operation.Value}|{decision.Scope?.Fence.Value}";

    private static StorageDecision ReplayFormat(int seed, StorageVolumeRecord volume, StorageEvidenceScope scope)
    {
        var evidence = (seed % 6) switch
        {
            1 => StorageTestData.Format(classification: StorageDeviceClassification.Recognized, scope: scope),
            _ => throw new InvalidDataException("Pinned format seed changed unexpectedly."),
        };
        return StorageFormatPlanner.Plan(volume, StorageTestData.Context(), evidence);
    }

    private static StorageAuthorityContext AuthorityContext(int seed) => (seed % 9) switch
    {
        0 => StorageTestData.Context(provider: StorageTestData.Provider($"wrong-{seed}")),
        1 => StorageTestData.Context(claim: StorageTestData.Claim($"wrong-{seed}")),
        2 => StorageTestData.Context(cell: StorageTestData.Cell($"wrong-{seed}")),
        3 => StorageTestData.Context(workload: StorageTestData.Workload($"wrong-{seed}")),
        4 => StorageTestData.Context(member: StorageTestData.Member($"wrong-{seed}")),
        5 => StorageTestData.Context(fence: StorageTestData.Fence($"wrong-{seed}")),
        6 => StorageTestData.Context(generation: StorageTestData.Generation((ulong)(100 + seed))),
        7 => StorageTestData.Context(epoch: StorageTestData.Epoch((ulong)(100 + seed))),
        _ => StorageTestData.Context(),
    };

    private static Exception? Capture(Action action) { try { action(); return null; } catch (Exception exception) { return exception; } }

    private sealed class PartialReadStream(byte[] bytes, int chunk) : Stream
    {
        private int _position;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_position == bytes.Length) return 0;
            var read = Math.Min(Math.Min(count, chunk), bytes.Length - _position);
            Array.Copy(bytes, _position, buffer, offset, read);
            _position += read;
            return read;
        }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class ThrowingStream(Exception exception) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => throw exception;
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
