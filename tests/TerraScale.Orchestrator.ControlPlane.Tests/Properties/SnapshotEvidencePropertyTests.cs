using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TerraScale.Orchestrator.ControlPlane.Evidence;
using TerraScale.Orchestrator.ControlPlane.Snapshots;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties;

public sealed class SnapshotEvidencePropertyTests
{
    private const int Cases = 1_000;

    [Test]
    public async Task Snapshot_epoch_and_position_freshness_matches_independent_oracle_for_1000_cases()
    {
        for (var seed = 0; seed < Cases; seed++)
        {
            var currentEpoch = 10UL + (ulong)(seed % 100);
            var currentSequence = 1_000UL + (ulong)seed;
            var mode = seed % 5;
            var candidateEpoch = mode == 1 ? currentEpoch - 1 : mode == 4 ? currentEpoch + 1 : currentEpoch;
            var candidateSequence = mode switch { 2 => currentSequence, 3 or 4 => currentSequence - 1, _ => currentSequence + 1 };
            var result = SignedSnapshotValidator.Validate(
                SnapshotTestData.Snapshot(SnapshotTestData.Material(epoch: SnapshotTestData.Epoch(candidateEpoch), sequence: SnapshotTestData.Sequence(candidateSequence))),
                SnapshotTestData.Context(currentEpoch: SnapshotTestData.Epoch(currentEpoch), currentSequence: SnapshotTestData.Sequence(currentSequence)));
            var expected = mode switch
            {
                1 => SnapshotValidationError.StaleEpoch,
                2 or 3 or 4 => SnapshotValidationError.StreamRollback,
                _ => SnapshotValidationError.None,
            };
            await Assert.That(result.Error).IsEqualTo(expected);
        }
    }

    [Test]
    public async Task Snapshot_signed_projection_corruption_matches_independent_field_oracle_for_1000_cases()
    {
        for (var seed = 0; seed < Cases; seed++)
        {
            var original = SnapshotTestData.Material(id: SnapshotTestData.Id($"snapshot-{seed}"));
            var mode = seed % 10;
            var candidate = mode switch
            {
                0 => original,
                1 => SnapshotTestData.Material(authority: SnapshotTestData.Authority("other"), id: original.SnapshotId),
                2 => SnapshotTestData.Material(stream: SnapshotTestData.Stream("other"), id: original.SnapshotId),
                3 => SnapshotTestData.Material(id: SnapshotTestData.Id($"tampered-{seed}")),
                4 => SnapshotTestData.Material(schema: SnapshotTestData.Schema("other"), id: original.SnapshotId),
                5 => SnapshotTestData.Material(key: SnapshotTestData.Key("other"), id: original.SnapshotId),
                6 => SnapshotTestData.Material(epoch: SnapshotTestData.Epoch(8), id: original.SnapshotId),
                7 => SnapshotTestData.Material(sequence: SnapshotTestData.Sequence(102), id: original.SnapshotId),
                8 => SnapshotTestData.Material(generation: SnapshotTestData.Generation(4), id: original.SnapshotId),
                _ => SnapshotTestData.Material(digest: SnapshotTestData.Digest("other"), id: original.SnapshotId),
            };
            var context = SnapshotTestData.Context(authority: candidate.Authority, stream: candidate.Stream, key: candidate.SigningKey,
                currentSchema: candidate.Schema, currentEpoch: SnapshotTestData.Epoch(1), currentSequence: SnapshotTestData.Sequence(1),
                digest: candidate.StateDigest, signatureVerifier: new TestSnapshotSignatureVerifier(expectedMaterial: original));
            var result = SignedSnapshotValidator.Validate(SnapshotTestData.Snapshot(candidate), context);
            await Assert.That(result.Error).IsEqualTo(mode == 0 ? SnapshotValidationError.None : SnapshotValidationError.InvalidSignature);
        }
    }

    [Test]
    public async Task Restore_replay_start_and_replay_equivalence_hold_across_1000_cases_and_cultures()
    {
        var cultures = new[] { "en-US", "tr-TR", "ar-SA" };
        for (var seed = 0; seed < Cases; seed++)
        {
            var sequence = 2UL + (ulong)seed;
            var snapshot = SnapshotTestData.Snapshot(SnapshotTestData.Material(sequence: SnapshotTestData.Sequence(sequence)));
            var context = SnapshotTestData.Context(currentSequence: SnapshotTestData.Sequence(sequence - 1));
            var original = CultureInfo.CurrentCulture;
            try
            {
                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(cultures[seed % cultures.Length]);
                var first = SnapshotRestorePlanner.Plan(snapshot, context);
                var replay = SnapshotRestorePlanner.Plan(snapshot, context);
                await Assert.That(first.IsPlanned).IsTrue();
                await Assert.That(first.Plan!.ReplayStartSequence.Value).IsEqualTo(sequence + 1);
                await Assert.That(Projection(first)).IsEqualTo(Projection(replay));
            }
            finally { CultureInfo.CurrentCulture = original; }
        }
    }

    [Test]
    public async Task Snapshot_completeness_schema_digest_signature_and_overflow_fail_closed_for_1000_cases()
    {
        var fingerprints = new HashSet<string>(StringComparer.Ordinal);
        for (var seed = 0; seed < Cases; seed++)
        {
            var mode = seed % 6;
            var material = SnapshotTestData.Material(id: SnapshotTestData.Id($"completeness-{seed}"));
            fingerprints.Add($"{seed}|{mode}|{material.SnapshotId.Value}");
            var result = mode switch
            {
                0 => SnapshotRestorePlanner.Plan(new SignedSnapshot(material, null!), SnapshotTestData.Context()),
                1 => SnapshotRestorePlanner.Plan(SnapshotTestData.Snapshot(material), SnapshotTestData.Context(compatibility: new TestSchemaCompatibility(SnapshotSchemaCompatibilityOutcome.Unknown))),
                2 => SnapshotRestorePlanner.Plan(SnapshotTestData.Snapshot(material), SnapshotTestData.Context(compatibility: new TestSchemaCompatibility(SnapshotSchemaCompatibilityOutcome.Incompatible))),
                3 => SnapshotRestorePlanner.Plan(SnapshotTestData.Snapshot(material), SnapshotTestData.Context(digest: SnapshotTestData.Digest("corrupt"))),
                4 => SnapshotRestorePlanner.Plan(SnapshotTestData.Snapshot(material), SnapshotTestData.Context(signatureVerifier: new TestSnapshotSignatureVerifier(SnapshotSignatureVerificationOutcome.Invalid))),
                _ => SnapshotRestorePlanner.Plan(SnapshotTestData.Snapshot(SnapshotTestData.Material(id: material.SnapshotId, sequence: SnapshotTestData.Sequence(ulong.MaxValue))), SnapshotTestData.Context(currentSequence: SnapshotTestData.Sequence(1))),
            };
            var expected = mode switch
            {
                0 => SnapshotValidationError.MalformedSnapshot,
                1 => SnapshotValidationError.UnknownSchema,
                2 => SnapshotValidationError.IncompatibleSchema,
                3 => SnapshotValidationError.StateDigestMismatch,
                4 => SnapshotValidationError.InvalidSignature,
                _ => SnapshotValidationError.None,
            };
            await Assert.That(result.IsPlanned).IsFalse();
            await Assert.That(result.ValidationError).IsEqualTo(expected);
            if (mode == 5) await Assert.That(result.Error).IsEqualTo(SnapshotRestorePlanError.ReplayStartOverflow);
        }
        await Assert.That(fingerprints.Count).IsEqualTo(Cases);
    }

    [Test]
    public async Task Evidence_generation_and_expiry_freshness_matches_independent_oracle_for_1000_cases()
    {
        var fingerprints = new HashSet<string>(StringComparer.Ordinal);
        for (var seed = 0; seed < Cases; seed++)
        {
            var mode = seed % 6;
            var expectedGeneration = 10_000UL + (ulong)seed;
            var expectedExpiry = 20_000UL + (ulong)seed;
            var generation = mode == 1 ? expectedGeneration - 1 : mode == 2 ? expectedGeneration + 1 : expectedGeneration;
            var expiry = mode == 3 ? expectedExpiry - 1 : mode == 4 ? expectedExpiry + 1 : mode == 5 ? expectedExpiry : expectedExpiry;
            var current = mode == 5 ? expectedExpiry + 1 : expectedExpiry - 1;
            fingerprints.Add($"{expectedGeneration}|{generation}|{expectedExpiry}|{expiry}|{current}");
            var decision = EvidenceTestData.Gate(envelope: EvidenceTestData.Envelope(generation: EvidenceTestData.G(generation), expiry: EvidenceTestData.Q(expiry)),
                context: EvidenceTestData.Context(generation: EvidenceTestData.G(expectedGeneration), current: EvidenceTestData.Q(current), expectedExpiry: EvidenceTestData.Q(expectedExpiry)));
            var expected = mode switch
            {
                1 => EvidenceCode.StaleGeneration,
                2 => EvidenceCode.FutureGeneration,
                3 => EvidenceCode.StaleExpiry,
                4 => EvidenceCode.FutureExpiry,
                5 => EvidenceCode.Expired,
                _ => EvidenceCode.Allowed,
            };
            await Assert.That(decision.Code).IsEqualTo(expected);
            await Assert.That(decision.AuthorizationScope is null).IsEqualTo(mode != 0);
        }
        await Assert.That(fingerprints.Count).IsEqualTo(Cases);
    }

    [Test]
    public async Task Evidence_collection_permutation_and_culture_are_equivalent_for_1000_cases()
    {
        var cultures = new[] { "en-US", "tr-TR", "ar-SA" };
        var fingerprints = new HashSet<string>(StringComparer.Ordinal);
        for (var seed = 0; seed < Cases; seed++)
        {
            var tree = EvidenceTestData.Tree($"tree-{seed}");
            var suites = new[]
            {
                EvidenceTestData.SuiteResult(EvidenceDomain.Control, suite: EvidenceTestData.Suite($"control-{seed}")),
                EvidenceTestData.SuiteResult(EvidenceDomain.Storage, suite: EvidenceTestData.Suite($"storage-{seed}")),
            };
            fingerprints.Add($"{tree.Value}|{string.Join('|', suites.Select(suite => suite.Suite.Value))}");
            var models = new[]
            {
                new EvidenceModelCorpus(EvidenceDomain.Control, EvidenceTestData.Corpus("control-model"), EvidenceTestData.D(9)),
                new EvidenceModelCorpus(EvidenceDomain.Storage, EvidenceTestData.Corpus("storage-model"), EvidenceTestData.D(12)),
            };
            var policy = EvidenceTestData.Policy(domains: [EvidenceDomain.Control, EvidenceDomain.Storage]);
            var expected = EvidenceTestData.Subject(tree: tree, suites: suites, models: models);
            var forward = EvidenceTestData.Gate(manifest: EvidenceTestData.Manifest(EvidenceTestData.Subject(tree: tree, suites: suites, models: models)), policy: policy, context: EvidenceTestData.Context(subject: expected));
            await Assert.That(forward.Code).IsEqualTo(EvidenceCode.Allowed);
            await Assert.That(forward.Action).IsEqualTo(EvidenceAction.AllowL1SCredentialRelease);
            await Assert.That(forward.Subject).IsNotNull();
            await Assert.That(forward.Subject!.PayloadDigest).IsEqualTo(EvidenceTestData.D(20));
            await Assert.That(forward.AuthorizationScope).IsNotNull();
            var original = CultureInfo.CurrentCulture;
            try
            {
                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(cultures[seed % cultures.Length]);
                var reverse = EvidenceTestData.Gate(manifest: EvidenceTestData.Manifest(EvidenceTestData.Subject(tree: tree, suites: suites.Reverse(), models: models.Reverse())), policy: policy, context: EvidenceTestData.Context(subject: expected));
                await Assert.That(reverse.Code).IsEqualTo(forward.Code);
                await Assert.That(reverse.Action).IsEqualTo(forward.Action);
                await Assert.That(reverse.AuthorizationScope).IsEqualTo(forward.AuthorizationScope);
            }
            finally { CultureInfo.CurrentCulture = original; }
        }
        await Assert.That(fingerprints.Count).IsEqualTo(Cases);
    }

    [Test]
    public async Task Snapshot_and_evidence_authorizing_outputs_are_construction_closed()
    {
        await Assert.That(typeof(SnapshotValidationResult).GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
        await Assert.That(typeof(SnapshotRestorePlan).GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
        await Assert.That(typeof(SnapshotRestorePlanResult).GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
        await Assert.That(typeof(EvidenceDecision).GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
        await Assert.That(typeof(EvidenceDecisionSubject).GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
        await Assert.That(typeof(EvidenceAuthorizationScope).GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
    }

    [Test]
    public async Task External_snapshot_and_evidence_verifiers_classify_ordinary_failures_and_propagate_fatals()
    {
        var ordinaryEvidence = EvidenceTestData.Gate(context: EvidenceTestData.Context(verifier: new ThrowingEvidenceVerifier(new InvalidOperationException("secret-evidence"))));
        var ordinarySchema = SignedSnapshotValidator.Validate(SnapshotTestData.Snapshot(), SnapshotTestData.Context(compatibility: new ThrowingSchemaCompatibility(new InvalidOperationException("secret-schema"))));
        var ordinarySignature = SignedSnapshotValidator.Validate(SnapshotTestData.Snapshot(), SnapshotTestData.Context(signatureVerifier: new ThrowingSnapshotVerifier(new InvalidOperationException("secret-signature"))));
        await Assert.That(ordinaryEvidence.Code).IsEqualTo(EvidenceCode.SignatureVerificationFailed);
        await Assert.That(ordinarySchema.Error).IsEqualTo(SnapshotValidationError.SchemaCompatibilityFailed);
        await Assert.That(ordinarySignature.Error).IsEqualTo(SnapshotValidationError.SignatureVerificationFailed);
        await Assert.That($"{ordinaryEvidence}|{ordinarySchema}|{ordinarySignature}").DoesNotContain("secret-");

        foreach (var fatal in new Exception[] { new OutOfMemoryException("fatal"), new StackOverflowException("fatal"), new AccessViolationException("fatal") })
        {
            await Assert.That(Capture(() => EvidenceTestData.Gate(context: EvidenceTestData.Context(verifier: new ThrowingEvidenceVerifier(fatal))) )!.GetType()).IsEqualTo(fatal.GetType());
            await Assert.That(Capture(() => SignedSnapshotValidator.Validate(SnapshotTestData.Snapshot(), SnapshotTestData.Context(compatibility: new ThrowingSchemaCompatibility(fatal))))!.GetType()).IsEqualTo(fatal.GetType());
            await Assert.That(Capture(() => SignedSnapshotValidator.Validate(SnapshotTestData.Snapshot(), SnapshotTestData.Context(signatureVerifier: new ThrowingSnapshotVerifier(fatal))))!.GetType()).IsEqualTo(fatal.GetType());
        }
    }

    [Test]
    public async Task Strict_whole_file_pinned_replay_corpus_is_input_sensitive()
    {
        var items = SnapshotEvidenceReplayCorpus.Load();
        var outcomes = new HashSet<string>(StringComparer.Ordinal);
        var fingerprints = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in items)
        {
            var actual = Replay(item);
            await Assert.That(actual).IsEqualTo(item.Expected);
            outcomes.Add(actual);
            var fingerprint = Fingerprint(item);
            await Assert.That(fingerprints.Add(fingerprint)).IsTrue();
            var mutation = item.Domain switch
            {
                "snapshot" when item.Expected == "StaleEpoch" => item with { Candidate = item.Current },
                "snapshot" when item.Expected == "StreamRollback" => item with { Position = item.Baseline + 1 },
                "snapshot" => item with { Position = item.Baseline },
                "evidence" when item.Expected == "Allowed" => item with { Candidate = item.Current - 1 },
                "evidence" => item with { Candidate = item.Current },
                _ => throw new InvalidDataException("Unknown replay domain."),
            };
            await Assert.That(Fingerprint(mutation)).IsNotEqualTo(fingerprint);
            await Assert.That(Replay(mutation)).IsNotEqualTo(actual);
        }
        await Assert.That(outcomes.Count).IsGreaterThan(3);
    }

    [Test]
    public async Task Replay_corpus_parser_rejects_ambiguous_or_noncanonical_json()
    {
        var invalid = new[]
        {
            "[{\"Id\":\"a\",\"Id\":\"b\",\"Domain\":\"snapshot\",\"Current\":7,\"Candidate\":7,\"Baseline\":100,\"Position\":101,\"Expected\":\"None\"}]",
            "[{\"Id\":\"a\",\"Domain\":\"snapshot\",\"Current\":7,\"Candidate\":7,\"Baseline\":100,\"Position\":101}]",
            "[{\"Id\":\"a\",\"Domain\":\"snapshot\",\"Current\":7,\"Candidate\":7,\"Baseline\":100,\"Position\":101,\"Expected\":\"None\",\"Extra\":1}]",
            "[{\"Id\":1,\"Domain\":\"snapshot\",\"Current\":7,\"Candidate\":7,\"Baseline\":100,\"Position\":101,\"Expected\":\"None\"}]",
            "[{\"Id\":\"a\",\"Domain\":\"snapshot\",\"Current\":\"7\",\"Candidate\":7,\"Baseline\":100,\"Position\":101,\"Expected\":\"None\"}]",
            "[{\"Id\":\"a\",\"Domain\":\"snapshot\",\"Current\":7,\"Candidate\":7,\"Baseline\":100,\"Position\":101,\"Expected\":true}]",
            "[{\"Id\":\"a\",\"Domain\":\"snapshot\",\"Current\":7,\"Candidate\":7,\"Baseline\":100,\"Position\":101,\"Expected\":\"Allowed\"}]",
            "[{\"Id\":\"a\",\"Domain\":\"snapshot\",\"Current\":0,\"Candidate\":7,\"Baseline\":100,\"Position\":101,\"Expected\":\"None\"}]",
            "[/*comment*/{\"Id\":\"a\",\"Domain\":\"snapshot\",\"Current\":7,\"Candidate\":7,\"Baseline\":100,\"Position\":101,\"Expected\":\"None\"}]",
            "[{\"Id\":\"a\",\"Domain\":\"snapshot\",\"Current\":7,\"Candidate\":7,\"Baseline\":100,\"Position\":101,\"Expected\":\"None\"},]",
            "[] {}",
            "[[[[[[[[[[{}]]]]]]]]]]",
        };
        foreach (var json in invalid)
            await Assert.That(Capture(() => SnapshotEvidenceReplayCorpus.ParseForTest(Encoding.UTF8.GetBytes(json)))).IsTypeOf<InvalidDataException>();
        var entries = "[" + string.Join(',', Enumerable.Range(0, 65).Select(index =>
            $"{{\"Id\":\"id-{index}\",\"Domain\":\"snapshot\",\"Current\":7,\"Candidate\":7,\"Baseline\":100,\"Position\":101,\"Expected\":\"None\"}}")) + "]";
        await Assert.That(Capture(() => SnapshotEvidenceReplayCorpus.ParseForTest(Encoding.UTF8.GetBytes(entries)))).IsTypeOf<InvalidDataException>();
        await Assert.That(Capture(() => SnapshotEvidenceReplayCorpus.ParseForTest(new byte[16_385]))).IsTypeOf<InvalidDataException>();
        var maximumId = new string('a', 64);
        await Assert.That(SnapshotEvidenceReplayCorpus.ParseForTest(CorpusWithFirstId(maximumId)).Count).IsEqualTo(8);
        foreach (var id in new[] { new string('a', 65), "-leading", "trailing-", "double--hyphen", "control_value", "control\nvalue" })
            await Assert.That(Capture(() => SnapshotEvidenceReplayCorpus.ParseForTest(CorpusWithFirstId(id)))).IsTypeOf<InvalidDataException>();
    }

    private static string Projection(SnapshotRestorePlanResult result) =>
        $"{result.Error}|{result.ValidationError}|{SnapshotRestorePlanFingerprint.Create(result.Plan!)}";
    private static string Replay(SnapshotEvidenceReplayItem item) => item.Domain switch
    {
        "snapshot" => SignedSnapshotValidator.Validate(
            SnapshotTestData.Snapshot(SnapshotTestData.Material(epoch: SnapshotTestData.Epoch((ulong)item.Candidate), sequence: SnapshotTestData.Sequence((ulong)item.Position))),
            SnapshotTestData.Context(currentEpoch: SnapshotTestData.Epoch((ulong)item.Current), currentSequence: SnapshotTestData.Sequence((ulong)item.Baseline))).Error.ToString(),
        "evidence" => EvidenceTestData.Gate(envelope: EvidenceTestData.Envelope(generation: EvidenceTestData.G((ulong)item.Candidate)),
            context: EvidenceTestData.Context(generation: EvidenceTestData.G((ulong)item.Current))).Code.ToString(),
        _ => throw new InvalidDataException("Unknown replay domain."),
    };
    private static string Fingerprint(SnapshotEvidenceReplayItem item) => $"{item.Id}|{item.Domain}|{item.Current}|{item.Candidate}|{item.Baseline}|{item.Position}|{item.Expected}";
    private static byte[] CorpusWithFirstId(string id)
    {
        var ids = new[] { id }.Concat(Enumerable.Range(1, 7).Select(index => $"fixture-{index}"));
        var json = "[" + string.Join(',', ids.Select(value =>
            $"{{\"Id\":{JsonSerializer.Serialize(value)},\"Domain\":\"snapshot\",\"Current\":7,\"Candidate\":7,\"Baseline\":100,\"Position\":101,\"Expected\":\"None\"}}")) + "]";
        return Encoding.UTF8.GetBytes(json);
    }
    private static Exception? Capture(Action action) { try { action(); return null; } catch (Exception exception) { return exception; } }
}

internal sealed class ThrowingEvidenceVerifier(Exception failure) : IEvidenceSignatureVerifier
{
    public EvidenceSignatureVerificationOutcome Verify(EvidenceSignedMaterial material, EvidenceOpaqueSignature signature) => throw failure;
}
internal sealed class ThrowingSchemaCompatibility(Exception failure) : ISnapshotSchemaCompatibility
{
    public SnapshotSchemaCompatibilityOutcome Evaluate(SnapshotSchemaId currentSchema, SnapshotSchemaId candidateSchema) => throw failure;
}
internal sealed class ThrowingSnapshotVerifier(Exception failure) : ISnapshotSignatureVerifier
{
    public SnapshotSignatureVerificationOutcome Verify(SnapshotSignedMaterial signedMaterial, SnapshotSignature signature) => throw failure;
}

internal sealed record SnapshotEvidenceReplayItem(string Id, string Domain, long Current, long Candidate, long Baseline, long Position, string Expected);

internal static class SnapshotEvidenceReplayCorpus
{
    private const string ResourceName = "TerraScale.Orchestrator.ControlPlane.Tests.Properties.SnapshotEvidenceReplayCorpus.v1.json";
    private const string ExpectedSha256 = "96026ea966b421af73833a78590e8ef75ea154a28cf64b78eb7ad901ee1197c0";
    private const int MaximumBytes = 16_384;
    private static readonly string[] Names = ["Id", "Domain", "Current", "Candidate", "Baseline", "Position", "Expected"];
    internal static IReadOnlyList<SnapshotEvidenceReplayItem> Load()
    {
        using var stream = typeof(SnapshotEvidenceReplayCorpus).Assembly.GetManifestResourceStream(ResourceName) ?? throw Invalid();
        using var memory = new MemoryStream(); var buffer = new byte[4096];
        while (true) { var read = stream.Read(buffer); if (read == 0) break; if (memory.Length + read > MaximumBytes) throw Invalid(); memory.Write(buffer, 0, read); }
        var bytes = memory.ToArray();
        if (!string.Equals(Convert.ToHexStringLower(SHA256.HashData(bytes)), ExpectedSha256, StringComparison.Ordinal)) throw Invalid();
        return Parse(bytes);
    }
    internal static IReadOnlyList<SnapshotEvidenceReplayItem> ParseForTest(byte[] bytes)
    {
        if (bytes.Length > MaximumBytes) throw Invalid();
        return Parse(bytes);
    }
    private static IReadOnlyList<SnapshotEvidenceReplayItem> Parse(byte[] bytes)
    {
        try
        {
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 8, CommentHandling = JsonCommentHandling.Disallow, AllowTrailingCommas = false });
            if (document.RootElement.ValueKind != JsonValueKind.Array) throw Invalid();
            var items = new List<SnapshotEvidenceReplayItem>(); var ids = new HashSet<string>(StringComparer.Ordinal);
            foreach (var element in document.RootElement.EnumerateArray())
            {
                if (items.Count == 64 || element.ValueKind != JsonValueKind.Object) throw Invalid();
                var map = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
                foreach (var property in element.EnumerateObject()) if (!Names.Contains(property.Name, StringComparer.Ordinal) || !map.TryAdd(property.Name, property.Value)) throw Invalid();
                if (map.Count != Names.Length) throw Invalid();
                var id = Text(map["Id"]); var domain = Text(map["Domain"]); var expected = Text(map["Expected"]);
                var current = Number(map["Current"]); var candidate = Number(map["Candidate"]); var baseline = Number(map["Baseline"]); var position = Number(map["Position"]);
                if (!CanonicalId(id) || !ids.Add(id)
                    || current <= 0 || candidate <= 0 || baseline <= 0 || position <= 0 || !Tuple(domain, expected)) throw Invalid();
                if (domain == "evidence" && (baseline != 1 || position != 1)) throw Invalid();
                items.Add(new(id, domain, current, candidate, baseline, position, expected));
            }
            if (items.Count < 8) throw Invalid(); return items;
        }
        catch (JsonException exception) { throw new InvalidDataException("Replay corpus JSON is invalid.", exception); }
    }
    private static bool Tuple(string domain, string expected) => domain switch
    {
        "snapshot" => expected is "None" or "StaleEpoch" or "StreamRollback",
        "evidence" => expected is "Allowed" or "StaleGeneration" or "FutureGeneration",
        _ => false,
    };
    private static bool CanonicalId(string id)
    {
        if (id.Length is < 1 or > 64 || id[0] == '-' || id[^1] == '-') return false;
        var previousHyphen = false;
        foreach (var character in id)
        {
            if (character == '-') { if (previousHyphen) return false; previousHyphen = true; continue; }
            if (character is not (>= 'a' and <= 'z') and not (>= '0' and <= '9')) return false;
            previousHyphen = false;
        }
        return true;
    }
    private static string Text(JsonElement value) => value.ValueKind == JsonValueKind.String && value.GetString() is { } text ? text : throw Invalid();
    private static long Number(JsonElement value) => value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out var number) ? number : throw Invalid();
    private static InvalidDataException Invalid() => new("Snapshot/evidence replay corpus is invalid.");
}

