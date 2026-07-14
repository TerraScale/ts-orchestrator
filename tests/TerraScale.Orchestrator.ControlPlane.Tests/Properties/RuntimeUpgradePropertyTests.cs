using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using TerraScale.Orchestrator.ControlPlane.Runtime;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties;

public sealed class RuntimeUpgradePropertyTests
{
    private const int Cases = 1000;
    private static readonly string[] Progression = ["VerifyUpdateArtifactIntent", "StageInactiveSlotIntent", "ArmRollbackIntent",
        "SwitchUpdateSlotIntent", "CheckRuntimeHealthIntent", "VerifyRegionalCompatibilityIntent", "CommitUpdateSlotIntent",
        "RetainOldUpdateSlotIntent", "CompleteSelfUpdateIntent", "ObserveUpdateIntent", "CompleteSelfUpdateIntent"];

    [Test]
    public async Task Every_AB_checkpoint_follows_independent_activation_oracle_for_1000_seeded_cases()
    {
        var operations = new HashSet<string>(StringComparer.Ordinal); var executed = 0;
        for (var seed = 1UL; seed <= Cases; seed++)
        {
            var variant = (int)(seed % 11); var request = RuntimeUpgradeData.Update(seed, variant); operations.Add(request.OperationId.Value);
            var decision = RuntimeDecisionEngine.EvaluateSelfUpdate(request);
            Require(decision.Authorized && decision.Intent.GetType().Name == Progression[variant], seed, "checkpoint");
            foreach (var code in new[] { RuntimeDecisionCode.SlotDistinct, RuntimeDecisionCode.ArtifactExact, RuntimeDecisionCode.ForwardAvailable,
                         RuntimeDecisionCode.RollbackAvailable, RuntimeDecisionCode.CompatibilityExact, RuntimeDecisionCode.RollbackPossible })
                Require(decision.Trace.Single(r => r.Code == code).Outcome == RuntimeDecisionOutcome.Passed, seed, $"activation code {code}");
            Require(Serialize(decision) == Serialize(RuntimeDecisionEngine.EvaluateSelfUpdate(RuntimeUpgradeData.Update(seed, variant))), seed, "replay");
            executed++;
        }
        await Assert.That(executed).IsEqualTo(1000); await Assert.That(operations.Count).IsEqualTo(1000);
    }

    [Test]
    public async Task Artifact_rollback_compatibility_epoch_and_operation_fences_have_exact_codes_for_1000_cases()
    {
        var codes = new[] { RuntimeDecisionCode.ArtifactExact, RuntimeDecisionCode.RollbackAvailable, RuntimeDecisionCode.CompatibilityExact,
            RuntimeDecisionCode.EpochCurrent, RuntimeDecisionCode.OperationExact };
        var executed = 0; for (var seed = 1UL; seed <= Cases; seed++)
        {
            var variant = 11 + (int)(seed % 5); var decision = RuntimeDecisionEngine.EvaluateSelfUpdate(RuntimeUpgradeData.Update(seed, variant));
            var reason = decision.Trace.Single(r => r.Code == codes[variant - 11]);
            var expectedOutcome = variant == 12 ? RuntimeDecisionOutcome.Held : RuntimeDecisionOutcome.Rejected;
            Require(!decision.Authorized && decision.Intent is HoldRuntimeIntent && reason.Outcome == expectedOutcome, seed, "fence");
            executed++;
        }
        await Assert.That(executed).IsEqualTo(1000);
    }

    [Test]
    public async Task Lost_response_and_failed_health_choose_observe_or_rollback_for_1000_cases()
    {
        var executed = 0; for (var seed = 1UL; seed <= Cases; seed++)
        {
            var variant = 16 + (int)(seed % 3); var decision = RuntimeDecisionEngine.EvaluateSelfUpdate(RuntimeUpgradeData.Update(seed, variant));
            var expected = variant switch { 16 => "ObserveUpdateIntent", 17 => "RollbackUpdateIntent", _ => "HoldRuntimeIntent" };
            Require(decision.Authorized == (variant != 18) && decision.Intent.GetType().Name == expected, seed, "recovery");
            var code = variant switch { 16 => RuntimeDecisionCode.CallSafe, 17 => RuntimeDecisionCode.ReadinessComplete, _ => RuntimeDecisionCode.RollbackPossible };
            Require(decision.Trace.Single(r => r.Code == code).Outcome == (variant == 16 ? RuntimeDecisionOutcome.Held : RuntimeDecisionOutcome.Rejected), seed, "recovery code");
            if (variant == 17) Require(decision.Trace.Single(r => r.Code == RuntimeDecisionCode.RollbackAvailable).Outcome == RuntimeDecisionOutcome.Passed, seed, "rollback artifact");
            executed++;
        }
        await Assert.That(executed).IsEqualTo(1000);
    }

    [Test]
    public async Task Health_permutation_and_culture_never_change_activation_for_1000_cases()
    {
        var cultures = new[] { "en-US", "tr-TR", "ar-SA", "ja-JP" }; var executed = 0;
        for (var seed = 1UL; seed <= Cases; seed++)
        {
            var previous = CultureInfo.CurrentCulture;
            try
            {
                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(cultures[seed % 4]);
                var forward = RuntimeDecisionEngine.EvaluateSelfUpdate(RuntimeUpgradeData.Update(seed, 6, reverseHealth: false));
                var reverse = RuntimeDecisionEngine.EvaluateSelfUpdate(RuntimeUpgradeData.Update(seed, 6, reverseHealth: true));
                Require(Serialize(forward) == Serialize(reverse), seed, "permutation"); executed++;
            }
            finally { CultureInfo.CurrentCulture = previous; }
        }
        await Assert.That(executed).IsEqualTo(1000);
    }

    [Test]
    public async Task Activation_is_construction_closed_and_strict_pinned_corpus_reconstructs_seeded_inputs()
    {
        await Assert.That(typeof(RuntimeDecision).GetConstructors(BindingFlags.Public | BindingFlags.Instance).Length).IsEqualTo(0);
        await Assert.That(typeof(RuntimeDecision).GetMethods(BindingFlags.Public | BindingFlags.Static)
            .Count(m => m.ReturnType == typeof(RuntimeDecision) && !m.IsSpecialName)).IsEqualTo(0);
        await Assert.That(typeof(RuntimeIntent).Assembly.GetTypes().Where(t => typeof(RuntimeIntent).IsAssignableFrom(t))
            .SelectMany(t => t.GetConstructors(BindingFlags.Public | BindingFlags.Instance)).Count()).IsEqualTo(0);

        var entries = RuntimeUpgradeCorpus.Load();
        foreach (var entry in entries)
        {
            var request = RuntimeUpgradeData.Update(entry.Seed, entry.Variant);
            var decision = RuntimeDecisionEngine.EvaluateSelfUpdate(request);
            Require(decision.Intent.GetType().Name == entry.Expected, entry.Seed, entry.Id);
            Require(Fingerprint(request) == ExpectedFingerprint(entry.Seed), entry.Seed, "corpus fingerprint");
            Require(decision.Intent.OperationId == request.OperationId, entry.Seed, "intent request identity");
            Require(Fingerprint(RuntimeUpgradeData.Update(entry.Seed + 1, entry.Variant)) != Fingerprint(request), entry.Seed, "mutated seed sensitivity");
        }
        await Assert.That(entries.Count).IsEqualTo(19);
    }

    [Test]
    public async Task Replay_reader_and_parser_reject_bound_shape_seed_and_closed_vocabulary_violations()
    {
        await Assert.That(RuntimeUpgradeCorpus.ReadBounded(new MemoryStream(new byte[8192])).Length).IsEqualTo(8192);
        await Assert.That(Fails(() => RuntimeUpgradeCorpus.ReadBounded(new MemoryStream(new byte[8193])))).IsTrue();
        await Assert.That(RuntimeUpgradeCorpus.Parse(System.Text.Encoding.UTF8.GetBytes(
            Entry("maximum-seed", RuntimeUpgradeData.MaximumReplaySeed.ToString(CultureInfo.InvariantCulture), 0, "VerifyUpdateArtifactIntent")), false).Count).IsEqualTo(1);
        await Assert.That(RuntimeUpgradeCorpus.Parse(System.Text.Encoding.UTF8.GetBytes(
            Entry(new string('a', RuntimeUpgradeCorpus.MaximumIdLength), "1", 0, "VerifyUpdateArtifactIntent")), false).Count).IsEqualTo(1);
        var invalid = new[] { "{}", "{/*x*/\"schema\":\"terrascale.runtime-upgrade-replay.v1\",\"entries\":[]}",
            "{\"schema\":\"terrascale.runtime-upgrade-replay.v1\",\"entries\":[],}",
            "{\"schema\":\"terrascale.runtime-upgrade-replay.v1\",\"entries\":[]} trailing",
            Entry("x", "0", 0, "VerifyUpdateArtifactIntent"), Entry("x", "-1", 0, "VerifyUpdateArtifactIntent"),
            Entry("x", "18446744073709551616", 0, "VerifyUpdateArtifactIntent"),
            Entry("x", (RuntimeUpgradeData.MaximumReplaySeed + 1).ToString(CultureInfo.InvariantCulture), 0, "VerifyUpdateArtifactIntent"),
            Entry(new string('a', RuntimeUpgradeCorpus.MaximumIdLength + 1), "1", 0, "VerifyUpdateArtifactIntent"),
            Entry("bad id", "1", 0, "VerifyUpdateArtifactIntent"), Entry("bad\nid", "1", 0, "VerifyUpdateArtifactIntent"),
            Entry("x", "\"1\"", 0, "VerifyUpdateArtifactIntent"), Entry("x", "1", 99, "VerifyUpdateArtifactIntent"),
            Entry("x", "1", 0, "HoldRuntimeIntent"),
            "{\"schema\":\"terrascale.runtime-upgrade-replay.v1\",\"entries\":[{\"id\":\"x\",\"seed\":1,\"variant\":0,\"expected\":\"VerifyUpdateArtifactIntent\"},{\"id\":\"x\",\"seed\":2,\"variant\":0,\"expected\":\"VerifyUpdateArtifactIntent\"}]}",
            "{\"schema\":\"terrascale.runtime-upgrade-replay.v1\",\"entries\":[{\"id\":\"x\",\"seed\":1,\"variant\":0,\"expected\":\"VerifyUpdateArtifactIntent\"},{\"id\":\"y\",\"seed\":1,\"variant\":0,\"expected\":\"VerifyUpdateArtifactIntent\"}]}",
            "{\"schema\":\"terrascale.runtime-upgrade-replay.v1\",\"entries\":[{\"id\":\"x\",\"id\":\"y\",\"seed\":1,\"variant\":0,\"expected\":\"VerifyUpdateArtifactIntent\"}]}",
            "{\"schema\":\"terrascale.runtime-upgrade-replay.v1\",\"entries\":[[[[[1]]]]]}" };
        foreach (var json in invalid) await Assert.That(Fails(() => RuntimeUpgradeCorpus.Parse(System.Text.Encoding.UTF8.GetBytes(json), false))).IsTrue();
    }

    private static string Entry(string id, string seed, int variant, string expected) => $"{{\"schema\":\"terrascale.runtime-upgrade-replay.v1\",\"entries\":[{{\"id\":\"{id}\",\"seed\":{seed},\"variant\":{variant},\"expected\":\"{expected}\"}}]}}";
    private static string Serialize(RuntimeDecision d) => $"{d.Authorized}|{d.Intent.GetType().Name}|" + string.Join(';', d.Trace.Select(r => $"{r.Code}:{r.Outcome}:{r.Observed}:{r.Required}"));
    private static string Fingerprint(SelfUpdateRequest r) => $"{r.OperationId.Value}|{r.NodeId.Value}|{r.AllocationId.Value}|{r.CurrentGeneration.Value}|{r.TargetGeneration.Value}|{r.ForwardArtifact.ReleaseId.Value}|{r.ForwardArtifact.ArtifactId.Value}|{r.ForwardArtifact.SignatureId.Value}";
    private static string ExpectedFingerprint(ulong seed) => $"operation-{seed}|node-{seed}|allocation-{seed}|{1000 + seed}|{1001 + seed}|release-{seed}-{1001 + seed}|artifact-{seed}-{1001 + seed}|signature-{seed}-{1001 + seed}";
    private static void Require(bool condition, ulong seed, string property) { if (!condition) throw new InvalidOperationException($"{property} failed at seed {seed}."); }
    private static bool Fails(Action action) { try { action(); return false; } catch (Exception) { return true; } }
}

internal static class RuntimeUpgradeData
{
    internal const ulong MaximumReplaySeed = 1_000_000;

    internal static SelfUpdateRequest Update(ulong seed, int variant, bool reverseHealth = false, IEnumerable<RuntimeHealthEvidence>? suppliedHealth = null)
    {
        if (seed is 0 or > MaximumReplaySeed) throw new ArgumentOutOfRangeException(nameof(seed));
        var operation = new RuntimeOperationId($"operation-{seed}"); var node = new RuntimeNodeId($"node-{seed}"); var allocation = new RuntimeAllocationId($"allocation-{seed}");
        var current = new RuntimeGeneration(1000 + seed); var target = new RuntimeGeneration(1001 + seed);
        var phase = variant switch { 0 => UpdatePhase.UpgradePlanned, 1 => UpdatePhase.ArtifactVerified, 2 => UpdatePhase.InactiveSlotStaged,
            3 or 16 => UpdatePhase.RollbackTimerArmed, 4 => UpdatePhase.ProcessRestarted, 5 or 17 => UpdatePhase.LocalHealthVerified,
            6 => UpdatePhase.RegionalCompatibilityVerified, 7 => UpdatePhase.SlotCommitted, 8 => UpdatePhase.OldSlotRetainedUntilSoak,
            9 => UpdatePhase.RollingBack, 10 => UpdatePhase.RolledBack, 18 => UpdatePhase.RollbackFailed, _ => UpdatePhase.UpgradePlanned };
        var active = phase is UpdatePhase.UpgradePlanned or UpdatePhase.ArtifactVerified or UpdatePhase.InactiveSlotStaged or UpdatePhase.RollbackTimerArmed or UpdatePhase.RolledBack ? UpdateSlot.A : UpdateSlot.B;
        var inactive = active == UpdateSlot.A ? UpdateSlot.B : UpdateSlot.A;
        var forward = Artifact(seed, target, 'a', variant == 11 ? ArtifactVerificationStatus.Failed : ArtifactVerificationStatus.Verified);
        var rollback = Artifact(seed, current, 'b', ArtifactVerificationStatus.Verified, variant == 12 ? ArtifactAvailability.Missing : ArtifactAvailability.Available);
        var expectedForward = Subject(Artifact(seed, target, 'a')); var expectedRollback = Subject(Artifact(seed, current, 'b'));
        var compatibility = new UpdateCompatibilityEvidence(operation, current, target, new(1), new(1), CompatibilityStatus.Compatible,
            variant == 13 ? CompatibilityStatus.Incompatible : CompatibilityStatus.Compatible);
        var observedOperation = variant == 15 ? new RuntimeOperationId($"wrong-{seed}") : operation;
        var observation = new SelfUpdateObservation(observedOperation, node, new(variant == 14 ? 4UL : 5UL), target, phase, active, inactive,
            variant == 16 ? ExecutorCallStatus.ResponseLost : ExecutorCallStatus.NotCalled);
        var health = suppliedHealth ?? Health(operation, allocation, phase == UpdatePhase.RolledBack ? current : target, variant == 17 ? HealthStatus.Failed : HealthStatus.Ready,
            phase is UpdatePhase.LocalHealthVerified or UpdatePhase.RegionalCompatibilityVerified or UpdatePhase.SlotCommitted or UpdatePhase.OldSlotRetainedUntilSoak or UpdatePhase.RolledBack);
        IEnumerable<RuntimeHealthEvidence> finalHealth = health;
        if (reverseHealth) { var healthArray = health.ToArray(); Array.Reverse(healthArray); finalHealth = healthArray; }
        return new(operation, node, allocation, new(5), new(5), RuntimeArchitecture.LinuxArm64, current, target, new(1), new(1), new(30), new(600),
            UpdateCompatibilityWindow.NAndNMinusOne, UpdateRollbackPolicy.LocalKnownGoodOnHealthOrCompatibilityFailure, active, inactive,
            expectedForward, expectedRollback, forward, rollback, compatibility, observation, finalHealth);
    }

    private static UpdateArtifactEvidence Artifact(ulong seed, RuntimeGeneration generation, char digest, ArtifactVerificationStatus verification = ArtifactVerificationStatus.Verified,
        ArtifactAvailability availability = ArtifactAvailability.Available) => new(new($"release-{seed}-{generation.Value}"), new($"artifact-{seed}-{generation.Value}"),
        new(new string(digest, 64)), new($"signature-{seed}-{generation.Value}"), new("sigstore-v1"), RuntimeArchitecture.LinuxArm64, generation, availability, verification);
    private static UpdateArtifactSubject Subject(UpdateArtifactEvidence x) => new(x.ReleaseId, x.ArtifactId, x.Digest, x.SignatureId, x.SigningProfileId, x.Architecture, x.Generation);
    private static RuntimeHealthEvidence[] Health(RuntimeOperationId operation, RuntimeAllocationId allocation, RuntimeGeneration generation, HealthStatus status, bool required) => required ?
        [new(new("health-live"), operation, allocation, generation, HealthDimension.Liveness, status), new(new("health-local"), operation, allocation, generation, HealthDimension.LocalReadiness, status),
         new(new("health-dependency"), operation, allocation, generation, HealthDimension.DependencyReadiness, status)] : [];
}

internal sealed record RuntimeUpgradeEntry(string Id, ulong Seed, int Variant, string Expected);
internal static class RuntimeUpgradeCorpus
{
    internal const int MaximumIdLength = 64;
    private const string Resource = "TerraScale.Orchestrator.ControlPlane.Tests.Properties.RuntimeUpgradeReplayCorpus.v1.json";
    private const string Digest = "d869460ff66604d33babe48d443351ce3de201ab046789e55afe985b27279376";
    internal static IReadOnlyList<RuntimeUpgradeEntry> Load() { using var stream = System.Reflection.Assembly.GetExecutingAssembly().GetManifestResourceStream(Resource) ?? throw new InvalidDataException(); return Parse(ReadBounded(stream), true); }
    internal static byte[] ReadBounded(Stream stream) { using var output = new MemoryStream(); var buffer = new byte[1024]; var total = 0; while (true) { var read = stream.Read(buffer); if (read == 0) break; total = checked(total + read); if (total > 8192) throw new InvalidDataException(); output.Write(buffer, 0, read); } return output.ToArray(); }
    internal static IReadOnlyList<RuntimeUpgradeEntry> Parse(byte[] bytes, bool enforceDigest)
    {
        if (bytes.Length > 8192 || enforceDigest && Convert.ToHexStringLower(SHA256.HashData(bytes)) != Digest) throw new InvalidDataException();
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow, MaxDepth = 4 });
        var root = document.RootElement; Exact(root, "schema", "entries"); if (root.GetProperty("schema").GetString() != "terrascale.runtime-upgrade-replay.v1") throw new InvalidDataException();
        var result = new List<RuntimeUpgradeEntry>(); foreach (var item in root.GetProperty("entries").EnumerateArray()) { if (result.Count == 64) throw new InvalidDataException(); Exact(item, "id", "seed", "variant", "expected"); result.Add(new(item.GetProperty("id").GetString()!, item.GetProperty("seed").GetUInt64(), item.GetProperty("variant").GetInt32(), item.GetProperty("expected").GetString()!)); }
        if (result.Count == 0 || result.Select(x => x.Id).Distinct(StringComparer.Ordinal).Count() != result.Count || result.Select(x => x.Seed).Distinct().Count() != result.Count || result.Any(x => x.Seed is 0 or > RuntimeUpgradeData.MaximumReplaySeed || !ValidId(x.Id) || !Vocabulary(x))) throw new InvalidDataException();
        return result.AsReadOnly();
    }
    private static bool Vocabulary(RuntimeUpgradeEntry x) => x.Variant is >= 0 and <= 18 && x.Expected == (x.Variant switch { >= 0 and <= 10 => RuntimeUpgradePropertyTestsExpected(x.Variant), 11 or 12 or 13 or 14 or 15 or 18 => "HoldRuntimeIntent", 16 => "ObserveUpdateIntent", 17 => "RollbackUpdateIntent", _ => "" });
    private static string RuntimeUpgradePropertyTestsExpected(int v) => new[] { "VerifyUpdateArtifactIntent", "StageInactiveSlotIntent", "ArmRollbackIntent", "SwitchUpdateSlotIntent", "CheckRuntimeHealthIntent", "VerifyRegionalCompatibilityIntent", "CommitUpdateSlotIntent", "RetainOldUpdateSlotIntent", "CompleteSelfUpdateIntent", "ObserveUpdateIntent", "CompleteSelfUpdateIntent" }[v];
    private static bool ValidId(string? value)
    {
        if (value is null || value.Length is < 1 or > MaximumIdLength || value[0] == '-' || value[^1] == '-') return false;
        var previousHyphen = false;
        foreach (var character in value) { var hyphen = character == '-'; if (!(character is >= 'a' and <= 'z' or >= '0' and <= '9') && !hyphen || hyphen && previousHyphen) return false; previousHyphen = hyphen; }
        return true;
    }
    private static void Exact(JsonElement element, params string[] names) { var actual = element.EnumerateObject().Select(p => p.Name).Order(StringComparer.Ordinal); if (!actual.SequenceEqual(names.Order(StringComparer.Ordinal), StringComparer.Ordinal)) throw new InvalidDataException(); }
}
