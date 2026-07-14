using System.Globalization;
using TerraScale.Orchestrator.ControlPlane.Delivery;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class DeliveryPolicyCompletenessPropertyTests
{
    private const int Cases = 1_000;
    private const int Undefined = int.MaxValue;

    [Test]
    public async Task SourceAndPromotionOutputsRetainEveryAcceptedProofFieldAcrossCultures()
    {
        var english = UnderCulture("en-US", () => RunSourceAndPromotion(0xD311_1001));
        foreach (var culture in new[] { "tr-TR", "ar-SA", "ja-JP" })
            await Assert.That(UnderCulture(culture, () => RunSourceAndPromotion(0xD311_1001))).IsEqualTo(english);
        await Assert.That(english.Cases).IsEqualTo(Cases);
        await Assert.That(english.Outcomes).IsEqualTo(6);
    }

    [Test]
    public async Task RolloutBindsArchitectureAndEveryIntentFieldWithStableDenialPrecedence()
    {
        var english = UnderCulture("en-US", () => RunRollout(0xD311_1002));
        foreach (var culture in new[] { "tr-TR", "ar-SA", "ja-JP" })
            await Assert.That(UnderCulture(culture, () => RunRollout(0xD311_1002))).IsEqualTo(english);
        await Assert.That(english.Cases).IsEqualTo(Cases);
        await Assert.That(english.Outcomes).IsEqualTo(12);
    }

    [Test]
    public async Task EveryObservedDeliveryEnumRejectsUndefinedValuesBeforeMutation()
    {
        var source = Source(1, 1);
        var sourceDecision = DeliveryEngine.DecideSource(new(source, null,
            Evidence(source, (SourceState)Undefined), 96));
        await AssertHeld(sourceDecision, DeliveryErrorCode.EvidenceInvalidated);

        var job = Job();
        await AssertHeld(DeliveryEngine.DecideJob(Job(kind: (JobKind)Undefined), [Runner()], 96), DeliveryErrorCode.InvalidInput);
        await AssertHeld(DeliveryEngine.DecideJob(job, [Runner(zone: (TrustZone)Undefined)], 96), DeliveryErrorCode.InvalidInput);
        await AssertHeld(DeliveryEngine.DecideJob(Job(capability: (RunnerCapability)Undefined), [Runner()], 96), DeliveryErrorCode.InvalidInput);

        var subject = Subject(1, DeliveryArchitecture.LinuxArm64);
        await AssertHeld(DeliveryEngine.DecidePromotion(new(new("release-1"), 1,
            subject with { Architecture = (DeliveryArchitecture)Undefined }, Qualification(1, 1, subject), 96)),
            DeliveryErrorCode.InvalidInput);

        foreach (var release in new[]
        {
            Release(1, 1, strategy: (RolloutStrategy)Undefined),
            Release(1, 1, policy: (RollbackPolicy)Undefined),
            Release(1, 1, architecture: (DeliveryArchitecture)Undefined),
            Release(1, 1, rollbackArchitecture: (DeliveryArchitecture)Undefined),
        })
            await AssertHeld(DeliveryEngine.DecideRollout(Rollout(release)), DeliveryErrorCode.InvalidInput);

        var valid = Release(1, 1);
        await AssertHeld(DeliveryEngine.DecideRollout(Rollout(valid,
            stage: Stage(valid, (StageHealth)Undefined))), DeliveryErrorCode.ArtifactMismatch);
    }

    private static Summary RunSourceAndPromotion(ulong seed)
    {
        var random = new Generator(seed); var outcomes = new HashSet<string>(); ulong digest = 0;
        for (var index = 0; index < Cases; index++)
        {
            var generation = random.Next(800_000) + 1L;
            var source = Source(index, generation);
            var mode = index % 6;
            DeliveryDecision decision;
            string expected;
            switch (mode)
            {
                case 0:
                    decision = DeliveryEngine.DecideSource(new(source, null, Evidence(source), 96));
                    expected = PlanSignature(source);
                    break;
                case 1:
                    decision = DeliveryEngine.DecideSource(new(source, null, Evidence(source, SourceState.Fetched), 96));
                    expected = $"Verify|{source.Source.Value}|{source.Commit.Value}|{source.Tree.Value}|{source.Manifest.Value}|{source.DesiredDigest.Value}|{source.Signature.Value}";
                    break;
                case 2:
                    decision = DeliveryEngine.DecideSource(new(source, source, null, 96));
                    expected = "Idempotent|Plan";
                    break;
                default:
                    var architecture = index % 2 == 0 ? DeliveryArchitecture.LinuxArm64 : DeliveryArchitecture.LinuxX64;
                    var subject = Subject(index, architecture);
                    var qualification = Qualification(index, generation, subject);
                    if (mode == 4) qualification = qualification with { Tests = new($"tests-other-{index}") };
                    if (mode == 5) qualification = qualification with { Compatibility = qualification.Compatibility with { CurrentToPreviousCompatible = false } };
                    decision = DeliveryEngine.DecidePromotion(new(new($"release-{index}"), generation, subject, qualification, 96));
                    expected = mode switch
                    {
                        3 => PromotionSignature(index, generation, subject, qualification),
                        4 => PromotionSignature(index, generation, subject, qualification),
                        _ => "CompatibilityDenied",
                    };
                    break;
            }
            var actual = DecisionSignature(decision);
            Require(actual == expected, "source-promotion", index, expected, actual);
            outcomes.Add(mode == 4 ? "PromoteChangedTests" : actual.Split('|')[0]);
            digest = Mix(digest, actual, generation);
        }
        return new(Cases, outcomes.Count, digest);
    }

    private static Summary RunRollout(ulong seed)
    {
        var random = new Generator(seed); var outcomes = new HashSet<string>(); ulong digest = 0;
        for (var index = 0; index < Cases; index++)
        {
            var generation = random.Next(800_000) + 1L;
            var architecture = index % 2 == 0 ? DeliveryArchitecture.LinuxArm64 : DeliveryArchitecture.LinuxX64;
            var release = Release(index, generation, architecture);
            var availability = Availability(release);
            var mode = index % 23;
            RolloutRequest request;
            string expected;
            switch (mode)
            {
                case 0: request = Rollout(release, availability: availability.Reverse()); expected = StageSignature(release, release.OrderedCells[0]); break;
                case 1: request = Rollout(release, availability: Replace(availability, 0, availability[0] with { ForwardArchitecture = Other(architecture) })); expected = "EvidenceInvalidated"; break;
                case 2: request = Rollout(release, availability: Replace(availability, 0, availability[0] with { RollbackArchitecture = Other(architecture) })); expected = "EvidenceInvalidated"; break;
                case 3: request = Rollout(Release(index, generation, architecture, Other(architecture))); expected = "InvalidInput"; break;
                case 4: request = Rollout(release, stage: Stage(release, StageHealth.Healthy) with { Architecture = Other(architecture) }); expected = "ArtifactMismatch"; break;
                case 5: request = Rollout(release, completed: [Completion(release, release.OrderedCells[0]) with { Architecture = Other(architecture) }]); expected = "StageOutOfOrder"; break;
                case 6: request = Rollout(release, stage: Stage(release, StageHealth.Healthy)); expected = AdvanceSignature(release, release.OrderedCells[0], release.OrderedCells[1]); break;
                case 7: request = Rollout(release, stage: Stage(release, StageHealth.Failed)); expected = RollbackSignature(release, release.OrderedCells[0]); break;
                case 8: request = Rollout(release, stage: Stage(release, StageHealth.Healthy) with { AvailabilityAuthorized = false }); expected = "AvailabilityDenied"; break;
                case 9: request = Rollout(Release(index, generation, architecture, policy: RollbackPolicy.HoldForApproval), stage: Stage(release, StageHealth.Failed)); expected = "HealthDenied"; break;
                case 10: request = Rollout(release, completed: release.OrderedCells.Select(cell => Completion(release, cell))); expected = "Idempotent|Advance"; break;
                case 11: request = Rollout(release, availability: availability.Take(2)); expected = "MissingEvidence"; break;
                case 12: request = Rollout(release, stage: Stage(release, StageHealth.Healthy) with { Signature = new($"wrong-{index}") }); expected = "ArtifactMismatch"; break;
                case 13: request = Rollout(release, availability: Replace(availability, 0, availability[0] with { ForwardAvailable = false })); expected = "ArtifactMismatch"; break;
                case 14: request = Rollout(release, availability: Replace(availability, 0, availability[0] with { RollbackAvailable = false })); expected = "RollbackUnavailable"; break;
                case 15: request = Rollout(release, stage: Stage(release, StageHealth.Pending)); expected = "HealthDenied"; break;
                case 16: request = Rollout(release, availability: Replace(availability, 0, availability[0] with { ForwardSigningIdentity = new($"wrong-{index}") })); expected = "EvidenceInvalidated"; break;
                case 17: request = Rollout(release, stage: Stage(release, StageHealth.Healthy) with { SigningIdentity = new($"wrong-{index}") }); expected = "ArtifactMismatch"; break;
                case 18: request = Rollout(Release(index, generation, (DeliveryArchitecture)Undefined), availability: availability.Take(2)); expected = "InvalidInput"; break;
                case 19: request = Rollout(release, availability: Replace(availability, 0, availability[0] with { ForwardArchitecture = Other(architecture), ForwardAvailable = false })); expected = "EvidenceInvalidated"; break;
                case 20: request = Rollout(release, stage: Stage(release, StageHealth.Healthy) with { SigningIdentity = new($"wrong-{index}"), AvailabilityAuthorized = false }); expected = "ArtifactMismatch"; break;
                case 21: request = Rollout(release, availability: Replace(availability, 0, availability[0] with { RollbackSigningIdentity = new($"wrong-{index}") })); expected = "EvidenceInvalidated"; break;
                default: request = Rollout(release, completed: [Completion(release, release.OrderedCells[0]) with { SigningIdentity = new($"wrong-{index}") }]); expected = "StageOutOfOrder"; break;
            }
            var actual = DecisionSignature(DeliveryEngine.DecideRollout(request));
            Require(actual == expected, "rollout", index, expected, actual);
            outcomes.Add(actual.Split('|')[0]); digest = Mix(digest, actual, generation);
        }
        return new(Cases, outcomes.Count, digest);
    }

    private static string DecisionSignature(DeliveryDecision decision)
    {
        if (decision.Errors.Count > 0)
        {
            var error = decision.Errors.Single(); var hold = (HoldDeliveryIntent)decision.Intents.Single();
            Require(error.Code == hold.Reason && error.Requirement == DeliveryRequirementCode.Inv005 &&
                error.Job == hold.Job && error.Release == hold.Release && error.Cell == hold.Cell,
                "hold-output", 0, error.Code.ToString(), hold.Reason.ToString());
            var trace = decision.Trace.Single();
            Require(trace.Sequence == 1 && trace.Code == DeliveryTraceCode.Held && trace.Action == DeliveryAction.Hold,
                "hold-trace", 0, "1/Held/Hold", $"{trace.Sequence}/{trace.Code}/{trace.Action}");
            return error.Code.ToString();
        }
        var onlyTrace = decision.Trace.Single();
        Require(onlyTrace.Sequence == 1, "trace-sequence", 0, "1", onlyTrace.Sequence.ToString(CultureInfo.InvariantCulture));
        if (decision.Intents.Count == 0) return $"{onlyTrace.Code}|{onlyTrace.Action}";
        var intent = decision.Intents.Single();
        Require(onlyTrace.Action == intent.Action, "trace-action", 0, intent.Action.ToString(), onlyTrace.Action.ToString());
        var expectedTrace = intent switch
        {
            PlanApplyIntent => DeliveryTraceCode.PlanReady,
            VerifySourceIntent => DeliveryTraceCode.VerificationRequired,
            PromoteArtifactIntent => DeliveryTraceCode.PromotionReady,
            StageReleaseIntent => DeliveryTraceCode.StageReady,
            AdvanceReleaseIntent => DeliveryTraceCode.AdvanceReady,
            RollbackReleaseIntent => DeliveryTraceCode.RollbackRequired,
            _ => throw new InvalidOperationException($"Unexpected delivery intent {intent.GetType().Name}."),
        };
        Require(onlyTrace.Code == expectedTrace, "trace-code", 0, expectedTrace.ToString(), onlyTrace.Code.ToString());
        return intent switch
        {
            PlanApplyIntent value => $"Plan|{value.Source.Value}|{value.Commit.Value}|{value.Tree.Value}|{value.Manifest.Value}|{value.Generation.ToString(CultureInfo.InvariantCulture)}|{value.Digest.Value}|{value.Signature.Value}|{value.SchemaAttestation.Value}|{value.DependencyAttestation.Value}|{string.Join(',', value.Dependencies.Select(dependency => $"{dependency.Manifest.Value}:{dependency.Generation.ToString(CultureInfo.InvariantCulture)}:{dependency.Digest.Value}"))}",
            VerifySourceIntent value => $"Verify|{value.Source.Value}|{value.Commit.Value}|{value.Tree.Value}|{value.Manifest.Value}|{value.Digest.Value}|{value.Signature.Value}",
            PromoteArtifactIntent value => $"Promote|{value.Release.Value}|{value.Generation.ToString(CultureInfo.InvariantCulture)}|{SubjectSignature(value.Subject)}|{value.Tests.Value}|{value.SigningIdentity.Value}|{value.Signature.Value}|{value.Approval.Value}|{value.Evidence.Value}|{CompatibilitySignature(value.Compatibility)}",
            StageReleaseIntent value => $"Stage|{value.Release.Value}|{value.Operation.Value}|{value.Cell.Value}|{value.Generation.ToString(CultureInfo.InvariantCulture)}|{value.Artifact.Value}|{value.Digest.Value}|{value.SigningIdentity.Value}|{value.Signature.Value}|{value.Architecture}|{value.RollbackArtifact.Value}|{value.RollbackDigest.Value}|{value.RollbackSigningIdentity.Value}|{value.RollbackSignature.Value}|{value.RollbackArchitecture}",
            AdvanceReleaseIntent value => $"Advance|{value.Release.Value}|{value.Operation.Value}|{value.CompletedCell.Value}|{value.NextCell?.Value ?? "-"}|{value.Generation.ToString(CultureInfo.InvariantCulture)}|{value.Artifact.Value}|{value.Digest.Value}|{value.SigningIdentity.Value}|{value.Signature.Value}|{value.Architecture}|{value.HealthProof.Value}",
            RollbackReleaseIntent value => $"Rollback|{value.Release.Value}|{value.Operation.Value}|{value.Cell.Value}|{value.Generation.ToString(CultureInfo.InvariantCulture)}|{value.FailedArtifact.Value}|{value.FailedDigest.Value}|{value.FailedSigningIdentity.Value}|{value.FailedSignature.Value}|{value.FailedArchitecture}|{value.RollbackArtifact.Value}|{value.RollbackDigest.Value}|{value.RollbackSigningIdentity.Value}|{value.RollbackSignature.Value}|{value.RollbackArchitecture}|{value.HealthProof.Value}",
            _ => throw new InvalidOperationException($"Unexpected delivery intent {intent.GetType().Name}."),
        };
    }

    private static string PlanSignature(SourceRevision source) =>
        $"Plan|{source.Source.Value}|{source.Commit.Value}|{source.Tree.Value}|{source.Manifest.Value}|{source.Generation.ToString(CultureInfo.InvariantCulture)}|{source.DesiredDigest.Value}|{source.Signature.Value}|schema-attestation|dependency-attestation|{string.Join(',', source.Dependencies.OrderBy(value => value.Manifest.Value, StringComparer.Ordinal).Select(value => $"{value.Manifest.Value}:{value.Generation.ToString(CultureInfo.InvariantCulture)}:{value.Digest.Value}"))}";
    private static string PromotionSignature(int index, long generation, EvidenceSubject subject, QualificationEvidence evidence) =>
        $"Promote|release-{index}|{generation.ToString(CultureInfo.InvariantCulture)}|{SubjectSignature(subject)}|{evidence.Tests.Value}|{evidence.SigningIdentity.Value}|{evidence.Signature.Value}|{evidence.Approval.Value}|{evidence.Evidence.Value}|{CompatibilitySignature(evidence.Compatibility)}";
    private static string StageSignature(ReleaseSpec release, DeliveryCellId cell) =>
        $"Stage|{release.Release.Value}|{release.Operation.Value}|{cell.Value}|{release.Generation.ToString(CultureInfo.InvariantCulture)}|{release.Artifact.Value}|{release.Digest.Value}|{release.SigningIdentity.Value}|{release.Signature.Value}|{release.Architecture}|{release.RollbackArtifact.Value}|{release.RollbackDigest.Value}|{release.RollbackSigningIdentity.Value}|{release.RollbackSignature.Value}|{release.RollbackArchitecture}";
    private static string AdvanceSignature(ReleaseSpec release, DeliveryCellId cell, DeliveryCellId next) =>
        $"Advance|{release.Release.Value}|{release.Operation.Value}|{cell.Value}|{next.Value}|{release.Generation.ToString(CultureInfo.InvariantCulture)}|{release.Artifact.Value}|{release.Digest.Value}|{release.SigningIdentity.Value}|{release.Signature.Value}|{release.Architecture}|health-{release.Release.Value}";
    private static string RollbackSignature(ReleaseSpec release, DeliveryCellId cell) =>
        $"Rollback|{release.Release.Value}|{release.Operation.Value}|{cell.Value}|{release.Generation.ToString(CultureInfo.InvariantCulture)}|{release.Artifact.Value}|{release.Digest.Value}|{release.SigningIdentity.Value}|{release.Signature.Value}|{release.Architecture}|{release.RollbackArtifact.Value}|{release.RollbackDigest.Value}|{release.RollbackSigningIdentity.Value}|{release.RollbackSignature.Value}|{release.RollbackArchitecture}|health-{release.Release.Value}";
    private static string SubjectSignature(EvidenceSubject value) => $"{value.Tree.Value}/{value.DependencyLock.Value}/{value.GeneratedSchemas.Value}/{value.Artifact.Value}/{value.ArtifactDigest.Value}/{value.Architecture}";
    private static string CompatibilitySignature(CompatibilityProof value) => $"{value.CurrentToCurrent.Value}/{value.CurrentToPrevious.Value}/{value.PreviousToCurrent.Value}/{value.CurrentToCurrentCompatible}/{value.CurrentToPreviousCompatible}/{value.PreviousToCurrentCompatible}";

    private static SourceRevision Source(int index, long generation) => new(new($"source-{index}"), new($"ref-{index}"),
        new($"commit-{index}"), new($"tree-{index}"), new($"manifest-{index}"), generation, new($"digest-{index}"),
        new($"source-signature-{index}"), [new(new($"dep-z-{index}"), generation, new($"dep-digest-z-{index}")), new(new($"dep-a-{index}"), generation, new($"dep-digest-a-{index}"))]);
    private static SourceEvidence Evidence(SourceRevision source, SourceState state = SourceState.Verified) => new(new($"observation-{source.Generation}"), state,
        source.Source, source.Reference, source.Generation, source.Commit, source.Tree, source.Manifest, source.DesiredDigest,
        source.Signature, new("schema-attestation"), new("dependency-attestation"), source.Dependencies, true, true);
    private static JobRequest Job(JobKind kind = JobKind.TrustedBuild, RunnerCapability capability = RunnerCapability.Compile) =>
        new(new("pipeline"), new("job"), kind, new("tree"), 1, 1, 3, new("key"), [TrustZone.TrustedBuild], [capability], 1, 10, false);
    private static RunnerEvidence Runner(TrustZone zone = TrustZone.TrustedBuild) => new(new("runner"), zone, 5, true, [RunnerCapability.Compile]);
    private static EvidenceSubject Subject(int index, DeliveryArchitecture architecture) => new(new($"tree-{index}"), new($"lock-{index}"),
        new($"schema-{index}"), new($"artifact-{index}"), new($"digest-{index}"), architecture);
    private static QualificationEvidence Qualification(int index, long generation, EvidenceSubject subject) => new(new($"release-{index}"), generation,
        subject, new($"tests-{index}"), new($"evidence-{index}"), new($"signer-{index}"), new($"signature-{index}"), new($"approval-{index}"),
        new(new($"nn-{index}"), new($"np-{index}"), new($"pn-{index}"), true, true, true), true, true, true, true);
    private static ReleaseSpec Release(int index, long generation, DeliveryArchitecture architecture = DeliveryArchitecture.LinuxArm64,
        DeliveryArchitecture? rollbackArchitecture = null, RolloutStrategy strategy = RolloutStrategy.Canary,
        RollbackPolicy policy = RollbackPolicy.AutomaticOnFailedHealth) => new(new($"release-{index}"), new($"operation-{index}"), generation,
        new($"artifact-{index}"), new($"digest-{index}"), new($"signer-{index}"), new($"signature-{index}"), architecture,
        new($"rollback-artifact-{index}"), new($"rollback-digest-{index}"), new($"rollback-signer-{index}"), new($"rollback-signature-{index}"), rollbackArchitecture ?? architecture,
        strategy, policy, [new("sfo"), new("fra"), new("gru")]);
    private static CellArtifactAvailability[] Availability(ReleaseSpec release) => release.OrderedCells.Select(cell => new CellArtifactAvailability(
        release.Release, release.Operation, release.Generation, cell, release.Artifact, release.Digest, release.SigningIdentity, release.Signature, release.Architecture,
        release.RollbackArtifact, release.RollbackDigest, release.RollbackSigningIdentity, release.RollbackSignature, release.RollbackArchitecture, true, true)).ToArray();
    private static StageEvidence Stage(ReleaseSpec release, StageHealth health) => new(new($"observation-{release.Release.Value}"), release.Operation,
        release.OrderedCells[0], release.Release, release.Generation, release.Artifact, release.Digest, release.SigningIdentity, release.Signature, release.Architecture,
        health, new($"health-{release.Release.Value}"), true, true);
    private static CellCompletionEvidence Completion(ReleaseSpec release, DeliveryCellId cell) => new(release.Operation, cell, release.Release,
        release.Generation, release.Artifact, release.Digest, release.SigningIdentity, release.Signature, release.Architecture,
        new($"health-{release.Release.Value}"), StageHealth.Healthy);
    private static RolloutRequest Rollout(ReleaseSpec release, IEnumerable<CellCompletionEvidence>? completed = null,
        IEnumerable<CellArtifactAvailability>? availability = null, StageEvidence? stage = null) =>
        new(release, completed ?? [], availability ?? Availability(release), stage, 96);
    private static CellArtifactAvailability[] Replace(CellArtifactAvailability[] values, int index, CellArtifactAvailability value)
    { var copy = values.ToArray(); copy[index] = value; return copy; }
    private static DeliveryArchitecture Other(DeliveryArchitecture architecture) => architecture == DeliveryArchitecture.LinuxArm64
        ? DeliveryArchitecture.LinuxX64 : DeliveryArchitecture.LinuxArm64;
    private static T UnderCulture<T>(string culture, Func<T> action)
    { var before = CultureInfo.CurrentCulture; var beforeUi = CultureInfo.CurrentUICulture; try { CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(culture); CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo(culture); return action(); } finally { CultureInfo.CurrentCulture = before; CultureInfo.CurrentUICulture = beforeUi; } }
    private static void Require(bool condition, string family, int index, string expected, string actual)
    { if (!condition) throw new InvalidOperationException($"{family} property failed at {index}: expected {expected}; actual {actual}."); }
    private static ulong Mix(ulong digest, string value, long number)
    { unchecked { foreach (var character in value) digest = (digest ^ character) * 1099511628211UL; return (digest ^ (ulong)number) * 1099511628211UL; } }
    private static async Task AssertHeld(DeliveryDecision decision, DeliveryErrorCode code)
    { await Assert.That(decision.Errors.Single().Code).IsEqualTo(code); await Assert.That(decision.Intents.Single()).IsTypeOf<HoldDeliveryIntent>(); }
    private sealed record Summary(int Cases, int Outcomes, ulong Digest);
    private sealed class Generator(ulong state)
    { private ulong _state = state; public int Next(int maximum) { _state ^= _state << 13; _state ^= _state >> 7; _state ^= _state << 17; return (int)(_state % (uint)maximum); } }
}
