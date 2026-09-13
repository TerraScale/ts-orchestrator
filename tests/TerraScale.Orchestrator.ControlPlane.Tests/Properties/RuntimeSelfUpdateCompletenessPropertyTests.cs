using System.Globalization;
using TerraScale.Orchestrator.ControlPlane.Runtime;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties;

public sealed class RuntimeSelfUpdateCompletenessPropertyTests
{
    private const int Cases = 1000;

    [Test]
    public async Task Every_forward_and_rollback_artifact_field_is_independently_bound_for_1000_cases()
    {
        var operations = new HashSet<string>(StringComparer.Ordinal);
        for (var seed = 1UL; seed <= Cases; seed++)
        {
            var request = RuntimeUpgradeData.Update(seed, 0);
            var variant = (int)(seed % 18);
            request = variant < 9
                ? Rebuild(request, forward: Mutate(request.ForwardArtifact, variant, seed))
                : Rebuild(request, rollback: Mutate(request.RollbackArtifact, variant - 9, seed));

            var decision = RuntimeDecisionEngine.EvaluateSelfUpdate(request);
            var expectedCode = variant switch
            {
                7 => RuntimeDecisionCode.ForwardAvailable,
                >= 9 => RuntimeDecisionCode.RollbackAvailable,
                _ => RuntimeDecisionCode.ArtifactExact,
            };
            var expectedOutcome = expectedCode == RuntimeDecisionCode.ArtifactExact
                ? RuntimeDecisionOutcome.Rejected
                : RuntimeDecisionOutcome.Held;

            Require(!decision.Authorized && decision.Intent is HoldRuntimeIntent, seed, "artifact mutation denied");
            Require(decision.Trace.Single(r => r.Code == expectedCode).Outcome == expectedOutcome, seed, $"artifact code {expectedCode}");
            Require(decision.Intent.OperationId == request.OperationId, seed, "denial operation identity");
            Require(decision.Trace.Count == 14, seed, "closed trace cardinality");
            operations.Add(request.OperationId.Value);
        }

        await Assert.That(operations.Count).IsEqualTo(Cases);
    }

    [Test]
    public async Task Exact_post_restart_compatibility_failure_rolls_back_with_full_trace_for_1000_cases()
    {
        var executed = 0;
        var recoverablePhases = new[]
        {
            UpdatePhase.LocalHealthVerified,
            UpdatePhase.RegionalCompatibilityVerified,
            UpdatePhase.SlotCommitted,
            UpdatePhase.OldSlotRetainedUntilSoak,
        };
        for (var seed = 1UL; seed <= Cases; seed++)
        {
            var phase = recoverablePhases[seed % (ulong)recoverablePhases.Length];
            var request = RuntimeUpgradeData.Update(seed, VariantFor(phase));
            var incompatible = new UpdateCompatibilityEvidence(
                request.OperationId, request.CurrentGeneration, request.TargetGeneration,
                request.CurrentProtocolGeneration, request.CurrentSchemaGeneration,
                seed % 2 == 0 ? CompatibilityStatus.Incompatible : CompatibilityStatus.Compatible,
                seed % 2 == 0 ? CompatibilityStatus.Compatible : CompatibilityStatus.Incompatible);
            request = Rebuild(request, compatibility: incompatible);

            var decision = RuntimeDecisionEngine.EvaluateSelfUpdate(request);
            Require(decision.Authorized && decision.Intent is RollbackUpdateIntent rollback && ReferenceEquals(rollback.Request, request), seed, "compatibility rollback");
            Require(decision.Intent.OperationId == request.OperationId, seed, "rollback operation identity");
            AssertExactRecoveryTrace(decision, request, RuntimeDecisionOutcome.Rejected, RuntimeDecisionOutcome.Passed, seed);
            executed++;
        }

        await Assert.That(executed).IsEqualTo(Cases);
    }

    [Test]
    public async Task Compatibility_failure_before_local_verification_and_after_rollback_is_not_rollback_eligible()
    {
        var phases = new[]
        {
            UpdatePhase.UpgradePlanned,
            UpdatePhase.ArtifactVerified,
            UpdatePhase.InactiveSlotStaged,
            UpdatePhase.RollbackTimerArmed,
            UpdatePhase.ProcessRestarted,
            UpdatePhase.RollingBack,
            UpdatePhase.RolledBack,
            UpdatePhase.RollbackFailed,
        };
        var executed = 0;
        for (var seed = 1UL; seed <= Cases; seed++)
        {
            var phase = phases[seed % (ulong)phases.Length];
            var request = RuntimeUpgradeData.Update(seed, VariantFor(phase));
            request = Rebuild(request, compatibility: new UpdateCompatibilityEvidence(
                request.OperationId, request.CurrentGeneration, request.TargetGeneration,
                request.CurrentProtocolGeneration, request.CurrentSchemaGeneration,
                CompatibilityStatus.Compatible, CompatibilityStatus.Incompatible));

            var decision = RuntimeDecisionEngine.EvaluateSelfUpdate(request);
            Require(!decision.Authorized && decision.Intent is HoldRuntimeIntent, seed, $"phase {phase} denied");
            Require(Reason(decision, RuntimeDecisionCode.CompatibilityExact).Outcome == RuntimeDecisionOutcome.Rejected, seed, "incompatible result visible");
            executed++;
        }

        await Assert.That(executed).IsEqualTo(Cases);
    }

    [Test]
    public async Task Accepted_calls_hard_fences_and_incomplete_rollback_have_safe_precedence_for_1000_cases()
    {
        var executed = 0;
        for (var seed = 1UL; seed <= Cases; seed++)
        {
            var request = RuntimeUpgradeData.Update(seed, 6);
            var failedCompatibility = new UpdateCompatibilityEvidence(
                request.OperationId, request.CurrentGeneration, request.TargetGeneration,
                request.CurrentProtocolGeneration, request.CurrentSchemaGeneration,
                CompatibilityStatus.Compatible, CompatibilityStatus.Incompatible);
            request = Rebuild(request, compatibility: failedCompatibility);
            var variant = (int)(seed % 10);

            request = variant switch
            {
                0 => Rebuild(request, observation: Observation(request, ExecutorCallStatus.Accepted)),
                1 => Rebuild(request, observation: Observation(request, ExecutorCallStatus.ResponseLost)),
                2 => Rebuild(request,
                    rollback: Mutate(request.RollbackArtifact, 7, seed),
                    compatibility: Compatible(request),
                    health: FailedHealth(request)),
                3 => Rebuild(request, forward: Mutate(request.ForwardArtifact, seed % 2 == 0 ? 2 : 3, seed), observation: Observation(request, ExecutorCallStatus.Accepted)),
                4 => Rebuild(request, observation: Observation(request, ExecutorCallStatus.Accepted, epoch: request.Epoch.Value - 1)),
                5 => Rebuild(request, currentGeneration: new RuntimeGeneration(request.CurrentGeneration.Value - 1), observation: Observation(request, ExecutorCallStatus.Accepted)),
                6 => Rebuild(request, health: FailedHealth(request)),
                7 => Rebuild(request, compatibility: new UpdateCompatibilityEvidence(
                    new RuntimeOperationId($"other-operation-{seed}"), request.CurrentGeneration, request.TargetGeneration,
                    request.CurrentProtocolGeneration, request.CurrentSchemaGeneration,
                    CompatibilityStatus.Compatible, CompatibilityStatus.Incompatible)),
                8 => RollbackFailedRequest(seed),
                _ => Rebuild(request, compatibility: new UpdateCompatibilityEvidence(
                    request.OperationId, request.CurrentGeneration, request.TargetGeneration,
                    request.CurrentProtocolGeneration, request.CurrentSchemaGeneration,
                    CompatibilityStatus.Compatible, seed % 2 == 0 ? CompatibilityStatus.Missing : CompatibilityStatus.Unknown)),
            };

            var decision = RuntimeDecisionEngine.EvaluateSelfUpdate(request);
            if (variant is 0 or 1)
                Require(decision.Authorized && decision.Intent is ObserveUpdateIntent observe && ReferenceEquals(observe.Request, request), seed, "accepted call observed first");
            else if (variant == 6)
                Require(decision.Authorized && decision.Intent is RollbackUpdateIntent rollback && ReferenceEquals(rollback.Request, request), seed, "mixed exact failures recover once");
            else
                Require(!decision.Authorized && decision.Intent is HoldRuntimeIntent, seed, "unsafe recovery denied");

            if (variant == 2) Require(Reason(decision, RuntimeDecisionCode.RollbackAvailable).Outcome == RuntimeDecisionOutcome.Held, seed, "rollback availability precedence");
            if (variant == 3) Require(Reason(decision, RuntimeDecisionCode.ArtifactExact).Outcome == RuntimeDecisionOutcome.Rejected, seed, "digest signature precedence");
            if (variant == 4) Require(Reason(decision, RuntimeDecisionCode.EpochCurrent).Outcome == RuntimeDecisionOutcome.Rejected, seed, "epoch precedence");
            if (variant == 5) Require(Reason(decision, RuntimeDecisionCode.GenerationCurrent).Outcome == RuntimeDecisionOutcome.Rejected, seed, "generation precedence");
            if (variant == 7) Require(Reason(decision, RuntimeDecisionCode.CompatibilityExact).Outcome == RuntimeDecisionOutcome.Rejected, seed, "compatibility scope precedence");
            if (variant == 8) Require(Reason(decision, RuntimeDecisionCode.RollbackPossible).Outcome == RuntimeDecisionOutcome.Rejected, seed, "rollback failed terminal precedence");
            if (variant == 9) Require(Reason(decision, RuntimeDecisionCode.CompatibilityExact).Outcome == RuntimeDecisionOutcome.Rejected, seed, "unproven compatibility is not failure recovery");
            executed++;
        }

        await Assert.That(executed).IsEqualTo(Cases);
    }

    [Test]
    public async Task Identical_update_is_culture_UI_culture_and_health_order_invariant_for_1000_cases()
    {
        var cultures = new[] { "tr-TR", "ar-SA", "ja-JP" };
        var executed = 0;
        for (var seed = 1UL; seed <= Cases; seed++)
        {
            var baseline = RenderUnderCulture(RuntimeUpgradeData.Update(seed, 6), "en-US");
            var permuted = RuntimeUpgradeData.Update(seed, 6, reverseHealth: true);
            Require(RenderUnderCulture(permuted, cultures[seed % 3]) == baseline, seed, "culture and health-order replay");
            executed++;
        }

        await Assert.That(executed).IsEqualTo(Cases);
    }

    private static void AssertExactRecoveryTrace(RuntimeDecision decision, SelfUpdateRequest request,
        RuntimeDecisionOutcome compatibility, RuntimeDecisionOutcome callSafe, ulong seed)
    {
        var expected = new (RuntimeDecisionCode Code, RuntimeDecisionOutcome Outcome, ulong Observed, ulong Required)[]
        {
            (RuntimeDecisionCode.OperationExact, RuntimeDecisionOutcome.Passed, 1, 1),
            (RuntimeDecisionCode.EpochCurrent, RuntimeDecisionOutcome.Passed, request.Observation.Epoch.Value, request.CurrentEpoch.Value),
            (RuntimeDecisionCode.GenerationCurrent, RuntimeDecisionOutcome.Passed, request.TargetGeneration.Value, request.CurrentGeneration.Value),
            (RuntimeDecisionCode.SlotDistinct, RuntimeDecisionOutcome.Passed, 1, 1),
            (RuntimeDecisionCode.ArtifactExact, RuntimeDecisionOutcome.Passed, 1, 1),
            (RuntimeDecisionCode.ForwardAvailable, RuntimeDecisionOutcome.Passed, 1, 1),
            (RuntimeDecisionCode.RollbackAvailable, RuntimeDecisionOutcome.Passed, 1, 1),
            (RuntimeDecisionCode.CompatibilityExact, compatibility, compatibility == RuntimeDecisionOutcome.Passed ? 1UL : 0UL, 1),
            (RuntimeDecisionCode.EvidenceUnique, RuntimeDecisionOutcome.Passed, 0, 0),
            (RuntimeDecisionCode.HealthExact, RuntimeDecisionOutcome.Passed, 3, 3),
            (RuntimeDecisionCode.ReadinessComplete, RuntimeDecisionOutcome.Passed, 3, 3),
            (RuntimeDecisionCode.CallSafe, callSafe, callSafe == RuntimeDecisionOutcome.Passed ? 1UL : 0UL, 1),
            (RuntimeDecisionCode.RollbackPossible, RuntimeDecisionOutcome.Passed, 1, 1),
            (RuntimeDecisionCode.SoakComplete, RuntimeDecisionOutcome.NotApplicable, 0, 0),
        };
        Require(decision.Trace.Select(r => (r.Code, r.Outcome, r.Observed, r.Required)).SequenceEqual(expected), seed, "exact recovery trace");
    }

    private static UpdateArtifactEvidence Mutate(UpdateArtifactEvidence artifact, int field, ulong seed) => new(
        field == 0 ? new RuntimeReleaseId($"other-release-{seed}") : artifact.ReleaseId,
        field == 1 ? new RuntimeArtifactId($"other-artifact-{seed}") : artifact.ArtifactId,
        field == 2 ? new RuntimeDigest(new string('f', 64)) : artifact.Digest,
        field == 3 ? new RuntimeSignatureId($"other-signature-{seed}") : artifact.SignatureId,
        field == 4 ? new RuntimeSigningProfileId($"other-profile-{seed}") : artifact.SigningProfileId,
        field == 5 ? RuntimeArchitecture.LinuxX64 : artifact.Architecture,
        field == 6 ? new RuntimeGeneration(artifact.Generation.Value + 1) : artifact.Generation,
        field == 7 ? ArtifactAvailability.Missing : artifact.Availability,
        field == 8 ? ArtifactVerificationStatus.Failed : artifact.Verification);

    private static SelfUpdateObservation Observation(SelfUpdateRequest request, ExecutorCallStatus callStatus, ulong? epoch = null) => new(
        request.Observation.OperationId, request.Observation.NodeId, new RuntimeEpoch(epoch ?? request.Observation.Epoch.Value),
        request.Observation.TargetGeneration, request.Observation.Phase, request.Observation.ActiveSlot, request.Observation.InactiveSlot, callStatus);

    private static SelfUpdateRequest Rebuild(SelfUpdateRequest request,
        UpdateArtifactEvidence? forward = null, UpdateArtifactEvidence? rollback = null,
        UpdateCompatibilityEvidence? compatibility = null, SelfUpdateObservation? observation = null,
        RuntimeGeneration? currentGeneration = null, IEnumerable<RuntimeHealthEvidence>? health = null) => new(
        request.OperationId, request.NodeId, request.AllocationId, request.Epoch, request.CurrentEpoch, request.Architecture,
        currentGeneration ?? request.CurrentGeneration, request.TargetGeneration, request.CurrentProtocolGeneration, request.CurrentSchemaGeneration,
        request.HealthTimeout, request.SoakDuration, request.CompatibilityWindow, request.RollbackPolicy,
        request.ExpectedActiveSlot, request.ExpectedInactiveSlot, request.ExpectedForwardArtifact, request.ExpectedRollbackArtifact,
        forward ?? request.ForwardArtifact, rollback ?? request.RollbackArtifact, compatibility ?? request.Compatibility,
        observation ?? request.Observation, request.Soak, health ?? request.Health);

    private static RuntimeHealthEvidence[] FailedHealth(SelfUpdateRequest request) =>
    [
        new(new RuntimeHealthId($"failed-live-{request.CurrentGeneration.Value}"), request.OperationId, request.AllocationId,
            request.TargetGeneration, HealthDimension.Liveness, HealthStatus.Failed),
        new(new RuntimeHealthId($"ready-local-{request.CurrentGeneration.Value}"), request.OperationId, request.AllocationId,
            request.TargetGeneration, HealthDimension.LocalReadiness, HealthStatus.Ready),
        new(new RuntimeHealthId($"ready-dependency-{request.CurrentGeneration.Value}"), request.OperationId, request.AllocationId,
            request.TargetGeneration, HealthDimension.DependencyReadiness, HealthStatus.Ready),
    ];

    private static UpdateCompatibilityEvidence Compatible(SelfUpdateRequest request) => new(
        request.OperationId, request.CurrentGeneration, request.TargetGeneration,
        request.CurrentProtocolGeneration, request.CurrentSchemaGeneration,
        CompatibilityStatus.Compatible, CompatibilityStatus.Compatible);

    private static SelfUpdateRequest RollbackFailedRequest(ulong seed)
    {
        var request = RuntimeUpgradeData.Update(seed, 18);
        return Rebuild(request, compatibility: new UpdateCompatibilityEvidence(
            request.OperationId, request.CurrentGeneration, request.TargetGeneration,
            request.CurrentProtocolGeneration, request.CurrentSchemaGeneration,
            CompatibilityStatus.Compatible, CompatibilityStatus.Incompatible));
    }

    private static int VariantFor(UpdatePhase phase) => phase switch
    {
        UpdatePhase.UpgradePlanned => 0,
        UpdatePhase.ArtifactVerified => 1,
        UpdatePhase.InactiveSlotStaged => 2,
        UpdatePhase.RollbackTimerArmed => 3,
        UpdatePhase.ProcessRestarted => 4,
        UpdatePhase.LocalHealthVerified => 5,
        UpdatePhase.RegionalCompatibilityVerified => 6,
        UpdatePhase.SlotCommitted => 7,
        UpdatePhase.OldSlotRetainedUntilSoak => 8,
        UpdatePhase.RollingBack => 9,
        UpdatePhase.RolledBack => 10,
        UpdatePhase.RollbackFailed => 18,
        _ => throw new ArgumentOutOfRangeException(nameof(phase)),
    };

    private static string RenderUnderCulture(SelfUpdateRequest request, string cultureName)
    {
        var previous = CultureInfo.CurrentCulture;
        var previousUi = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(cultureName);
            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo(cultureName);
            var decision = RuntimeDecisionEngine.EvaluateSelfUpdate(request);
            return $"{decision.Authorized}|{decision.Intent.GetType().Name}|{decision.Intent.OperationId.Value}|" +
                   string.Join(';', decision.Trace.Select(r => $"{r.Code}:{r.Outcome}:{r.Observed}:{r.Required}"));
        }
        finally
        {
            CultureInfo.CurrentCulture = previous;
            CultureInfo.CurrentUICulture = previousUi;
        }
    }

    private static RuntimeDecisionReason Reason(RuntimeDecision decision, RuntimeDecisionCode code) => decision.Trace.Single(r => r.Code == code);
    private static void Require(bool condition, ulong seed, string property)
    {
        if (!condition) throw new InvalidOperationException($"{property} failed at seed {seed}.");
    }
}

