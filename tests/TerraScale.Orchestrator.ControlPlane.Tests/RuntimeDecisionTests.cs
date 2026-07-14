using System.Globalization;
using System.Reflection;
using TerraScale.Orchestrator.ControlPlane.Runtime;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class RuntimeDecisionTests
{
    [Test]
    public async Task NativeAndOciDriversFollowEquivalentLifecycleContract()
    {
        var native = RuntimeDecisionEngine.EvaluateLifecycle(Lifecycle(payload: NativePayload(), role: RuntimeRole.TerraBase));
        var oci = RuntimeDecisionEngine.EvaluateLifecycle(Lifecycle(payload: OciPayload(), role: RuntimeRole.TerraBase));
        await Assert.That(native.Intent.GetType()).IsEqualTo(typeof(FetchRuntimeArtifactIntent));
        await Assert.That(oci.Intent.GetType()).IsEqualTo(native.Intent.GetType());
        await Assert.That(Serialize(native)).IsEqualTo(Serialize(oci));

        var manifestSubstitution = RuntimeDecisionEngine.EvaluateLifecycle(Lifecycle(
            payload: OciPayload(), observedDigest: Digest()));
        await Assert.That(Reason(manifestSubstitution, RuntimeDecisionCode.ArtifactExact).Outcome).IsEqualTo(RuntimeDecisionOutcome.Rejected);
    }

    [Test]
    public async Task RuntimeAdmissionRejectsRoleDescriptorDriverAndArchitectureReplay()
    {
        var wrongRole = RuntimeDecisionEngine.EvaluateLifecycle(Lifecycle(payload: NativePayload(), role: RuntimeRole.Api));
        var wrongDriver = RuntimeDecisionEngine.EvaluateLifecycle(Lifecycle(
            payload: NativePayload(), role: RuntimeRole.TerraBase,
            admission: new(RuntimeRole.TerraBase, RuntimeDriver.OciContainer, RuntimeArchitecture.LinuxArm64, new(2))));
        var wrongArchitecture = RuntimeDecisionEngine.EvaluateLifecycle(Lifecycle(
            payload: NativePayload(), role: RuntimeRole.TerraBase,
            admission: new(RuntimeRole.TerraBase, RuntimeDriver.NativeSystemd, RuntimeArchitecture.LinuxX64, new(2))));
        await Assert.That(Reason(wrongRole, RuntimeDecisionCode.AdmissionExact).Outcome).IsEqualTo(RuntimeDecisionOutcome.Rejected);
        await Assert.That(wrongDriver.Authorized).IsFalse();
        await Assert.That(wrongArchitecture.Authorized).IsFalse();
    }

    [Test]
    public async Task LifecycleProgressionEmitsOnlyNextTypedStep()
    {
        var cases = new (LifecyclePhase Phase, Type Intent)[]
        {
            (LifecyclePhase.None, typeof(FetchRuntimeArtifactIntent)),
            (LifecyclePhase.ArtifactFetched, typeof(VerifyRuntimeArtifactIntent)),
            (LifecyclePhase.ArtifactVerified, typeof(StageRuntimeIntent)),
            (LifecyclePhase.Staged, typeof(MountRuntimeIntent)),
            (LifecyclePhase.Mounted, typeof(StartRuntimeIntent)),
        };
        foreach (var (phase, intent) in cases)
            await Assert.That(RuntimeDecisionEngine.EvaluateLifecycle(Lifecycle(phase: phase)).Intent.GetType()).IsEqualTo(intent);
    }

    [Test]
    public async Task ProcessExitZeroNeverSubstitutesForReadinessOrDependencyHealth()
    {
        var noHealth = RuntimeDecisionEngine.EvaluateLifecycle(Lifecycle(
            phase: LifecyclePhase.Started, process: ProcessStatus.ExitedSuccessfully));
        var dependencyFailed = RuntimeDecisionEngine.EvaluateLifecycle(Lifecycle(
            phase: LifecyclePhase.Started, process: ProcessStatus.Running,
            health: Health(dependency: HealthStatus.Failed)));
        await Assert.That(noHealth.Authorized).IsFalse();
        await Assert.That(Reason(noHealth, RuntimeDecisionCode.ProcessConsistent).Outcome).IsEqualTo(RuntimeDecisionOutcome.Rejected);
        await Assert.That(dependencyFailed.Authorized).IsFalse();
        await Assert.That(Reason(dependencyFailed, RuntimeDecisionCode.ReadinessComplete).Outcome).IsEqualTo(RuntimeDecisionOutcome.Rejected);
    }

    [Test]
    public async Task ExactReadinessEvidenceRemainsDistinctAcrossAllDimensions()
    {
        var ready = RuntimeDecisionEngine.EvaluateLifecycle(Lifecycle(
            phase: LifecyclePhase.Started, process: ProcessStatus.Running, health: Health()));
        var replayed = Health().Select(item => item.Dimension == HealthDimension.DependencyReadiness
            ? new RuntimeHealthEvidence(item.Id, new("other-operation"), item.AllocationId, item.Generation, item.Dimension, item.Status)
            : item).ToArray();
        var wrongOperation = RuntimeDecisionEngine.EvaluateLifecycle(Lifecycle(
            phase: LifecyclePhase.Started, process: ProcessStatus.Running, health: replayed));
        await Assert.That(ready.Authorized).IsTrue();
        await Assert.That(Reason(ready, RuntimeDecisionCode.ReadinessComplete).Outcome).IsEqualTo(RuntimeDecisionOutcome.Passed);
        await Assert.That(Reason(wrongOperation, RuntimeDecisionCode.HealthExact).Outcome).IsEqualTo(RuntimeDecisionOutcome.Rejected);
    }

    [Test]
    public async Task PortAndVolumeConflictsRejectBeforeExecutorIntent()
    {
        var port = new RuntimeConflictEvidence(new("other-allocation"), Node, [new RuntimePort(8080)], []);
        var volume = new RuntimeConflictEvidence(new("other-allocation"), Node, [], [new RuntimeVolumeId("volume-1")]);
        var portDecision = RuntimeDecisionEngine.EvaluateLifecycle(Lifecycle(conflicts: [port]));
        var volumeDecision = RuntimeDecisionEngine.EvaluateLifecycle(Lifecycle(conflicts: [volume]));
        await Assert.That(Reason(portDecision, RuntimeDecisionCode.PortConflictFree).Outcome).IsEqualTo(RuntimeDecisionOutcome.Rejected);
        await Assert.That(Reason(volumeDecision, RuntimeDecisionCode.VolumeConflictFree).Outcome).IsEqualTo(RuntimeDecisionOutcome.Rejected);
        await Assert.That(portDecision.Intent is HoldRuntimeIntent).IsTrue();
    }

    [Test]
    public async Task ConflictInventoryMustBeCurrentScopedAndCompleteEvenWhenEmpty()
    {
        var missing = RuntimeDecisionEngine.EvaluateLifecycle(Lifecycle(inventory: Inventory(completeness: EvidenceCompleteness.Incomplete)));
        var stale = RuntimeDecisionEngine.EvaluateLifecycle(Lifecycle(inventory: Inventory(generation: 4)));
        var replay = RuntimeDecisionEngine.EvaluateLifecycle(Lifecycle(inventory: Inventory(operation: new("other-operation"))));
        await Assert.That(Reason(missing, RuntimeDecisionCode.EvidenceComplete).Outcome).IsEqualTo(RuntimeDecisionOutcome.Held);
        await Assert.That(Reason(stale, RuntimeDecisionCode.EvidenceComplete).Outcome).IsEqualTo(RuntimeDecisionOutcome.Rejected);
        await Assert.That(replay.Authorized).IsFalse();
    }

    [Test]
    public async Task ServingReobservesMissingHealthButSafetyActionsRemainAuthorizedOnFailure()
    {
        var servingWithoutHealth = RuntimeDecisionEngine.EvaluateLifecycle(Lifecycle(
            phase: LifecyclePhase.Serving, process: ProcessStatus.Running));
        var stopFailed = RuntimeDecisionEngine.EvaluateLifecycle(Lifecycle(
            phase: LifecyclePhase.Started, action: LifecycleAction.Stop, process: ProcessStatus.Running,
            health: Health(dependency: HealthStatus.Failed)));
        await Assert.That(servingWithoutHealth.Intent is CheckRuntimeHealthIntent).IsTrue();
        await Assert.That(servingWithoutHealth.Authorized).IsTrue();
        await Assert.That(Reason(servingWithoutHealth, RuntimeDecisionCode.ReadinessComplete).Outcome).IsEqualTo(RuntimeDecisionOutcome.Held);
        await Assert.That(stopFailed.Intent is StopRuntimeIntent).IsTrue();
        await Assert.That(stopFailed.Authorized).IsTrue();
    }

    [Test]
    public async Task FutureAuthorityAtStartedHoldsWithoutAuthorizedHealthWork()
    {
        var futureEpoch = RuntimeDecisionEngine.EvaluateLifecycle(Lifecycle(
            phase: LifecyclePhase.Started, process: ProcessStatus.Running, epoch: 6));
        var futureGeneration = RuntimeDecisionEngine.EvaluateLifecycle(Lifecycle(
            phase: LifecyclePhase.Started, process: ProcessStatus.Running, observedGeneration: 6));
        await Assert.That(futureEpoch.Authorized).IsFalse();
        await Assert.That(futureGeneration.Authorized).IsFalse();
        await Assert.That(futureEpoch.Intent is HoldRuntimeIntent).IsTrue();
        await Assert.That(futureGeneration.Intent is HoldRuntimeIntent).IsTrue();
    }

    [Test]
    public async Task StaleEpochGenerationDigestAndOperationReplayReject()
    {
        var staleEpoch = RuntimeDecisionEngine.EvaluateLifecycle(Lifecycle(epoch: 4));
        var futureGeneration = RuntimeDecisionEngine.EvaluateLifecycle(Lifecycle(observedGeneration: 6));
        var wrongDigest = RuntimeDecisionEngine.EvaluateLifecycle(Lifecycle(observedDigest: new(new string('b', 64))));
        var wrongOperation = RuntimeDecisionEngine.EvaluateLifecycle(Lifecycle(observedOperation: new("other-operation")));
        await Assert.That(Reason(staleEpoch, RuntimeDecisionCode.EpochCurrent).Outcome).IsEqualTo(RuntimeDecisionOutcome.Rejected);
        await Assert.That(Reason(futureGeneration, RuntimeDecisionCode.GenerationCurrent).Outcome).IsEqualTo(RuntimeDecisionOutcome.Held);
        await Assert.That(Reason(wrongDigest, RuntimeDecisionCode.ArtifactExact).Outcome).IsEqualTo(RuntimeDecisionOutcome.Rejected);
        await Assert.That(Reason(wrongOperation, RuntimeDecisionCode.OperationExact).Outcome).IsEqualTo(RuntimeDecisionOutcome.Rejected);
    }

    [Test]
    public async Task LostExecutorResponseReobservesAndNeverRepeatsStartOrStop()
    {
        var lostStart = RuntimeDecisionEngine.EvaluateLifecycle(Lifecycle(
            phase: LifecyclePhase.Mounted, call: ExecutorCallStatus.ResponseLost));
        var lostStop = RuntimeDecisionEngine.EvaluateLifecycle(Lifecycle(
            phase: LifecyclePhase.Serving, action: LifecycleAction.Stop, process: ProcessStatus.Running, call: ExecutorCallStatus.Accepted));
        await Assert.That(lostStart.Intent is ObserveExecutorIntent).IsTrue();
        await Assert.That(lostStop.Intent is ObserveExecutorIntent).IsTrue();
    }

    [Test]
    public async Task DrainStopAndCleanupAreExplicitAndPreserveRetentionPolicy()
    {
        var drain = RuntimeDecisionEngine.EvaluateLifecycle(Lifecycle(phase: LifecyclePhase.Serving, action: LifecycleAction.Drain, process: ProcessStatus.Running));
        var stop = RuntimeDecisionEngine.EvaluateLifecycle(Lifecycle(phase: LifecyclePhase.Draining, action: LifecycleAction.Stop, process: ProcessStatus.Running));
        var cleanupRequest = Lifecycle(phase: LifecyclePhase.Stopped, action: LifecycleAction.Cleanup);
        var cleanup = RuntimeDecisionEngine.EvaluateLifecycle(cleanupRequest);
        await Assert.That(drain.Intent is DrainRuntimeIntent).IsTrue();
        await Assert.That(stop.Intent is StopRuntimeIntent).IsTrue();
        var cleanupIntent = (CleanupRuntimeIntent)cleanup.Intent;
        await Assert.That(ReferenceEquals(cleanupIntent.Request, cleanupRequest)).IsTrue();
        await Assert.That(cleanupIntent.EphemeralVolumes).IsEquivalentTo([new RuntimeVolumeId("scratch-1")]);
        await Assert.That(cleanupIntent.EphemeralVolumes).IsEquivalentTo(
            cleanupRequest.Spec.Volumes.Where(volume => volume.Retention == VolumeRetention.Ephemeral).Select(volume => volume.VolumeId));
        await Assert.That(cleanupIntent.EphemeralVolumes is RuntimeVolumeId[]).IsFalse();
        await Assert.That(Throws<NotSupportedException>(() =>
            ((IList<RuntimeVolumeId>)cleanupIntent.EphemeralVolumes)[0] = new RuntimeVolumeId("volume-1"))).IsTrue();
        await Assert.That(cleanupIntent.EphemeralVolumes).IsEquivalentTo([new RuntimeVolumeId("scratch-1")]);
    }

    [Test]
    public async Task EveryMutatingLifecycleIntentRetainsItsExactValidatedRequest()
    {
        var cases = new RuntimeLifecycleRequest[]
        {
            Lifecycle(phase: LifecyclePhase.None),
            Lifecycle(phase: LifecyclePhase.ArtifactFetched),
            Lifecycle(phase: LifecyclePhase.ArtifactVerified),
            Lifecycle(phase: LifecyclePhase.Staged),
            Lifecycle(phase: LifecyclePhase.Mounted),
            Lifecycle(phase: LifecyclePhase.Serving, action: LifecycleAction.Drain, process: ProcessStatus.Running),
            Lifecycle(phase: LifecyclePhase.Draining, action: LifecycleAction.Stop, process: ProcessStatus.Running),
            Lifecycle(phase: LifecyclePhase.Stopped, action: LifecycleAction.Cleanup),
        };

        foreach (var request in cases)
        {
            var intent = RuntimeDecisionEngine.EvaluateLifecycle(request).Intent;
            var requestProperty = intent.GetType().GetProperty(nameof(FetchRuntimeArtifactIntent.Request));
            await Assert.That(requestProperty).IsNotNull();
            await Assert.That(ReferenceEquals(requestProperty!.GetValue(intent), request)).IsTrue();
        }

        var readOnlyIntentTypes = new[]
        {
            typeof(CheckRuntimeHealthIntent), typeof(ObserveExecutorIntent), typeof(HoldRuntimeIntent),
        };
        foreach (var type in readOnlyIntentTypes)
            await Assert.That(type.GetProperty(nameof(FetchRuntimeArtifactIntent.Request))).IsNull();
    }

    [Test]
    public async Task SelfUpdateRequiresExactSignedForwardAndLocalRollbackArtifacts()
    {
        var exact = RuntimeDecisionEngine.EvaluateSelfUpdate(Update());
        var unsigned = RuntimeDecisionEngine.EvaluateSelfUpdate(Update(forward: Artifact(6, verification: ArtifactVerificationStatus.Failed)));
        var wrongArch = RuntimeDecisionEngine.EvaluateSelfUpdate(Update(forward: Artifact(6, architecture: RuntimeArchitecture.LinuxX64)));
        var missingRollback = RuntimeDecisionEngine.EvaluateSelfUpdate(Update(rollback: Artifact(5, availability: ArtifactAvailability.Missing)));
        await Assert.That(exact.Intent is VerifyUpdateArtifactIntent).IsTrue();
        await Assert.That(unsigned.Authorized).IsFalse();
        await Assert.That(wrongArch.Authorized).IsFalse();
        await Assert.That(Reason(missingRollback, RuntimeDecisionCode.RollbackAvailable).Outcome).IsEqualTo(RuntimeDecisionOutcome.Held);
    }

    [Test]
    public async Task VerifiedArtifactEvidenceCannotSubstituteForIndependentDesiredSubject()
    {
        var substitute = Artifact(6);
        var expected = new UpdateArtifactSubject(new("release-6"), new("artifact-6"), new(new string('d', 64)),
            new("signature-6"), new("sigstore-v1"), RuntimeArchitecture.LinuxArm64, new(6));
        var decision = RuntimeDecisionEngine.EvaluateSelfUpdate(Update(forward: substitute, expectedForward: expected));
        await Assert.That(decision.Authorized).IsFalse();
        await Assert.That(Reason(decision, RuntimeDecisionCode.ArtifactExact).Outcome).IsEqualTo(RuntimeDecisionOutcome.Rejected);
    }

    [Test]
    public async Task SelfUpdateRejectsIncompatibleOrReplayedProtocolSchemaGeneration()
    {
        var incompatible = RuntimeDecisionEngine.EvaluateSelfUpdate(Update(
            compatibility: Compatibility(status: CompatibilityStatus.Incompatible)));
        var replay = RuntimeDecisionEngine.EvaluateSelfUpdate(Update(
            compatibility: Compatibility(operation: new("other-operation"))));
        var staleSchema = RuntimeDecisionEngine.EvaluateSelfUpdate(Update(
            compatibility: Compatibility(schema: 2)));
        await Assert.That(Reason(incompatible, RuntimeDecisionCode.CompatibilityExact).Outcome).IsEqualTo(RuntimeDecisionOutcome.Rejected);
        await Assert.That(replay.Authorized).IsFalse();
        await Assert.That(staleSchema.Authorized).IsFalse();
    }

    [Test]
    public async Task EveryPersistedUpdateCheckpointResumesWithOneDeterministicIntent()
    {
        var cases = new (UpdatePhase Phase, Type Intent)[]
        {
            (UpdatePhase.UpgradePlanned, typeof(VerifyUpdateArtifactIntent)),
            (UpdatePhase.ArtifactVerified, typeof(StageInactiveSlotIntent)),
            (UpdatePhase.InactiveSlotStaged, typeof(ArmRollbackIntent)),
            (UpdatePhase.RollbackTimerArmed, typeof(SwitchUpdateSlotIntent)),
            (UpdatePhase.ProcessRestarted, typeof(CheckRuntimeHealthIntent)),
            (UpdatePhase.LocalHealthVerified, typeof(VerifyRegionalCompatibilityIntent)),
            (UpdatePhase.RegionalCompatibilityVerified, typeof(CommitUpdateSlotIntent)),
            (UpdatePhase.SlotCommitted, typeof(RetainOldUpdateSlotIntent)),
            (UpdatePhase.OldSlotRetainedUntilSoak, typeof(CompleteSelfUpdateIntent)),
            (UpdatePhase.RollingBack, typeof(ObserveUpdateIntent)),
            (UpdatePhase.RolledBack, typeof(CompleteSelfUpdateIntent)),
        };
        foreach (var (phase, intent) in cases)
            await Assert.That(RuntimeDecisionEngine.EvaluateSelfUpdate(Update(phase: phase)).Intent.GetType()).IsEqualTo(intent);
    }

    [Test]
    public async Task SwitchIsNotRepeatedAfterLostResponse()
    {
        var decision = RuntimeDecisionEngine.EvaluateSelfUpdate(Update(
            phase: UpdatePhase.RollbackTimerArmed, call: ExecutorCallStatus.ResponseLost));
        await Assert.That(decision.Intent is ObserveUpdateIntent).IsTrue();
        await Assert.That(decision.Intent is SwitchUpdateSlotIntent).IsFalse();
    }

    [Test]
    public async Task FailedNewHealthRollsBackWithoutNewProcessDependency()
    {
        var failed = RuntimeDecisionEngine.EvaluateSelfUpdate(Update(
            phase: UpdatePhase.ProcessRestarted, health: Health(liveness: HealthStatus.Failed, generation: 6)));
        var failedRollback = RuntimeDecisionEngine.EvaluateSelfUpdate(Update(phase: UpdatePhase.RollbackFailed));
        await Assert.That(failed.Intent is RollbackUpdateIntent).IsTrue();
        await Assert.That(failedRollback.Authorized).IsFalse();
        await Assert.That(Reason(failedRollback, RuntimeDecisionCode.RollbackPossible).Outcome).IsEqualTo(RuntimeDecisionOutcome.Rejected);
    }

    [Test]
    public async Task LaterUpdateCheckpointsRevalidateHealthBeforeCommit()
    {
        foreach (var phase in new[] { UpdatePhase.LocalHealthVerified, UpdatePhase.RegionalCompatibilityVerified, UpdatePhase.SlotCommitted })
        {
            var missing = RuntimeDecisionEngine.EvaluateSelfUpdate(Update(phase: phase, health: []));
            var failed = RuntimeDecisionEngine.EvaluateSelfUpdate(Update(phase: phase, health: Health(dependency: HealthStatus.Failed, generation: 6)));
            await Assert.That(missing.Authorized).IsFalse();
            await Assert.That(failed.Intent is RollbackUpdateIntent).IsTrue();
        }
    }

    [Test]
    public async Task HealthySelfUpdateCompletesOnlyAfterExactConfiguredSoak()
    {
        var missing = RuntimeDecisionEngine.EvaluateSelfUpdate(Update(
            phase: UpdatePhase.OldSlotRetainedUntilSoak, omitSoak: true));
        var before = RuntimeDecisionEngine.EvaluateSelfUpdate(Update(
            phase: UpdatePhase.OldSlotRetainedUntilSoak, soak: Soak(599)));
        var exact = RuntimeDecisionEngine.EvaluateSelfUpdate(Update(
            phase: UpdatePhase.OldSlotRetainedUntilSoak, soak: Soak(600)));
        var after = RuntimeDecisionEngine.EvaluateSelfUpdate(Update(
            phase: UpdatePhase.OldSlotRetainedUntilSoak, soak: Soak(601)));

        await Assert.That(missing.Authorized).IsFalse();
        await Assert.That(Reason(missing, RuntimeDecisionCode.SoakComplete).Outcome).IsEqualTo(RuntimeDecisionOutcome.Held);
        await Assert.That(before.Authorized).IsFalse();
        await Assert.That(Reason(before, RuntimeDecisionCode.SoakComplete).Outcome).IsEqualTo(RuntimeDecisionOutcome.Held);
        await Assert.That(exact.Intent is CompleteSelfUpdateIntent).IsTrue();
        await Assert.That(after.Intent is CompleteSelfUpdateIntent).IsTrue();
        await Assert.That(Reason(exact, RuntimeDecisionCode.SoakComplete).Observed).IsEqualTo(600UL);
        await Assert.That(Reason(after, RuntimeDecisionCode.SoakComplete).Observed).IsEqualTo(601UL);
        await Assert.That(exact.Trace.Count).IsEqualTo(14);
        await Assert.That(exact.Trace[^1].Code).IsEqualTo(RuntimeDecisionCode.SoakComplete);
        await Assert.That(Enum.GetValues<RuntimeDecisionCode>().Select(value => (int)value)
            .SequenceEqual(Enumerable.Range(1, 22))).IsTrue();
    }

    [Test]
    public async Task SoakEvidenceIsExactScopedAndRejectedOutsideSoakPhase()
    {
        var replayed = new[]
        {
            Soak(operation: new("other-operation")),
            Soak(node: new("other-node")),
            Soak(allocation: new("other-allocation")),
            Soak(epoch: 4),
            Soak(target: 7),
            Soak(slot: UpdateSlot.A),
        };
        foreach (var evidence in replayed)
        {
            var decision = RuntimeDecisionEngine.EvaluateSelfUpdate(Update(
                phase: UpdatePhase.OldSlotRetainedUntilSoak, soak: evidence));
            await Assert.That(decision.Authorized).IsFalse();
            await Assert.That(Reason(decision, RuntimeDecisionCode.SoakComplete).Outcome).IsEqualTo(RuntimeDecisionOutcome.Rejected);
        }

        foreach (var phase in Enum.GetValues<UpdatePhase>().Where(value => value != UpdatePhase.OldSlotRetainedUntilSoak))
        {
            var activeSlot = phase is UpdatePhase.UpgradePlanned or UpdatePhase.ArtifactVerified or
                UpdatePhase.InactiveSlotStaged or UpdatePhase.RollbackTimerArmed or UpdatePhase.RolledBack
                ? UpdateSlot.A
                : UpdateSlot.B;
            var future = RuntimeDecisionEngine.EvaluateSelfUpdate(Update(
                phase: phase, soak: Soak(slot: activeSlot)));
            await Assert.That(future.Authorized).IsFalse();
            await Assert.That(Reason(future, RuntimeDecisionCode.SoakComplete).Outcome).IsEqualTo(RuntimeDecisionOutcome.Rejected);
        }
    }

    [Test]
    public async Task SoakNeverDelaysExactHealthOrCompatibilityRollback()
    {
        var compatibilityFailure = RuntimeDecisionEngine.EvaluateSelfUpdate(Update(
            phase: UpdatePhase.OldSlotRetainedUntilSoak,
            compatibility: Compatibility(status: CompatibilityStatus.Incompatible), omitSoak: true));
        var healthFailure = RuntimeDecisionEngine.EvaluateSelfUpdate(Update(
            phase: UpdatePhase.OldSlotRetainedUntilSoak,
            health: Health(dependency: HealthStatus.Failed, generation: 6),
            soak: Soak(operation: new("other-operation"))));

        await Assert.That(compatibilityFailure.Intent is RollbackUpdateIntent).IsTrue();
        await Assert.That(healthFailure.Intent is RollbackUpdateIntent).IsTrue();
        await Assert.That(Reason(compatibilityFailure, RuntimeDecisionCode.SoakComplete).Outcome).IsEqualTo(RuntimeDecisionOutcome.NotApplicable);
        await Assert.That(Reason(healthFailure, RuntimeDecisionCode.SoakComplete).Outcome).IsEqualTo(RuntimeDecisionOutcome.NotApplicable);
    }

    [Test]
    public async Task RollbackIsObservedThenCompletesOnlyAfterOldGenerationHealth()
    {
        var applying = RuntimeDecisionEngine.EvaluateSelfUpdate(Update(phase: UpdatePhase.RollingBack));
        var missingHealth = RuntimeDecisionEngine.EvaluateSelfUpdate(Update(phase: UpdatePhase.RolledBack, health: []));
        var recovered = RuntimeDecisionEngine.EvaluateSelfUpdate(Update(phase: UpdatePhase.RolledBack, health: Health(generation: 5)));
        await Assert.That(applying.Intent is ObserveUpdateIntent).IsTrue();
        await Assert.That(missingHealth.Authorized).IsFalse();
        await Assert.That(recovered.Intent is CompleteSelfUpdateIntent).IsTrue();
    }

    [Test]
    public async Task ActiveAndInactiveSlotsCannotAliasAndCommittedSlotAdvancesToSoak()
    {
        await Assert.That(Throws<ArgumentException>(() => Observation(UpdatePhase.UpgradePlanned, active: UpdateSlot.A, inactive: UpdateSlot.A))).IsTrue();
        var committed = RuntimeDecisionEngine.EvaluateSelfUpdate(Update(phase: UpdatePhase.SlotCommitted));
        await Assert.That(committed.Authorized).IsTrue();
        await Assert.That(committed.Intent is RetainOldUpdateSlotIntent).IsTrue();
    }

    [Test]
    public async Task UpdateReplayAcrossNodeOperationArchitectureAndGenerationRejects()
    {
        var node = RuntimeDecisionEngine.EvaluateSelfUpdate(Update(observation: Observation(UpdatePhase.UpgradePlanned, node: new("other-node"))));
        var operation = RuntimeDecisionEngine.EvaluateSelfUpdate(Update(observation: Observation(UpdatePhase.UpgradePlanned, operation: new("other-operation"))));
        var generation = RuntimeDecisionEngine.EvaluateSelfUpdate(Update(observation: Observation(UpdatePhase.UpgradePlanned, target: 7)));
        var slotReplay = RuntimeDecisionEngine.EvaluateSelfUpdate(Update(observation: Observation(UpdatePhase.UpgradePlanned, active: UpdateSlot.B, inactive: UpdateSlot.A)));
        await Assert.That(node.Authorized).IsFalse();
        await Assert.That(operation.Authorized).IsFalse();
        await Assert.That(generation.Authorized).IsFalse();
        await Assert.That(Reason(slotReplay, RuntimeDecisionCode.SlotDistinct).Outcome).IsEqualTo(RuntimeDecisionOutcome.Rejected);
    }

    [Test]
    public async Task InputsAreDefensiveAndCulturePermutationDeterministic()
    {
        var mutable = Health().ToList();
        var request = Lifecycle(phase: LifecyclePhase.Started, health: mutable);
        mutable.Clear();
        await Assert.That(request.Health.Count).IsEqualTo(3);
        string? baseline = null;
        foreach (var culture in new[] { "en-US", "tr-TR", "ar-SA" })
        foreach (var health in new[] { Health(), Health().Reverse().ToArray() })
        {
            var original = CultureInfo.CurrentCulture;
            try
            {
                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(culture);
                var value = Serialize(RuntimeDecisionEngine.EvaluateLifecycle(Lifecycle(phase: LifecyclePhase.Started, health: health)));
                baseline ??= value;
                await Assert.That(value).IsEqualTo(baseline);
            }
            finally { CultureInfo.CurrentCulture = original; }
        }
    }

    [Test]
    public async Task ArbitraryExecutionIoSecretsAndPublicIntentForgeryAreUnrepresentable()
    {
        var types = typeof(RuntimeDecisionEngine).Assembly.GetTypes().Where(t => t.Namespace == "TerraScale.Orchestrator.ControlPlane.Runtime").ToArray();
        var forbiddenNames = new[] { "Command", "UnitText", "ContainerSpec", "HostPath", "Privileged", "Capability", "SecretValue", "PrivateKey", "Shell" };
        await Assert.That(types.SelectMany(t => t.GetProperties()).Any(p => forbiddenNames.Any(n => p.Name.Contains(n, StringComparison.OrdinalIgnoreCase)))).IsFalse();
        var forbiddenTypes = new[] { typeof(byte[]), typeof(Stream), typeof(Delegate), typeof(System.Diagnostics.Process), typeof(DateTime), typeof(DateTimeOffset) };
        await Assert.That(types.SelectMany(t => t.GetProperties()).Any(p => forbiddenTypes.Contains(p.PropertyType))).IsFalse();
        await Assert.That(types.Where(t => typeof(RuntimeIntent).IsAssignableFrom(t) && !t.IsAbstract)
            .SelectMany(t => t.GetConstructors(BindingFlags.Public | BindingFlags.Instance)).Any()).IsFalse();
        await Assert.That(typeof(RuntimeDecision).GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
        await Assert.That(Serialize(RuntimeDecisionEngine.EvaluateLifecycle(Lifecycle()))).DoesNotContain("secret");
    }

    [Test]
    public async Task UnknownZeroDuplicateAndMalformedInputsFailClosed()
    {
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => new RuntimeGeneration(0))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => new RuntimeDigest("mutable-tag"))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => new RuntimeWorkloadId("bad/path"))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => new RuntimeAdmission(RuntimeRole.Api, (RuntimeDriver)0, RuntimeArchitecture.LinuxArm64, new(1)))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => Spec(NativePayload(), RuntimeRole.TerraBase, ports: [new(8080), new(8080)]))).IsTrue();
        await Assert.That(Throws<ArgumentNullException>(() => new UpdateSoakEvidence(
            null!, Node, Allocation, new(5), new(6), UpdateSlot.B, new(600)))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => new UpdateSoakEvidence(
            Operation, Node, Allocation, new(5), new(6), (UpdateSlot)0, new(600)))).IsTrue();
    }

    private static RuntimeOperationId Operation { get; } = new("operation-1");
    private static RuntimeAllocationId Allocation { get; } = new("allocation-1");
    private static RuntimeNodeId Node { get; } = new("node-1");
    private static RuntimeDigest Digest() => new(new string('a', 64));
    private static NativeRuntimePayload NativePayload() => new(new("terrabase-artifact"), Digest(), new("signature-1"), new("sigstore-v1"), new("ol9-aarch64-1"), new("systemd-261"), RuntimeArchitecture.LinuxArm64, NativeUnitDescriptor.TerraBase);
    private static OciRuntimePayload OciPayload() => new(new("terrabase-image"), Digest(), new(new string('b', 64)), new("signature-1"), new("sigstore-v1"), new("ol9-aarch64-1"), new("containerd-2.2"), RuntimeArchitecture.LinuxArm64, OciRuntimeDescriptor.TerraBase);
    private static WorkloadRuntimeSpec Spec(RuntimePayload? payload = null, RuntimeRole role = RuntimeRole.TerraBase, IEnumerable<RuntimePort>? ports = null) => new(
        new("terrabase"), Allocation, Node, role, new(5), new("config-5"), payload ?? NativePayload(),
        [new("database-secret-v5")], [new(new("volume-1"), VolumeRetention.Retained), new(new("scratch-1"), VolumeRetention.Ephemeral)],
        ports ?? [new RuntimePort(8080)], [HealthDimension.Liveness, HealthDimension.LocalReadiness, HealthDimension.DependencyReadiness]);
    private static RuntimeHealthEvidence[] Health(
        HealthStatus liveness = HealthStatus.Ready, HealthStatus local = HealthStatus.Ready,
        HealthStatus dependency = HealthStatus.Ready, ulong generation = 5) =>
    [
        new(new("health-live"), Operation, Allocation, new(generation), HealthDimension.Liveness, liveness),
        new(new("health-local"), Operation, Allocation, new(generation), HealthDimension.LocalReadiness, local),
        new(new("health-dependency"), Operation, Allocation, new(generation), HealthDimension.DependencyReadiness, dependency),
    ];
    private static RuntimeLifecycleRequest Lifecycle(
        RuntimePayload? payload = null, RuntimeRole role = RuntimeRole.TerraBase,
        RuntimeAdmission? admission = null, LifecyclePhase phase = LifecyclePhase.None,
        LifecycleAction action = LifecycleAction.Converge, ProcessStatus process = ProcessStatus.Absent,
        ExecutorCallStatus call = ExecutorCallStatus.NotCalled, ulong epoch = 5, ulong observedGeneration = 5,
        RuntimeDigest? observedDigest = null, RuntimeOperationId? observedOperation = null,
        IEnumerable<RuntimeHealthEvidence>? health = null, IEnumerable<RuntimeConflictEvidence>? conflicts = null,
        RuntimeInventoryEvidence? inventory = null)
    {
        var spec = Spec(payload, role);
        return new(Operation, new(epoch), new(5), new(5), new(2), new(30), spec,
            admission ?? new(role, spec.Payload.Driver, spec.Payload.Architecture, new(2)), action,
            new(observedOperation ?? Operation, Allocation, new(epoch), new(observedGeneration), phase,
                observedDigest ?? spec.Payload.ActivationDigest, process, call), health ?? [],
            inventory ?? Inventory(conflicts ?? []));
    }

    private static RuntimeInventoryEvidence Inventory(
        IEnumerable<RuntimeConflictEvidence>? allocations = null, EvidenceCompleteness completeness = EvidenceCompleteness.Complete,
        RuntimeOperationId? operation = null, ulong generation = 5) =>
        new(operation ?? Operation, Node, new(generation), completeness, allocations ?? []);

    private static UpdateArtifactEvidence Artifact(
        ulong generation, RuntimeArchitecture architecture = RuntimeArchitecture.LinuxArm64,
        ArtifactAvailability availability = ArtifactAvailability.Available,
        ArtifactVerificationStatus verification = ArtifactVerificationStatus.Verified) => new(
        new($"release-{generation}"), new($"artifact-{generation}"), generation == 6 ? Digest() : new(new string('c', 64)),
        new($"signature-{generation}"), new("sigstore-v1"), architecture, new(generation), availability, verification);
    private static UpdateArtifactSubject Subject(UpdateArtifactEvidence evidence) => new(
        evidence.ReleaseId, evidence.ArtifactId, evidence.Digest, evidence.SignatureId, evidence.SigningProfileId, evidence.Architecture, evidence.Generation);
    private static UpdateCompatibilityEvidence Compatibility(
        CompatibilityStatus status = CompatibilityStatus.Compatible, RuntimeOperationId? operation = null,
        ulong schema = 1) => new(operation ?? Operation, new(5), new(6), new(1), new(schema), CompatibilityStatus.Compatible, status);
    private static SelfUpdateObservation Observation(
        UpdatePhase phase, ExecutorCallStatus call = ExecutorCallStatus.NotCalled,
        UpdateSlot active = UpdateSlot.A, UpdateSlot inactive = UpdateSlot.B,
        RuntimeNodeId? node = null, RuntimeOperationId? operation = null, ulong target = 6) => new(
        operation ?? Operation, node ?? Node, new(5), new(target), phase, active, inactive, call);
    private static UpdateSoakEvidence Soak(
        ulong duration = 600, RuntimeOperationId? operation = null, RuntimeNodeId? node = null,
        RuntimeAllocationId? allocation = null, ulong epoch = 5, ulong target = 6,
        UpdateSlot slot = UpdateSlot.B) => new(
        operation ?? Operation, node ?? Node, allocation ?? Allocation, new(epoch), new(target), slot, new(duration));
    private static SelfUpdateRequest Update(
        UpdatePhase phase = UpdatePhase.UpgradePlanned, ExecutorCallStatus call = ExecutorCallStatus.NotCalled,
        UpdateArtifactEvidence? forward = null, UpdateArtifactEvidence? rollback = null,
        UpdateArtifactSubject? expectedForward = null, UpdateArtifactSubject? expectedRollback = null,
        UpdateCompatibilityEvidence? compatibility = null, IEnumerable<RuntimeHealthEvidence>? health = null,
        SelfUpdateObservation? observation = null, UpdateSoakEvidence? soak = null, bool omitSoak = false)
    {
        var forwardEvidence = forward ?? Artifact(6);
        var rollbackEvidence = rollback ?? Artifact(5);
        var expectedActive = phase is UpdatePhase.UpgradePlanned or UpdatePhase.ArtifactVerified or UpdatePhase.InactiveSlotStaged or UpdatePhase.RollbackTimerArmed or UpdatePhase.RolledBack ? UpdateSlot.A : UpdateSlot.B;
        var expectedInactive = expectedActive == UpdateSlot.A ? UpdateSlot.B : UpdateSlot.A;
        var observed = observation ?? Observation(phase, call, expectedActive, expectedInactive);
        var soakEvidence = omitSoak ? null : soak ?? (phase == UpdatePhase.OldSlotRetainedUntilSoak
            ? new UpdateSoakEvidence(Operation, Node, Allocation, new(5), new(6), expectedActive, new(600))
            : null);
        return new(Operation, Node, Allocation, new(5), new(5), RuntimeArchitecture.LinuxArm64, new(5), new(6), new(1), new(1), new(30), new(600), UpdateCompatibilityWindow.NAndNMinusOne, UpdateRollbackPolicy.LocalKnownGoodOnHealthOrCompatibilityFailure, expectedActive, expectedInactive,
            expectedForward ?? Subject(Artifact(6)), expectedRollback ?? Subject(Artifact(5)),
            forwardEvidence, rollbackEvidence, compatibility ?? Compatibility(),
            observed, soakEvidence, health ?? DefaultUpdateHealth(phase));
    }
    private static RuntimeHealthEvidence[] DefaultUpdateHealth(UpdatePhase phase) => phase switch
    {
        UpdatePhase.LocalHealthVerified or UpdatePhase.RegionalCompatibilityVerified or UpdatePhase.SlotCommitted or UpdatePhase.OldSlotRetainedUntilSoak => Health(generation: 6),
        UpdatePhase.RolledBack => Health(generation: 5),
        _ => [],
    };
    private static RuntimeDecisionReason Reason(RuntimeDecision decision, RuntimeDecisionCode code) => decision.Trace.Single(r => r.Code == code);
    private static string Serialize(RuntimeDecision decision) => $"{decision.Authorized}|{decision.Intent.GetType().Name}|{string.Join(';', decision.Trace.Select(r => $"{r.Code}:{r.Outcome}:{r.Observed}:{r.Required}"))}";
    private static bool Throws<T>(Action action) where T : Exception { try { action(); return false; } catch (T) { return true; } }
}
