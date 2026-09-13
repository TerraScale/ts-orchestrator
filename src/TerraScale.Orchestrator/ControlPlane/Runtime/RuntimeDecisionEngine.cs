using System.Collections.ObjectModel;

namespace TerraScale.Orchestrator.ControlPlane.Runtime;

public static class RuntimeDecisionEngine
{
    public static RuntimeDecision EvaluateLifecycle(RuntimeLifecycleRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var trace = new List<RuntimeDecisionReason>();
        var healthGroups = request.Health.ToLookup(h => h.Dimension);
        var duplicates = healthGroups.Sum(g => Math.Max(0, g.Count() - 1));
        var conflicts = healthGroups.Count(g => g.Select(h => (h.OperationId, h.AllocationId, h.Generation, h.Status)).Distinct().Skip(1).Any());
        trace.Add(Hold(RuntimeDecisionCode.EvidenceUnique, duplicates == 0, checked((ulong)duplicates), 0));
        trace.Add(Hold(RuntimeDecisionCode.EvidenceConsistent, conflicts == 0, checked((ulong)conflicts), 0));
        if (trace.Any(r => r.Outcome == RuntimeDecisionOutcome.Held)) return Deny(request.OperationId, trace);

        var observation = request.Observation;
        var operationExact = observation.OperationId == request.OperationId && observation.AllocationId == request.Spec.AllocationId;
        trace.Add(Reject(RuntimeDecisionCode.OperationExact, operationExact, operationExact ? 1UL : 0UL, 1));
        var epochExact = request.Epoch == request.CurrentEpoch && observation.Epoch == request.Epoch;
        trace.Add(observation.Epoch.Value > request.CurrentEpoch.Value ? Hold(RuntimeDecisionCode.EpochCurrent, false, observation.Epoch.Value, request.CurrentEpoch.Value) : Reject(RuntimeDecisionCode.EpochCurrent, epochExact, observation.Epoch.Value, request.CurrentEpoch.Value));
        var generation = request.Spec.Generation == request.CurrentGeneration && observation.Generation == request.Spec.Generation;
        trace.Add(observation.Generation.Value > request.CurrentGeneration.Value ? Hold(RuntimeDecisionCode.GenerationCurrent, false, observation.Generation.Value, request.CurrentGeneration.Value) : Reject(RuntimeDecisionCode.GenerationCurrent, generation, observation.Generation.Value, request.CurrentGeneration.Value));
        var admission = request.Admission.Role == request.Spec.Role && request.Admission.Driver == request.Spec.Payload.Driver &&
                        request.Admission.Architecture == request.Spec.Payload.Architecture && request.Admission.PolicyGeneration == request.AdmissionPolicyGeneration &&
                        DescriptorMatches(request.Spec);
        trace.Add(Reject(RuntimeDecisionCode.AdmissionExact, admission, admission ? 1UL : 0UL, 1));
        trace.Add(Reject(RuntimeDecisionCode.ArchitectureExact, request.Admission.Architecture == request.Spec.Payload.Architecture, request.Admission.Architecture == request.Spec.Payload.Architecture ? 1UL : 0UL, 1));
        trace.Add(Reject(RuntimeDecisionCode.ArtifactExact, observation.ArtifactDigest == request.Spec.Payload.ActivationDigest, observation.ArtifactDigest == request.Spec.Payload.ActivationDigest ? 1UL : 0UL, 1));
        var safetyAction = request.Action is LifecycleAction.Drain or LifecycleAction.Stop or LifecycleAction.Cleanup;
        var inventoryExact = request.Inventory.OperationId == request.OperationId && request.Inventory.NodeId == request.Spec.NodeId && request.Inventory.Generation == request.CurrentGeneration;
        trace.Add(safetyAction ? NotApplicable(RuntimeDecisionCode.EvidenceComplete) : !inventoryExact ? Reject(RuntimeDecisionCode.EvidenceComplete, false, 0, 1) : Hold(RuntimeDecisionCode.EvidenceComplete, request.Inventory.Completeness == EvidenceCompleteness.Complete, request.Inventory.Completeness == EvidenceCompleteness.Complete ? 1UL : 0UL, 1));
        var sameNode = request.Inventory.Allocations.Where(c => c.NodeId == request.Spec.NodeId && c.AllocationId != request.Spec.AllocationId).ToArray();
        var portConflicts = sameNode.Sum(c => c.Ports.Count(p => request.Spec.Ports.Contains(p)));
        var volumeConflicts = sameNode.Sum(c => c.Volumes.Count(v => request.Spec.Volumes.Any(binding => binding.VolumeId == v)));
        trace.Add(safetyAction ? NotApplicable(RuntimeDecisionCode.PortConflictFree) : Reject(RuntimeDecisionCode.PortConflictFree, portConflicts == 0, checked((ulong)portConflicts), 0));
        trace.Add(safetyAction ? NotApplicable(RuntimeDecisionCode.VolumeConflictFree) : Reject(RuntimeDecisionCode.VolumeConflictFree, volumeConflicts == 0, checked((ulong)volumeConflicts), 0));
        var healthExact = request.Health.All(h => h.OperationId == request.OperationId && h.AllocationId == request.Spec.AllocationId && h.Generation == request.Spec.Generation);
        trace.Add(safetyAction ? NotApplicable(RuntimeDecisionCode.HealthExact) : Reject(RuntimeDecisionCode.HealthExact, healthExact, healthExact ? checked((ulong)request.Health.Count) : 0UL, checked((ulong)request.Health.Count)));
        var readiness = request.Spec.RequiredHealth.All(required => request.Health.Any(h => h.Dimension == required && h.Status == HealthStatus.Ready));
        var requiresReadiness = request.Action == LifecycleAction.Converge && observation.Phase is LifecyclePhase.Started or LifecyclePhase.Serving;
        trace.Add(requiresReadiness
            ? (request.Health.Any(h => h.Status == HealthStatus.Failed) ? Reject(RuntimeDecisionCode.ReadinessComplete, false, 0, checked((ulong)request.Spec.RequiredHealth.Count)) : Hold(RuntimeDecisionCode.ReadinessComplete, readiness, readiness ? checked((ulong)request.Spec.RequiredHealth.Count) : 0UL, checked((ulong)request.Spec.RequiredHealth.Count)))
            : NotApplicable(RuntimeDecisionCode.ReadinessComplete));
        var processConsistent = ProcessConsistent(request.Action, observation.Phase, observation.ProcessStatus);
        trace.Add(Reject(RuntimeDecisionCode.ProcessConsistent, processConsistent, processConsistent ? 1UL : 0UL, 1));
        var callSafe = observation.CallStatus is ExecutorCallStatus.NotCalled or ExecutorCallStatus.Completed;
        trace.Add(callSafe ? Pass(RuntimeDecisionCode.CallSafe) : Hold(RuntimeDecisionCode.CallSafe, false, 0, 1));

        if (trace.Any(r => r.Outcome == RuntimeDecisionOutcome.Rejected)) return Deny(request.OperationId, trace);
        if (!callSafe) return Decision(true, trace, new ObserveExecutorIntent(request));
        if (trace.Any(r => r.Outcome == RuntimeDecisionOutcome.Held))
        {
            var held = trace.Where(r => r.Outcome == RuntimeDecisionOutcome.Held).ToArray();
            if (request.Action == LifecycleAction.Converge && observation.Phase is LifecyclePhase.Started or LifecyclePhase.Serving &&
                held.Length == 1 && held[0].Code == RuntimeDecisionCode.ReadinessComplete)
                return Decision(true, trace, new CheckRuntimeHealthIntent(request));
            return Deny(request.OperationId, trace);
        }

        RuntimeIntent intent = request.Action switch
        {
            LifecycleAction.Converge => observation.Phase switch
            {
                LifecyclePhase.None => new FetchRuntimeArtifactIntent(request),
                LifecyclePhase.ArtifactFetched => new VerifyRuntimeArtifactIntent(request),
                LifecyclePhase.ArtifactVerified => new StageRuntimeIntent(request),
                LifecyclePhase.Staged => new MountRuntimeIntent(request),
                LifecyclePhase.Mounted => new StartRuntimeIntent(request),
                LifecyclePhase.Started => new CheckRuntimeHealthIntent(request),
                LifecyclePhase.Serving => new CheckRuntimeHealthIntent(request),
                _ => new HoldRuntimeIntent(request.OperationId),
            },
            LifecycleAction.Drain when observation.Phase == LifecyclePhase.Serving => new DrainRuntimeIntent(request),
            LifecycleAction.Stop when observation.Phase is LifecyclePhase.Started or LifecyclePhase.Serving or LifecyclePhase.Draining => new StopRuntimeIntent(request),
            LifecycleAction.Cleanup when observation.Phase == LifecyclePhase.Stopped => new CleanupRuntimeIntent(request),
            _ => new HoldRuntimeIntent(request.OperationId),
        };
        return intent is HoldRuntimeIntent ? Decision(false, trace, intent) : Decision(true, trace, intent);
    }

    private static bool ProcessConsistent(LifecycleAction action, LifecyclePhase phase, ProcessStatus status)
    {
        if (action == LifecycleAction.Stop && phase is LifecyclePhase.Started or LifecyclePhase.Serving or LifecyclePhase.Draining)
            return status is ProcessStatus.Running or ProcessStatus.Failed;
        return phase switch
        {
            LifecyclePhase.None or LifecyclePhase.ArtifactFetched or LifecyclePhase.ArtifactVerified or LifecyclePhase.Staged or LifecyclePhase.Mounted => status == ProcessStatus.Absent,
            LifecyclePhase.Started or LifecyclePhase.Serving or LifecyclePhase.Draining => status == ProcessStatus.Running,
            LifecyclePhase.Stopped => status is ProcessStatus.Absent or ProcessStatus.ExitedSuccessfully or ProcessStatus.Failed,
            LifecyclePhase.Cleaned => status == ProcessStatus.Absent,
            _ => false,
        };
    }

    public static RuntimeDecision EvaluateSelfUpdate(SelfUpdateRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var trace = new List<RuntimeDecisionReason>();
        var observation = request.Observation;
        var operation = observation.OperationId == request.OperationId && observation.NodeId == request.NodeId && observation.TargetGeneration == request.TargetGeneration;
        trace.Add(Reject(RuntimeDecisionCode.OperationExact, operation, operation ? 1UL : 0UL, 1));
        trace.Add(Reject(RuntimeDecisionCode.EpochCurrent, request.Epoch == request.CurrentEpoch && observation.Epoch == request.Epoch, observation.Epoch.Value, request.CurrentEpoch.Value));
        var next = request.CurrentGeneration.Value < ulong.MaxValue && request.TargetGeneration.Value == request.CurrentGeneration.Value + 1;
        trace.Add(Reject(RuntimeDecisionCode.GenerationCurrent, next, request.TargetGeneration.Value, request.CurrentGeneration.Value));
        var slotDistinct = observation.ActiveSlot != observation.InactiveSlot && observation.ActiveSlot == request.ExpectedActiveSlot && observation.InactiveSlot == request.ExpectedInactiveSlot;
        trace.Add(Reject(RuntimeDecisionCode.SlotDistinct, slotDistinct, slotDistinct ? 1UL : 0UL, 1));
        var forwardExact = ArtifactMatches(request.ExpectedForwardArtifact, request.ForwardArtifact) && request.ExpectedForwardArtifact.Generation == request.TargetGeneration && request.ExpectedForwardArtifact.Architecture == request.Architecture && request.ForwardArtifact.Verification == ArtifactVerificationStatus.Verified;
        trace.Add(Reject(RuntimeDecisionCode.ArtifactExact, forwardExact, forwardExact ? 1UL : 0UL, 1));
        trace.Add(request.ForwardArtifact.Availability == ArtifactAvailability.Available ? Pass(RuntimeDecisionCode.ForwardAvailable) : Hold(RuntimeDecisionCode.ForwardAvailable, false, 0, 1));
        var rollback = ArtifactMatches(request.ExpectedRollbackArtifact, request.RollbackArtifact) && request.ExpectedRollbackArtifact.Generation == request.CurrentGeneration && request.ExpectedRollbackArtifact.Architecture == request.Architecture &&
                       request.RollbackArtifact.Availability == ArtifactAvailability.Available && request.RollbackArtifact.Verification == ArtifactVerificationStatus.Verified;
        trace.Add(rollback ? Pass(RuntimeDecisionCode.RollbackAvailable) : Hold(RuntimeDecisionCode.RollbackAvailable, false, 0, 1));
        var compatibilityScopeExact = request.Compatibility.OperationId == request.OperationId && request.Compatibility.CurrentGeneration == request.CurrentGeneration &&
                                      request.Compatibility.TargetGeneration == request.TargetGeneration && request.Compatibility.ProtocolGeneration == request.CurrentProtocolGeneration &&
                                      request.Compatibility.SchemaGeneration == request.CurrentSchemaGeneration;
        var compatibility = compatibilityScopeExact && request.Compatibility.NToNMinusOne == CompatibilityStatus.Compatible &&
                            request.Compatibility.Status == CompatibilityStatus.Compatible;
        trace.Add(Reject(RuntimeDecisionCode.CompatibilityExact, compatibility, compatibility ? 1UL : 0UL, 1));
        var healthGroups = request.Health.ToLookup(h => h.Dimension);
        var healthUnique = healthGroups.All(g => g.Count() == 1);
        trace.Add(Hold(RuntimeDecisionCode.EvidenceUnique, healthUnique, healthUnique ? 0UL : 1UL, 0));
        var expectedHealthGeneration = observation.Phase == UpdatePhase.RolledBack ? request.CurrentGeneration : request.TargetGeneration;
        var healthExact = request.Health.All(h => h.OperationId == request.OperationId && h.AllocationId == request.AllocationId && h.Generation == expectedHealthGeneration);
        trace.Add(Reject(RuntimeDecisionCode.HealthExact, healthExact, healthExact ? checked((ulong)request.Health.Count) : 0UL, checked((ulong)request.Health.Count)));
        var requiresNewHealth = observation.Phase is UpdatePhase.LocalHealthVerified or UpdatePhase.RegionalCompatibilityVerified or UpdatePhase.SlotCommitted or UpdatePhase.OldSlotRetainedUntilSoak;
        var requiresRollbackHealth = observation.Phase == UpdatePhase.RolledBack;
        var requiredHealthReady = request.Health.Any() && new[] { HealthDimension.Liveness, HealthDimension.LocalReadiness, HealthDimension.DependencyReadiness }.All(d => Ready(request, d));
        var requiredHealthFailed = request.Health.Any(h => (h.Dimension is HealthDimension.Liveness or HealthDimension.LocalReadiness or HealthDimension.DependencyReadiness) && h.Status == HealthStatus.Failed);
        trace.Add(requiresNewHealth || requiresRollbackHealth
            ? (requiredHealthFailed ? Reject(RuntimeDecisionCode.ReadinessComplete, false, 0, 3) : Hold(RuntimeDecisionCode.ReadinessComplete, requiredHealthReady, requiredHealthReady ? 3UL : 0UL, 3))
            : NotApplicable(RuntimeDecisionCode.ReadinessComplete));
        var callSafe = observation.CallStatus is ExecutorCallStatus.NotCalled or ExecutorCallStatus.Completed;
        trace.Add(callSafe ? Pass(RuntimeDecisionCode.CallSafe) : Hold(RuntimeDecisionCode.CallSafe, false, 0, 1));
        trace.Add(observation.Phase == UpdatePhase.RollbackFailed ? Reject(RuntimeDecisionCode.RollbackPossible, false, 0, 1) : rollback ? Pass(RuntimeDecisionCode.RollbackPossible) : Hold(RuntimeDecisionCode.RollbackPossible, false, 0, 1));

        var requiresCompatibilityRecovery = observation.Phase is UpdatePhase.LocalHealthVerified or UpdatePhase.RegionalCompatibilityVerified or
                                            UpdatePhase.SlotCommitted or UpdatePhase.OldSlotRetainedUntilSoak;
        var compatibilityFailed = compatibilityScopeExact &&
                                  (request.Compatibility.NToNMinusOne == CompatibilityStatus.Incompatible || request.Compatibility.Status == CompatibilityStatus.Incompatible);
        var recoverableFailure = requiresNewHealth && healthExact && requiredHealthFailed || requiresCompatibilityRecovery && compatibilityFailed;
        var soakPhase = observation.Phase == UpdatePhase.OldSlotRetainedUntilSoak;
        if (soakPhase && recoverableFailure)
        {
            trace.Add(NotApplicable(RuntimeDecisionCode.SoakComplete));
        }
        else if (!soakPhase)
        {
            trace.Add(request.Soak is null
                ? NotApplicable(RuntimeDecisionCode.SoakComplete)
                : Reject(RuntimeDecisionCode.SoakComplete, false, request.Soak.ObservedDuration.Value, 0));
        }
        else if (request.Soak is null)
        {
            trace.Add(Hold(RuntimeDecisionCode.SoakComplete, false, 0, request.SoakDuration.Value));
        }
        else
        {
            var soakScopeExact = request.Soak.OperationId == request.OperationId && request.Soak.NodeId == request.NodeId &&
                                 request.Soak.AllocationId == request.AllocationId && request.Soak.Epoch == request.Epoch &&
                                 request.Soak.TargetGeneration == request.TargetGeneration && request.Soak.ActiveSlot == observation.ActiveSlot;
            trace.Add(!soakScopeExact
                ? Reject(RuntimeDecisionCode.SoakComplete, false, request.Soak.ObservedDuration.Value, request.SoakDuration.Value)
                : Hold(RuntimeDecisionCode.SoakComplete, request.Soak.ObservedDuration.Value >= request.SoakDuration.Value,
                    request.Soak.ObservedDuration.Value, request.SoakDuration.Value));
        }
        var hardRejected = trace.Any(r => r.Outcome == RuntimeDecisionOutcome.Rejected &&
                                          r.Code != RuntimeDecisionCode.ReadinessComplete &&
                                          !(r.Code == RuntimeDecisionCode.CompatibilityExact && requiresCompatibilityRecovery && compatibilityFailed));
        if (hardRejected || (trace.Any(r => r.Outcome == RuntimeDecisionOutcome.Rejected) && !recoverableFailure)) return Deny(request.OperationId, trace);
        if (!callSafe) return Decision(true, trace, new ObserveUpdateIntent(request));
        if (trace.Any(r => r.Outcome == RuntimeDecisionOutcome.Held)) return Deny(request.OperationId, trace);
        if (requiresNewHealth && healthExact && requiredHealthFailed) return Decision(true, trace, new RollbackUpdateIntent(request));
        if (requiresCompatibilityRecovery && compatibilityFailed) return Decision(true, trace, new RollbackUpdateIntent(request));

        var localReady = Ready(request, HealthDimension.Liveness) && Ready(request, HealthDimension.LocalReadiness) && Ready(request, HealthDimension.DependencyReadiness);
        var localFailed = request.Health.Any(h => (h.Dimension is HealthDimension.Liveness or HealthDimension.LocalReadiness or HealthDimension.DependencyReadiness) && h.Status == HealthStatus.Failed);
        RuntimeIntent intent = observation.Phase switch
        {
            UpdatePhase.UpgradePlanned => new VerifyUpdateArtifactIntent(request),
            UpdatePhase.ArtifactVerified => new StageInactiveSlotIntent(request),
            UpdatePhase.InactiveSlotStaged => new ArmRollbackIntent(request),
            UpdatePhase.RollbackTimerArmed => new SwitchUpdateSlotIntent(request),
            UpdatePhase.ProcessRestarted when localFailed => new RollbackUpdateIntent(request),
            UpdatePhase.ProcessRestarted when localReady => new CheckRuntimeHealthIntent(request),
            UpdatePhase.ProcessRestarted => new CheckRuntimeHealthIntent(request),
            UpdatePhase.LocalHealthVerified => new VerifyRegionalCompatibilityIntent(request),
            UpdatePhase.RegionalCompatibilityVerified => new CommitUpdateSlotIntent(request),
            UpdatePhase.SlotCommitted => new RetainOldUpdateSlotIntent(request),
            UpdatePhase.OldSlotRetainedUntilSoak => new CompleteSelfUpdateIntent(request),
            UpdatePhase.RollingBack => new ObserveUpdateIntent(request),
            UpdatePhase.RolledBack when localReady => new CompleteSelfUpdateIntent(request),
            _ => new HoldRuntimeIntent(request.OperationId),
        };
        return intent is HoldRuntimeIntent ? Decision(false, trace, intent) : Decision(true, trace, intent);
    }

    private static bool ArtifactMatches(UpdateArtifactSubject expected, UpdateArtifactEvidence evidence) =>
        expected.ReleaseId == evidence.ReleaseId && expected.ArtifactId == evidence.ArtifactId && expected.Digest == evidence.Digest &&
        expected.SignatureId == evidence.SignatureId && expected.SigningProfileId == evidence.SigningProfileId && expected.Architecture == evidence.Architecture && expected.Generation == evidence.Generation;

    private static bool DescriptorMatches(WorkloadRuntimeSpec spec) => (spec.Role, spec.Payload) switch
    {
        (RuntimeRole.Orchestrator, NativeRuntimePayload { Descriptor: NativeUnitDescriptor.Orchestrator }) => true,
        (RuntimeRole.TerraBase, NativeRuntimePayload { Descriptor: NativeUnitDescriptor.TerraBase }) => true,
        (RuntimeRole.NatsServer, NativeRuntimePayload { Descriptor: NativeUnitDescriptor.NatsServer }) => true,
        (RuntimeRole.Telemetry, NativeRuntimePayload { Descriptor: NativeUnitDescriptor.Telemetry }) => true,
        (RuntimeRole.Platform, OciRuntimePayload { Descriptor: OciRuntimeDescriptor.Platform }) => true,
        (RuntimeRole.Authentication, OciRuntimePayload { Descriptor: OciRuntimeDescriptor.Authentication }) => true,
        (RuntimeRole.Dashboard, OciRuntimePayload { Descriptor: OciRuntimeDescriptor.Dashboard }) => true,
        (RuntimeRole.TerraBase, OciRuntimePayload { Descriptor: OciRuntimeDescriptor.TerraBase }) => true,
        (RuntimeRole.Telemetry, OciRuntimePayload { Descriptor: OciRuntimeDescriptor.Telemetry }) => true,
        (RuntimeRole.Grafana, OciRuntimePayload { Descriptor: OciRuntimeDescriptor.Grafana }) => true,
        (RuntimeRole.TrustedCi, OciRuntimePayload { Descriptor: OciRuntimeDescriptor.TrustedCi }) => true,
        _ => false,
    };
    private static bool Ready(SelfUpdateRequest r, HealthDimension d) => r.Health.Any(h => h.Dimension == d && h.Status == HealthStatus.Ready);
    private static RuntimeDecisionReason Pass(RuntimeDecisionCode c) => new(c, RuntimeDecisionOutcome.Passed, 1, 1);
    private static RuntimeDecisionReason Hold(RuntimeDecisionCode c, bool pass, ulong o, ulong required) => new(c, pass ? RuntimeDecisionOutcome.Passed : RuntimeDecisionOutcome.Held, o, required);
    private static RuntimeDecisionReason Reject(RuntimeDecisionCode c, bool pass, ulong o, ulong required) => new(c, pass ? RuntimeDecisionOutcome.Passed : RuntimeDecisionOutcome.Rejected, o, required);
    private static RuntimeDecisionReason NotApplicable(RuntimeDecisionCode c) => new(c, RuntimeDecisionOutcome.NotApplicable, 0, 0);
    private static RuntimeDecision Decision(bool authorized, List<RuntimeDecisionReason> trace, RuntimeIntent intent) => new(authorized, new ReadOnlyCollection<RuntimeDecisionReason>(trace.ToArray()), intent);
    private static RuntimeDecision Deny(RuntimeOperationId operationId, List<RuntimeDecisionReason> trace) => Decision(false, trace, new HoldRuntimeIntent(operationId));
}

