using System.Buffers;
using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text.Json;
using TerraScale.Orchestrator.ControlPlane.Reconciliation;

namespace TerraScale.Orchestrator.Delivery;

internal enum NativeGitOpsWorkloadState
{
    Unspecified,
    Absent,
    Applying,
    Healthy,
    Unhealthy,
    Suspended,
}

internal enum NativeGitOpsWorkloadOwnership
{
    Unspecified,
    NativeGitOpsParent,
    RegionalJournalChild,
    Foreign,
}

internal enum NativeGitOpsCellConvergenceIntentKind
{
    Unspecified,
    Observe,
    Apply,
    Suspend,
    AuthorizeRetirement,
    Retire,
    RequestRollbackGeneration,
}

internal enum NativeGitOpsCellConvergenceState
{
    Unspecified,
    Pending,
    Held,
    Converged,
}

internal enum NativeGitOpsCellConvergenceHoldReason
{
    None,
    InvalidObservation,
    AcceptedBaseMismatch,
    ForeignOwnership,
    FutureGeneration,
    SameGenerationConflict,
    FailedHealthWithoutRollback,
    RetirementProofMismatch,
    ReconciliationRejected,
}

internal sealed record NativeGitOpsWorkloadObservation(
    string WorkloadId,
    long Generation,
    string? WorkloadSha256,
    NativeGitOpsWorkloadState State,
    NativeGitOpsWorkloadOwnership Ownership,
    long FreshnessSequence,
    string EvidenceSha256);

internal sealed record NativeGitOpsAcceptedCellBaseline(
    string Cell,
    long Generation,
    string GlobalPlanDigest);

internal sealed record NativeGitOpsRollbackTarget(
    long QualifiedGeneration,
    string GlobalPlanDigest,
    string QualificationProofSha256);

internal sealed record NativeGitOpsRetirementEvidence(
    string Cell,
    string WorkloadId,
    long AcceptedGeneration,
    string AcceptedGlobalPlanDigest,
    string AcceptedWorkloadSha256,
    long WriterEpoch,
    string OwnershipProofSha256,
    string SafetyProofSha256,
    string RetentionProofSha256,
    string DependencyProofSha256,
    string DomainAuthorizationSha256);

internal sealed record NativeGitOpsCellConvergenceIntent(
    NativeGitOpsCellConvergenceIntentKind Kind,
    string WorkloadId,
    long Generation,
    string WorkloadSha256,
    string? ObservationEvidenceSha256,
    NativeGitOpsRollbackTarget? RollbackTarget);

internal sealed record NativeGitOpsCellConvergenceDecision(
    NativeGitOpsCellConvergenceState State,
    NativeGitOpsCellConvergenceHoldReason HoldReason,
    NativeGitOpsCellConvergenceIntent? Intent,
    string? ConvergenceDigest)
{
    internal bool IsConverged => State == NativeGitOpsCellConvergenceState.Converged &&
        HoldReason == NativeGitOpsCellConvergenceHoldReason.None && Intent is null && ConvergenceDigest is not null;
}

/// <summary>
/// Plans at most one regional action from one durably accepted CellSpec. A complete digest proves
/// exact regional live convergence only; cross-cell success remains a separate global barrier.
/// </summary>
internal static class NativeGitOpsCellConvergencePlanner
{
    internal static NativeGitOpsCellConvergenceDecision Decide(
        NativeGitOpsAcceptedCellSpec accepted,
        NativeGitOpsAcceptedCellBaseline? acceptedBase,
        IEnumerable<NativeGitOpsWorkloadObservation> observations,
        IEnumerable<NativeGitOpsRetirementEvidence> retirementEvidence,
        NativeGitOpsRollbackTarget? rollbackTarget,
        long minimumFreshnessSequence)
    {
        ArgumentNullException.ThrowIfNull(accepted);
        ArgumentNullException.ThrowIfNull(observations);
        ArgumentNullException.ThrowIfNull(retirementEvidence);
        var spec = NativeGitOpsCellPayload.Parse(accepted);
        var observed = Capture(observations, NativeGitOpsManifest.MaximumWorkloads);
        var retirements = Capture(retirementEvidence, NativeGitOpsManifest.MaximumWorkloads);
        if (minimumFreshnessSequence <= 0 || !ValidObservations(observed) || !ValidRetirements(retirements) ||
            observed.Select(static value => value.WorkloadId).Distinct(StringComparer.Ordinal).Count() != observed.Length ||
            retirements.Select(static value => value.WorkloadId).Distinct(StringComparer.Ordinal).Count() != retirements.Length)
            return Hold(NativeGitOpsCellConvergenceHoldReason.InvalidObservation);
        if (!ValidBaseline(spec, acceptedBase))
            return Hold(NativeGitOpsCellConvergenceHoldReason.AcceptedBaseMismatch);

        var known = spec.DesiredWorkloads.Select(static value => value.Id)
            .Concat(spec.Changes.Where(static value => value.Kind == NativeGitOpsChangeKind.GuardedRetirement)
                .Select(static value => value.WorkloadId))
            .ToHashSet(StringComparer.Ordinal);
        if (observed.Any(value => !known.Contains(value.WorkloadId)) ||
            retirements.Any(value => !known.Contains(value.WorkloadId)))
            return Hold(NativeGitOpsCellConvergenceHoldReason.ForeignOwnership);

        var byId = observed.ToDictionary(static value => value.WorkloadId, StringComparer.Ordinal);
        var active = spec.DesiredWorkloads.Where(static value => !value.Suspended).ToArray();
        var activeDecision = Active(spec, active, byId, rollbackTarget, minimumFreshnessSequence);
        if (activeDecision is not null) return activeDecision;

        var stopping = spec.Changes.Where(static value => value.Kind is
                NativeGitOpsChangeKind.Suspend or NativeGitOpsChangeKind.GuardedRetirement)
            .Select(static value => value.WorkloadId)
            .Concat(spec.DesiredWorkloads.Reverse().Where(static value => value.Suspended)
                .Select(static value => value.Id))
            .Distinct(StringComparer.Ordinal);
        var changes = spec.Changes.ToDictionary(static value => value.WorkloadId, StringComparer.Ordinal);
        var desired = spec.DesiredWorkloads.ToDictionary(static value => value.Id, StringComparer.Ordinal);
        var evidence = retirements.ToDictionary(static value => value.WorkloadId, StringComparer.Ordinal);
        foreach (var item in retirements)
        {
            if (!changes.TryGetValue(item.WorkloadId, out var change) ||
                change.Kind != NativeGitOpsChangeKind.GuardedRetirement ||
                !ValidRetirement(item, accepted, spec, change))
                return Hold(NativeGitOpsCellConvergenceHoldReason.RetirementProofMismatch);
        }
        foreach (var workloadId in stopping)
        {
            if (changes.TryGetValue(workloadId, out var change) &&
                change.Kind == NativeGitOpsChangeKind.GuardedRetirement)
            {
                var retirement = Retirement(
                    accepted,
                    spec,
                    change,
                    byId.GetValueOrDefault(workloadId),
                    evidence.GetValueOrDefault(workloadId),
                    minimumFreshnessSequence);
                if (retirement is not null) return retirement;
                continue;
            }
            var suspension = Suspend(
                spec,
                desired[workloadId],
                byId.GetValueOrDefault(workloadId),
                minimumFreshnessSequence);
            if (suspension is not null) return suspension;
        }

        return Complete(accepted, observed);
    }

    private static NativeGitOpsCellConvergenceDecision? Active(
        NativeGitOpsParsedCellSpec spec,
        IReadOnlyList<NativeGitOpsWorkloadPlan> active,
        IReadOnlyDictionary<string, NativeGitOpsWorkloadObservation> observed,
        NativeGitOpsRollbackTarget? rollbackTarget,
        long minimumFreshnessSequence)
    {
        if (active.Count == 0) return null;
        foreach (var workload in active)
        {
            if (!observed.TryGetValue(workload.Id, out var observation)) continue;
            if (observation.Ownership != NativeGitOpsWorkloadOwnership.NativeGitOpsParent &&
                observation.State != NativeGitOpsWorkloadState.Absent)
                return Hold(NativeGitOpsCellConvergenceHoldReason.ForeignOwnership);
            if (observation.State == NativeGitOpsWorkloadState.Absent) continue;
            var desiredDigest = NativeGitOpsCellSpecCompiler.WorkloadDigest(workload);
            if (observation.Generation > spec.Generation)
                return Hold(NativeGitOpsCellConvergenceHoldReason.FutureGeneration);
            if (observation.Generation == spec.Generation && observation.WorkloadSha256 != desiredDigest)
                return Hold(NativeGitOpsCellConvergenceHoldReason.SameGenerationConflict);
        }
        var desired = active.Select(workload => new DesiredResource(
            new(workload.Id),
            workload.Role.ToString(),
            spec.Generation,
            NativeGitOpsCellSpecCompiler.WorkloadDigest(workload),
            workload.DependsOn.Select(static dependency => new ResourceIdentity(dependency)))).ToArray();
        var usable = active.Select(workload => observed.GetValueOrDefault(workload.Id))
            .Where(value => value is not null && value.FreshnessSequence >= minimumFreshnessSequence &&
                value.State is NativeGitOpsWorkloadState.Healthy or NativeGitOpsWorkloadState.Unhealthy)
            .Select(value => new ObservedResourceState(
                new(value!.WorkloadId),
                active.Single(workload => workload.Id == value.WorkloadId).Role.ToString(),
                value.Generation,
                value.WorkloadSha256!,
                value.EvidenceSha256,
                value.FreshnessSequence,
                value.State == NativeGitOpsWorkloadState.Healthy ||
                value.Generation != spec.Generation ||
                value.WorkloadSha256 != NativeGitOpsCellSpecCompiler.WorkloadDigest(
                    active.Single(workload => workload.Id == value.WorkloadId))
                    ? ObservedCondition.Ready
                    : ObservedCondition.Failed))
            .ToArray();
        var policy = new ReconciliationPolicy(
            active.Select(static value => value.Role.ToString()).Distinct(StringComparer.Ordinal),
            new Dictionary<ResourceIdentity, long>(),
            NativeGitOpsManifest.MaximumWorkloads,
            maximumIdentityLength: 63,
            maximumKindLength: 64,
            maximumDigestLength: 64,
            maximumObservationIdLength: 64,
            NativeGitOpsManifest.MaximumDependenciesPerWorkload,
            minimumFreshnessSequence);
        var plan = ReconciliationEngine.Plan(new(desired, usable, policy));
        if (plan.Errors.Count != 0)
            return Hold(NativeGitOpsCellConvergenceHoldReason.ReconciliationRejected);
        foreach (var step in plan.Steps)
        {
            if (step.Output is ConvergedResource) continue;
            var workload = active.Single(value => value.Id == step.Desired.Identity.Value);
            observed.TryGetValue(workload.Id, out var observation);
            var digest = NativeGitOpsCellSpecCompiler.WorkloadDigest(workload);
            if (step.Output is ReconcileResourceIntent)
                return Intent(NativeGitOpsCellConvergenceIntentKind.Apply, spec.Generation, workload.Id, digest, observation);
            if (step.Output is ObserveResourceIntent)
            {
                if (observation is { FreshnessSequence: var sequence } && sequence >= minimumFreshnessSequence &&
                    observation.State is NativeGitOpsWorkloadState.Absent or NativeGitOpsWorkloadState.Suspended)
                    return Intent(NativeGitOpsCellConvergenceIntentKind.Apply, spec.Generation, workload.Id, digest, observation);
                return Intent(NativeGitOpsCellConvergenceIntentKind.Observe, spec.Generation, workload.Id, digest, observation);
            }
            var hold = (HoldResource)step.Output;
            if (hold.Reason == ReconciliationReasonCode.FailedObservation)
                return Rollback(spec, workload, observation!, rollbackTarget);
            return Hold(hold.Reason switch
            {
                ReconciliationReasonCode.FutureObservation => NativeGitOpsCellConvergenceHoldReason.FutureGeneration,
                ReconciliationReasonCode.ConflictingObservation => NativeGitOpsCellConvergenceHoldReason.SameGenerationConflict,
                _ => NativeGitOpsCellConvergenceHoldReason.ReconciliationRejected,
            });
        }
        return null;
    }

    private static NativeGitOpsCellConvergenceDecision? Suspend(
        NativeGitOpsParsedCellSpec spec,
        NativeGitOpsWorkloadPlan workload,
        NativeGitOpsWorkloadObservation? observation,
        long minimumFreshnessSequence)
    {
        var digest = NativeGitOpsCellSpecCompiler.WorkloadDigest(workload);
        if (observation is null || observation.FreshnessSequence < minimumFreshnessSequence)
            return Intent(NativeGitOpsCellConvergenceIntentKind.Observe, spec.Generation, workload.Id, digest, observation);
        if (observation.State == NativeGitOpsWorkloadState.Absent) return null;
        if (observation.Ownership != NativeGitOpsWorkloadOwnership.NativeGitOpsParent)
            return Hold(NativeGitOpsCellConvergenceHoldReason.ForeignOwnership);
        if (observation.Generation > spec.Generation)
            return Hold(NativeGitOpsCellConvergenceHoldReason.FutureGeneration);
        if (observation.Generation == spec.Generation && observation.WorkloadSha256 != digest)
            return Hold(NativeGitOpsCellConvergenceHoldReason.SameGenerationConflict);
        if (observation.State == NativeGitOpsWorkloadState.Suspended &&
            observation.Generation == spec.Generation && observation.WorkloadSha256 == digest)
            return null;
        return Intent(NativeGitOpsCellConvergenceIntentKind.Suspend, spec.Generation, workload.Id, digest, observation);
    }

    private static NativeGitOpsCellConvergenceDecision? Retirement(
        NativeGitOpsAcceptedCellSpec accepted,
        NativeGitOpsParsedCellSpec spec,
        NativeGitOpsParsedCellChange change,
        NativeGitOpsWorkloadObservation? observation,
        NativeGitOpsRetirementEvidence? evidence,
        long minimumFreshnessSequence)
    {
        var generation = spec.AcceptedGeneration!.Value;
        var digest = change.AcceptedWorkloadSha256!;
        if (observation is null || observation.FreshnessSequence < minimumFreshnessSequence)
            return Intent(NativeGitOpsCellConvergenceIntentKind.Observe, generation, change.WorkloadId, digest, observation);
        if (observation.State == NativeGitOpsWorkloadState.Absent) return null;
        if (observation.Ownership != NativeGitOpsWorkloadOwnership.NativeGitOpsParent)
            return Hold(NativeGitOpsCellConvergenceHoldReason.ForeignOwnership);
        if (observation.Generation != generation || observation.WorkloadSha256 != digest)
            return Hold(observation.Generation > generation
                ? NativeGitOpsCellConvergenceHoldReason.FutureGeneration
                : NativeGitOpsCellConvergenceHoldReason.SameGenerationConflict);
        if (evidence is null)
            return Intent(
                NativeGitOpsCellConvergenceIntentKind.AuthorizeRetirement,
                generation,
                change.WorkloadId,
                digest,
                observation);
        if (!ValidRetirement(evidence, accepted, spec, change))
            return Hold(NativeGitOpsCellConvergenceHoldReason.RetirementProofMismatch);
        return Intent(NativeGitOpsCellConvergenceIntentKind.Retire, generation, change.WorkloadId, digest, observation);
    }

    private static NativeGitOpsCellConvergenceDecision Rollback(
        NativeGitOpsParsedCellSpec spec,
        NativeGitOpsWorkloadPlan workload,
        NativeGitOpsWorkloadObservation observation,
        NativeGitOpsRollbackTarget? target)
    {
        if (target is null || target.QualifiedGeneration <= 0 || target.QualifiedGeneration >= spec.Generation ||
            !Digest(target.GlobalPlanDigest) || target.GlobalPlanDigest == spec.GlobalPlanDigest ||
            !Digest(target.QualificationProofSha256))
            return Hold(NativeGitOpsCellConvergenceHoldReason.FailedHealthWithoutRollback);
        return new(
            NativeGitOpsCellConvergenceState.Pending,
            NativeGitOpsCellConvergenceHoldReason.None,
            new(
                NativeGitOpsCellConvergenceIntentKind.RequestRollbackGeneration,
                workload.Id,
                spec.Generation,
                NativeGitOpsCellSpecCompiler.WorkloadDigest(workload),
                observation.EvidenceSha256,
                target),
            null);
    }

    private static NativeGitOpsCellConvergenceDecision Complete(
        NativeGitOpsAcceptedCellSpec accepted,
        IReadOnlyList<NativeGitOpsWorkloadObservation> observations)
    {
        var bytes = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(bytes))
        {
            writer.WriteStartObject();
            writer.WriteString("cell", accepted.Cell);
            writer.WriteNumber("generation", accepted.Generation);
            writer.WriteString("globalPlanDigest", accepted.GlobalPlanDigest);
            writer.WriteString("handoffDigest", accepted.HandoffDigest);
            writer.WriteString("payloadSha256", accepted.PayloadSha256);
            writer.WriteNumber("writerEpoch", accepted.WriterEpoch);
            writer.WriteNumber("acceptanceRevision", accepted.JournalRevision);
            writer.WriteStartArray("observations");
            foreach (var observation in observations.OrderBy(static value => value.WorkloadId, StringComparer.Ordinal))
            {
                writer.WriteStartObject();
                writer.WriteString("workloadId", observation.WorkloadId);
                writer.WriteNumber("generation", observation.Generation);
                if (observation.WorkloadSha256 is null) writer.WriteNull("workloadSha256");
                else writer.WriteString("workloadSha256", observation.WorkloadSha256);
                writer.WriteString("state", observation.State.ToString());
                writer.WriteString("ownership", observation.Ownership.ToString());
                writer.WriteNumber("freshnessSequence", observation.FreshnessSequence);
                writer.WriteString("evidenceSha256", observation.EvidenceSha256);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteEndObject();
        }
        return new(
            NativeGitOpsCellConvergenceState.Converged,
            NativeGitOpsCellConvergenceHoldReason.None,
            null,
            Convert.ToHexStringLower(SHA256.HashData(bytes.WrittenSpan)));
    }

    private static bool ValidBaseline(
        NativeGitOpsParsedCellSpec spec,
        NativeGitOpsAcceptedCellBaseline? baseline) => spec.AcceptedGeneration is null
        ? baseline is null
        : baseline is not null && baseline.Cell == spec.Cell && baseline.Generation == spec.AcceptedGeneration &&
            baseline.GlobalPlanDigest == spec.AcceptedGlobalPlanDigest;

    private static bool ValidObservations(IEnumerable<NativeGitOpsWorkloadObservation> values) => values.All(value =>
        value is not null && value.FreshnessSequence > 0 && Digest(value.EvidenceSha256) &&
        value.State is not NativeGitOpsWorkloadState.Unspecified &&
        (value.State == NativeGitOpsWorkloadState.Absent
            ? value.Generation == 0 && value.WorkloadSha256 is null &&
                value.Ownership == NativeGitOpsWorkloadOwnership.Unspecified
            : value.Generation > 0 && Digest(value.WorkloadSha256) &&
                value.Ownership is not NativeGitOpsWorkloadOwnership.Unspecified));

    private static bool ValidRetirements(IEnumerable<NativeGitOpsRetirementEvidence> values) => values.All(value =>
        value is not null && value.AcceptedGeneration > 0 && value.WriterEpoch > 0 &&
        Digest(value.AcceptedGlobalPlanDigest) && Digest(value.AcceptedWorkloadSha256) &&
        Digest(value.OwnershipProofSha256) && Digest(value.SafetyProofSha256) &&
        Digest(value.RetentionProofSha256) && Digest(value.DependencyProofSha256) &&
        Digest(value.DomainAuthorizationSha256));

    private static bool ValidRetirement(
        NativeGitOpsRetirementEvidence evidence,
        NativeGitOpsAcceptedCellSpec accepted,
        NativeGitOpsParsedCellSpec spec,
        NativeGitOpsParsedCellChange change) =>
        evidence.Cell == spec.Cell && evidence.WorkloadId == change.WorkloadId &&
        evidence.AcceptedGeneration == spec.AcceptedGeneration &&
        evidence.AcceptedGlobalPlanDigest == spec.AcceptedGlobalPlanDigest &&
        evidence.AcceptedWorkloadSha256 == change.AcceptedWorkloadSha256 &&
        evidence.WriterEpoch == accepted.WriterEpoch;

    private static NativeGitOpsCellConvergenceDecision Intent(
        NativeGitOpsCellConvergenceIntentKind kind,
        long generation,
        string workloadId,
        string workloadSha256,
        NativeGitOpsWorkloadObservation? observation) => new(
        NativeGitOpsCellConvergenceState.Pending,
        NativeGitOpsCellConvergenceHoldReason.None,
        new(kind, workloadId, generation, workloadSha256, observation?.EvidenceSha256, null),
        null);

    private static NativeGitOpsCellConvergenceDecision Hold(NativeGitOpsCellConvergenceHoldReason reason) => new(
        NativeGitOpsCellConvergenceState.Held,
        reason,
        null,
        null);

    private static T[] Capture<T>(IEnumerable<T> values, int maximum)
    {
        var captured = values.Take(maximum + 1).ToArray();
        return captured.Length <= maximum
            ? captured
            : throw new ArgumentException("The native GitOps convergence input exceeded its bound.");
    }

    private static bool Digest(string? value) => value is { Length: 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
}
