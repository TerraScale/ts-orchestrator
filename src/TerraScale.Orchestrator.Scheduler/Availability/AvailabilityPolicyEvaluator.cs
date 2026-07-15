using System.Collections.ObjectModel;

namespace TerraScale.Orchestrator.Scheduler.Availability;

/// <summary>
/// Pure explicit-input availability policy. It never infers stateful safety or
/// product/project geography (INV-013) and emits no caller free text.
/// </summary>
public sealed class AvailabilityPolicyEvaluator
{
    public AvailabilityDecision Evaluate(AvailabilityEvaluationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var observations = request.Observations
            .OrderBy(observation => observation.ReplicaId.Value, StringComparer.Ordinal)
            .ThenBy(observation => observation.CanonicalKey, StringComparer.Ordinal)
            .ToArray();
        var groups = observations.GroupBy(observation => observation.ReplicaId.Value, StringComparer.Ordinal).ToArray();
        var duplicateCount = groups.Where(group => group.Count() > 1)
            .Aggregate(0, (total, group) => checked(total + group.Count() - 1));
        var conflictCount = groups.Count(group => group.Select(observation => observation.CanonicalKey)
            .Distinct(StringComparer.Ordinal).Skip(1).Any());
        var missingIdentityCount = observations.Count(observation => observation.NodeId is null || observation.FailureDomainId is null);
        var wrongServiceCount = observations.Count(observation => observation.ServiceId != request.Policy.ServiceId);
        var trace = new List<AvailabilityReason>(28)
        {
            Reason(AvailabilityReasonCode.ObservationSetComplete,
                request.ObservationCompleteness == ObservationCompleteness.Complete,
                request.ObservationCompleteness == ObservationCompleteness.Complete ? 1UL : 0UL, 1),
            Reason(AvailabilityReasonCode.ReplicaObservationsUnique, duplicateCount == 0, checked((ulong)duplicateCount), 0),
            Reason(AvailabilityReasonCode.ReplicaObservationsConsistent, conflictCount == 0, checked((ulong)conflictCount), 0),
            Reason(AvailabilityReasonCode.ReplicaIdentitiesComplete, missingIdentityCount == 0, checked((ulong)missingIdentityCount), 0),
            Reason(AvailabilityReasonCode.ServiceIdentityConsistent, wrongServiceCount == 0, checked((ulong)wrongServiceCount), 0),
        };

        var generationTrace = new[]
        {
            Reason(
                AvailabilityReasonCode.ObservationGenerationNotRollback,
                request.ObservationGeneration.Value >= request.CurrentAcceptedObservationGeneration.Value,
                request.ObservationGeneration.Value,
                request.CurrentAcceptedObservationGeneration.Value),
            Reason(
                AvailabilityReasonCode.ObservationGenerationNotFuture,
                request.ObservationGeneration.Value <= request.CurrentAcceptedObservationGeneration.Value,
                request.ObservationGeneration.Value,
                request.CurrentAcceptedObservationGeneration.Value),
        };

        var held = trace.Concat(generationTrace)
            .Any(reason => reason.Outcome is AvailabilityReasonOutcome.Held);
        var unique = groups.Select(group => group.First()).ToArray();
        var target = EvaluateTarget(request.Change, unique, held);
        trace.Add(target.Reason);

        if (held || target.Reason.Outcome != AvailabilityReasonOutcome.Passed)
        {
            AddUnavailablePolicyTrace(trace, held ? AvailabilityReasonOutcome.Held : AvailabilityReasonOutcome.NotApplicable);
            return Decision(request, trace, generationTrace);
        }

        var available = unique.Where(observation => observation.State == ReplicaAvailabilityState.Available).ToArray();
        var disrupting = unique.Count(observation => observation.State == ReplicaAvailabilityState.Disrupting);
        var projectedAvailable = AvailabilityCount.FromInt32(available.Length);
        var projectedDisrupting = AvailabilityCount.FromInt32(disrupting);
        var projectedReplicaCount = AvailabilityCount.FromInt32(unique.Length);
        IReadOnlyList<ReplicaObservation> availableTopologyReplicas = available;
        IReadOnlyList<ReplicaObservation> antiAffinityReplicas = unique;

        switch (request.Change)
        {
            case PlaceReplicaChange placement:
                projectedReplicaCount = projectedReplicaCount.AddChecked(new(1));
                projectedAvailable = projectedAvailable.AddChecked(new(1));
                var planned = new ReplicaObservation(
                    placement.ReplicaId,
                    request.Policy.ServiceId,
                    placement.TargetNodeId,
                    placement.TargetFailureDomainId,
                    ReplicaAvailabilityState.Available);
                availableTopologyReplicas = available.Append(planned).ToArray();
                antiAffinityReplicas = unique.Append(planned).ToArray();
                break;
            case MaintainReplicaChange maintenance:
            {
                var affected = unique.Single(observation => observation.ReplicaId == maintenance.ReplicaId);
                if (affected.State == ReplicaAvailabilityState.Available)
                {
                    projectedAvailable = projectedAvailable.SubtractChecked(new(1));
                    projectedDisrupting = projectedDisrupting.AddChecked(new(1));
                }

                availableTopologyReplicas = availableTopologyReplicas
                    .Where(observation => observation.ReplicaId != maintenance.ReplicaId).ToArray();
                break;
            }
            case DrainNodeChange drain:
            {
                var newlyDisrupted = available.Count(observation => observation.NodeId == drain.NodeId);
                projectedAvailable = projectedAvailable.SubtractChecked(AvailabilityCount.FromInt32(newlyDisrupted));
                projectedDisrupting = projectedDisrupting.AddChecked(AvailabilityCount.FromInt32(newlyDisrupted));
                availableTopologyReplicas = availableTopologyReplicas
                    .Where(observation => observation.NodeId != drain.NodeId).ToArray();
                antiAffinityReplicas = antiAffinityReplicas
                    .Where(observation => observation.NodeId != drain.NodeId).ToArray();
                break;
            }
        }

        trace.Add(RejectReason(AvailabilityReasonCode.DesiredCount,
            projectedReplicaCount.Value <= request.Policy.Desired.Value,
            projectedReplicaCount.Value, request.Policy.Desired.Value));
        trace.Add(RejectReason(AvailabilityReasonCode.MinimumAvailable,
            projectedAvailable.Value >= request.Policy.MinimumAvailable.Value,
            projectedAvailable.Value, request.Policy.MinimumAvailable.Value));
        trace.Add(RejectReason(AvailabilityReasonCode.Quorum,
            projectedAvailable.Value >= request.Policy.Quorum.Value,
            projectedAvailable.Value, request.Policy.Quorum.Value));
        trace.Add(RejectReason(AvailabilityReasonCode.DisruptionBudget,
            projectedDisrupting.Value <= request.Policy.MaximumConcurrentDisruptions.Value,
            projectedDisrupting.Value, request.Policy.MaximumConcurrentDisruptions.Value));

        var hostGroups = antiAffinityReplicas.Where(observation => observation.NodeId is not null)
            .GroupBy(observation => observation.NodeId!.Value, StringComparer.Ordinal);
        var colocated = hostGroups.Aggregate(0,
            (total, group) => checked(total + Math.Max(0, group.Count() - 1)));
        trace.Add(request.Policy.OnePerHost
            ? RejectReason(AvailabilityReasonCode.OnePerHost, colocated == 0, checked((ulong)colocated), 0)
            : NotApplicable(AvailabilityReasonCode.OnePerHost));

        var distinctDomains = availableTopologyReplicas.Where(observation => observation.FailureDomainId is not null)
            .Select(observation => observation.FailureDomainId!.Value).Distinct(StringComparer.Ordinal).Count();
        trace.Add(RejectReason(AvailabilityReasonCode.FailureDomainSpread,
            checked((ulong)distinctDomains) >= request.Policy.RequiredDistinctFailureDomains.Value,
            checked((ulong)distinctDomains), request.Policy.RequiredDistinctFailureDomains.Value));

        AddResourceTrace(trace, request.Change, request.Policy);
        return Decision(request, trace, generationTrace);
    }

    private static TargetResult EvaluateTarget(AvailabilityChange change, ReplicaObservation[] observations, bool held)
    {
        if (held)
        {
            return new(new(AvailabilityReasonCode.ChangeTargetValid, AvailabilityReasonOutcome.Held, 0, 1));
        }

        return change switch
        {
            PlaceReplicaChange placement => new(RejectReason(AvailabilityReasonCode.ChangeTargetValid,
                observations.All(observation => observation.ReplicaId != placement.ReplicaId),
                observations.Any(observation => observation.ReplicaId == placement.ReplicaId) ? 0UL : 1UL, 1)),
            MaintainReplicaChange maintenance => MaintainTarget(
                observations.Where(observation => observation.ReplicaId == maintenance.ReplicaId).ToArray()),
            DrainNodeChange drain => TargetCount(
                observations.Count(observation => observation.NodeId == drain.NodeId)),
            _ => throw new ArgumentOutOfRangeException(nameof(change)),
        };
    }

    private static TargetResult TargetCount(int count) => new(RejectReason(
        AvailabilityReasonCode.ChangeTargetValid, count > 0, checked((ulong)count), 1));

    private static TargetResult MaintainTarget(ReplicaObservation[] matches)
    {
        var valid = matches.Length == 1 && matches[0].State == ReplicaAvailabilityState.Available;
        return new(RejectReason(AvailabilityReasonCode.ChangeTargetValid,
            valid, valid ? 1UL : 0UL, 1));
    }

    private static void AddResourceTrace(
        ICollection<AvailabilityReason> trace,
        AvailabilityChange change,
        ServiceAvailabilityPolicy policy)
    {
        if (change is not PlaceReplicaChange placement)
        {
            foreach (var code in ReserveCodes)
            {
                trace.Add(NotApplicable(code));
            }

            foreach (var code in CapacityCodes)
            {
                trace.Add(NotApplicable(code));
            }

            return;
        }

        var available = placement.AvailableResources.OrderedValues().ToArray();
        var requested = placement.RequestedResources.OrderedValues().ToArray();
        var reserve = policy.Reserve.OrderedValues().ToArray();

        if (policy.ReserveDisposition == ReserveDisposition.MayConsume)
        {
            foreach (var code in ReserveCodes)
            {
                trace.Add(NotApplicable(code));
            }
        }
        else
        {
            for (var index = 0; index < available.Length; index++)
            {
                var canSubtract = available[index].Value >= requested[index].Value;
                var remaining = canSubtract ? checked(available[index].Value - requested[index].Value) : 0;
                var passes = canSubtract && remaining >= reserve[index].Value;
                trace.Add(RejectReason(ReserveCodes[index], passes,
                    checked((ulong)remaining), checked((ulong)reserve[index].Value)));
            }
        }

        for (var index = 0; index < available.Length; index++)
        {
            trace.Add(RejectReason(CapacityCodes[index],
                available[index].Value >= requested[index].Value,
                checked((ulong)available[index].Value),
                checked((ulong)requested[index].Value)));
        }
    }

    private static void AddUnavailablePolicyTrace(
        ICollection<AvailabilityReason> trace,
        AvailabilityReasonOutcome outcome)
    {
        foreach (var code in PolicyReasonCodes)
        {
            trace.Add(new(code, outcome, 0, 0));
        }
    }

    private static AvailabilityDecision Decision(
        AvailabilityEvaluationRequest request,
        List<AvailabilityReason> trace,
        IReadOnlyCollection<AvailabilityReason> generationTrace)
    {
        trace.AddRange(generationTrace);
        var admitted = trace.All(reason => reason.Outcome is AvailabilityReasonOutcome.Passed or AvailabilityReasonOutcome.NotApplicable);
        return new(admitted ? request : null, new ReadOnlyCollection<AvailabilityReason>(trace));
    }

    private static AvailabilityReason Reason(AvailabilityReasonCode code, bool passes, ulong observed, ulong required) =>
        new(code, passes ? AvailabilityReasonOutcome.Passed : AvailabilityReasonOutcome.Held, observed, required);

    private static AvailabilityReason RejectReason(AvailabilityReasonCode code, bool passes, ulong observed, ulong required) =>
        new(code, passes ? AvailabilityReasonOutcome.Passed : AvailabilityReasonOutcome.Rejected, observed, required);

    private static AvailabilityReason NotApplicable(AvailabilityReasonCode code) =>
        new(code, AvailabilityReasonOutcome.NotApplicable, 0, 0);

    private static AvailabilityReasonCode[] ReserveCodes { get; } =
    [
        AvailabilityReasonCode.ReserveCpu,
        AvailabilityReasonCode.ReserveMemory,
        AvailabilityReasonCode.ReserveBlockIo,
        AvailabilityReasonCode.ReserveEphemeralDisk,
        AvailabilityReasonCode.ReserveBandwidth,
        AvailabilityReasonCode.ReservePids,
        AvailabilityReasonCode.ReserveFileDescriptors,
        AvailabilityReasonCode.ReserveHugePages,
    ];

    private static AvailabilityReasonCode[] CapacityCodes { get; } =
    [
        AvailabilityReasonCode.CapacityCpu,
        AvailabilityReasonCode.CapacityMemory,
        AvailabilityReasonCode.CapacityBlockIo,
        AvailabilityReasonCode.CapacityEphemeralDisk,
        AvailabilityReasonCode.CapacityBandwidth,
        AvailabilityReasonCode.CapacityPids,
        AvailabilityReasonCode.CapacityFileDescriptors,
        AvailabilityReasonCode.CapacityHugePages,
    ];

    private static AvailabilityReasonCode[] PolicyReasonCodes { get; } =
    [
        AvailabilityReasonCode.DesiredCount,
        AvailabilityReasonCode.MinimumAvailable,
        AvailabilityReasonCode.Quorum,
        AvailabilityReasonCode.DisruptionBudget,
        AvailabilityReasonCode.OnePerHost,
        AvailabilityReasonCode.FailureDomainSpread,
        .. ReserveCodes,
        .. CapacityCodes,
    ];

    private sealed record TargetResult(AvailabilityReason Reason);
}
