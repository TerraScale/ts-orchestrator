using System.Collections.ObjectModel;
using System.Text.RegularExpressions;

namespace TerraScale.Orchestrator.Scheduler.Availability;

internal static partial class AvailabilityIdentity
{
    public static string Validate(string value, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(value, parameterName);
        if (value.Length is < 1 or > 63 || !Pattern().IsMatch(value))
        {
            throw new ArgumentException("Identity must be a bounded canonical lowercase token.", parameterName);
        }

        return value;
    }

    [GeneratedRegex("^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$", RegexOptions.CultureInvariant)]
    private static partial Regex Pattern();
}

public sealed record ServiceId
{
    public ServiceId(string value) => Value = AvailabilityIdentity.Validate(value, nameof(value));
    public string Value { get; }
    public override string ToString() => Value;
}

public sealed record ReplicaId
{
    public ReplicaId(string value) => Value = AvailabilityIdentity.Validate(value, nameof(value));
    public string Value { get; }
    public override string ToString() => Value;
}

public sealed record AvailabilityNodeId
{
    public AvailabilityNodeId(string value) => Value = AvailabilityIdentity.Validate(value, nameof(value));
    public string Value { get; }
    public override string ToString() => Value;
}

public sealed record FailureDomainId
{
    public FailureDomainId(string value) => Value = AvailabilityIdentity.Validate(value, nameof(value));
    public string Value { get; }
    public override string ToString() => Value;
}

public sealed record AvailabilityCount
{
    public AvailabilityCount(ulong value) => Value = value;

    public ulong Value { get; }

    public AvailabilityCount AddChecked(AvailabilityCount other)
    {
        ArgumentNullException.ThrowIfNull(other);
        return new(checked(Value + other.Value));
    }

    public AvailabilityCount SubtractChecked(AvailabilityCount other)
    {
        ArgumentNullException.ThrowIfNull(other);
        return new(checked(Value - other.Value));
    }

    internal static AvailabilityCount FromInt32(int value) => new(checked((ulong)value));
}

public enum ServiceCriticality
{
    Ordinary = 1,
    Critical = 2,
}

public enum ReserveDisposition
{
    Preserve = 1,
    MayConsume = 2,
}

public sealed class ServiceAvailabilityPolicy
{
    public ServiceAvailabilityPolicy(
        ServiceId serviceId,
        AvailabilityCount desired,
        AvailabilityCount minimumAvailable,
        AvailabilityCount quorum,
        AvailabilityCount maximumConcurrentDisruptions,
        ServiceCriticality criticality,
        bool onePerHost,
        AvailabilityCount requiredDistinctFailureDomains,
        ResourceVector reserve,
        ReserveDisposition reserveDisposition)
    {
        ServiceId = serviceId ?? throw new ArgumentNullException(nameof(serviceId));
        Desired = desired ?? throw new ArgumentNullException(nameof(desired));
        MinimumAvailable = minimumAvailable ?? throw new ArgumentNullException(nameof(minimumAvailable));
        Quorum = quorum ?? throw new ArgumentNullException(nameof(quorum));
        MaximumConcurrentDisruptions = maximumConcurrentDisruptions ?? throw new ArgumentNullException(nameof(maximumConcurrentDisruptions));
        RequiredDistinctFailureDomains = requiredDistinctFailureDomains ?? throw new ArgumentNullException(nameof(requiredDistinctFailureDomains));
        Reserve = reserve ?? throw new ArgumentNullException(nameof(reserve));
        if (!Enum.IsDefined(criticality))
        {
            throw new ArgumentOutOfRangeException(nameof(criticality));
        }

        if (!Enum.IsDefined(reserveDisposition))
        {
            throw new ArgumentOutOfRangeException(nameof(reserveDisposition));
        }

        if (minimumAvailable.Value > desired.Value || quorum.Value > desired.Value ||
            maximumConcurrentDisruptions.Value > desired.Value || requiredDistinctFailureDomains.Value > desired.Value)
        {
            throw new ArgumentException("Minimum, quorum, disruption, and topology counts cannot exceed desired count.");
        }

        Criticality = criticality;
        OnePerHost = onePerHost;
        ReserveDisposition = reserveDisposition;
    }

    public ServiceId ServiceId { get; }
    public AvailabilityCount Desired { get; }
    public AvailabilityCount MinimumAvailable { get; }
    public AvailabilityCount Quorum { get; }
    public AvailabilityCount MaximumConcurrentDisruptions { get; }
    public ServiceCriticality Criticality { get; }
    public bool OnePerHost { get; }
    public AvailabilityCount RequiredDistinctFailureDomains { get; }
    public ResourceVector Reserve { get; }
    public ReserveDisposition ReserveDisposition { get; }
}

public enum ReplicaAvailabilityState
{
    Available = 1,
    Unavailable = 2,
    Disrupting = 3,
}

public sealed record ReplicaObservation
{
    public ReplicaObservation(
        ReplicaId replicaId,
        ServiceId serviceId,
        AvailabilityNodeId? nodeId,
        FailureDomainId? failureDomainId,
        ReplicaAvailabilityState state)
    {
        ReplicaId = replicaId ?? throw new ArgumentNullException(nameof(replicaId));
        ServiceId = serviceId ?? throw new ArgumentNullException(nameof(serviceId));
        NodeId = nodeId;
        FailureDomainId = failureDomainId;
        if (!Enum.IsDefined(state))
        {
            throw new ArgumentOutOfRangeException(nameof(state));
        }

        State = state;
    }

    public ReplicaId ReplicaId { get; }
    public ServiceId ServiceId { get; }
    public AvailabilityNodeId? NodeId { get; }
    public FailureDomainId? FailureDomainId { get; }
    public ReplicaAvailabilityState State { get; }

    internal string CanonicalKey =>
        $"{ReplicaId.Value}|{ServiceId.Value}|{NodeId?.Value ?? "-"}|{FailureDomainId?.Value ?? "-"}|{(int)State}";
}

public enum ObservationCompleteness
{
    Complete = 1,
    Incomplete = 2,
}

public abstract class AvailabilityChange
{
    internal AvailabilityChange() { }
}

public sealed class PlaceReplicaChange : AvailabilityChange
{
    public PlaceReplicaChange(
        ReplicaId replicaId,
        AvailabilityNodeId targetNodeId,
        FailureDomainId targetFailureDomainId,
        ResourceVector requestedResources,
        ResourceVector availableResources)
    {
        ReplicaId = replicaId ?? throw new ArgumentNullException(nameof(replicaId));
        TargetNodeId = targetNodeId ?? throw new ArgumentNullException(nameof(targetNodeId));
        TargetFailureDomainId = targetFailureDomainId ?? throw new ArgumentNullException(nameof(targetFailureDomainId));
        RequestedResources = requestedResources ?? throw new ArgumentNullException(nameof(requestedResources));
        AvailableResources = availableResources ?? throw new ArgumentNullException(nameof(availableResources));
    }

    public ReplicaId ReplicaId { get; }
    public AvailabilityNodeId TargetNodeId { get; }
    public FailureDomainId TargetFailureDomainId { get; }
    public ResourceVector RequestedResources { get; }
    public ResourceVector AvailableResources { get; }
}

public sealed class DrainNodeChange : AvailabilityChange
{
    public DrainNodeChange(AvailabilityNodeId nodeId) =>
        NodeId = nodeId ?? throw new ArgumentNullException(nameof(nodeId));

    public AvailabilityNodeId NodeId { get; }
}

public sealed class MaintainReplicaChange : AvailabilityChange
{
    public MaintainReplicaChange(ReplicaId replicaId) =>
        ReplicaId = replicaId ?? throw new ArgumentNullException(nameof(replicaId));

    public ReplicaId ReplicaId { get; }
}

public sealed class AvailabilityEvaluationRequest
{
    public AvailabilityEvaluationRequest(
        ServiceAvailabilityPolicy policy,
        AvailabilityChange change,
        ObservationCompleteness observationCompleteness,
        IEnumerable<ReplicaObservation> observations)
    {
        Policy = policy ?? throw new ArgumentNullException(nameof(policy));
        Change = change ?? throw new ArgumentNullException(nameof(change));
        if (!Enum.IsDefined(observationCompleteness))
        {
            throw new ArgumentOutOfRangeException(nameof(observationCompleteness));
        }

        ArgumentNullException.ThrowIfNull(observations);
        var copy = SchedulerInputSnapshot.Copy(observations,SchedulerTechnicalInputLimits.MaximumAvailabilityObservationCount,nameof(observations),"Availability observation input");
        if (copy.Any(observation => observation is null))
        {
            throw new ArgumentException("Observations cannot contain null.", nameof(observations));
        }

        ObservationCompleteness = observationCompleteness;
        Observations = new ReadOnlyCollection<ReplicaObservation>(copy);
    }

    public ServiceAvailabilityPolicy Policy { get; }
    public AvailabilityChange Change { get; }
    public ObservationCompleteness ObservationCompleteness { get; }
    public IReadOnlyList<ReplicaObservation> Observations { get; }
}

public enum AvailabilityReasonCode
{
    ObservationSetComplete = 1,
    ReplicaObservationsUnique,
    ReplicaObservationsConsistent,
    ReplicaIdentitiesComplete,
    ServiceIdentityConsistent,
    ChangeTargetValid,
    DesiredCount,
    MinimumAvailable,
    Quorum,
    DisruptionBudget,
    OnePerHost,
    FailureDomainSpread,
    ReserveCpu,
    ReserveMemory,
    ReserveBlockIo,
    ReserveEphemeralDisk,
    ReserveBandwidth,
    ReservePids,
    ReserveFileDescriptors,
    ReserveHugePages,
    CapacityCpu,
    CapacityMemory,
    CapacityBlockIo,
    CapacityEphemeralDisk,
    CapacityBandwidth,
    CapacityPids,
    CapacityFileDescriptors,
    CapacityHugePages,
}

public enum AvailabilityReasonOutcome
{
    Passed = 1,
    Rejected,
    Held,
    NotApplicable,
}

public sealed record AvailabilityReason
{
    internal AvailabilityReason(
        AvailabilityReasonCode code,
        AvailabilityReasonOutcome outcome,
        ulong observed,
        ulong required)
    {
        if (!Enum.IsDefined(code) || !Enum.IsDefined(outcome))
        {
            throw new ArgumentOutOfRangeException(nameof(code), "Trace codes and outcomes must be known.");
        }

        Code = code;
        Outcome = outcome;
        Observed = observed;
        Required = required;
    }

    public AvailabilityReasonCode Code { get; }
    public AvailabilityReasonOutcome Outcome { get; }
    public ulong Observed { get; }
    public ulong Required { get; }
}

public sealed record AvailabilityDecision
{
    internal AvailabilityDecision(bool admitted, IReadOnlyList<AvailabilityReason> trace)
    {
        Admitted = admitted;
        Trace = trace ?? throw new ArgumentNullException(nameof(trace));
    }

    public bool Admitted { get; }
    public IReadOnlyList<AvailabilityReason> Trace { get; }
}
