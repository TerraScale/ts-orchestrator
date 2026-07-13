using System.Collections.Frozen;
using System.Collections.ObjectModel;
using System.Numerics;

namespace TerraScale.Orchestrator.Scheduler;

/// <summary>
/// Non-negative quantities in scheduler-defined base units. Callers are responsible
/// for using the same unit for available and requested values in each dimension.
/// </summary>
public sealed record ResourceVector
{
    public ResourceVector(
        long cpu,
        long memory,
        long blockIo,
        long ephemeralDisk,
        long bandwidth,
        long pids,
        long fileDescriptors,
        long hugePages)
    {
        Cpu = RequireNonNegative(cpu, nameof(cpu));
        Memory = RequireNonNegative(memory, nameof(memory));
        BlockIo = RequireNonNegative(blockIo, nameof(blockIo));
        EphemeralDisk = RequireNonNegative(ephemeralDisk, nameof(ephemeralDisk));
        Bandwidth = RequireNonNegative(bandwidth, nameof(bandwidth));
        Pids = RequireNonNegative(pids, nameof(pids));
        FileDescriptors = RequireNonNegative(fileDescriptors, nameof(fileDescriptors));
        HugePages = RequireNonNegative(hugePages, nameof(hugePages));
    }

    public long Cpu { get; }

    public long Memory { get; }

    public long BlockIo { get; }

    public long EphemeralDisk { get; }

    public long Bandwidth { get; }

    public long Pids { get; }

    public long FileDescriptors { get; }

    public long HugePages { get; }

    public static ResourceVector Zero { get; } = new(0, 0, 0, 0, 0, 0, 0, 0);

    public ResourceVector AddChecked(ResourceVector other)
    {
        ArgumentNullException.ThrowIfNull(other);
        checked
        {
            return new(
                Cpu + other.Cpu,
                Memory + other.Memory,
                BlockIo + other.BlockIo,
                EphemeralDisk + other.EphemeralDisk,
                Bandwidth + other.Bandwidth,
                Pids + other.Pids,
                FileDescriptors + other.FileDescriptors,
                HugePages + other.HugePages);
        }
    }

    public ResourceVector SubtractChecked(ResourceVector other)
    {
        ArgumentNullException.ThrowIfNull(other);
        checked
        {
            return new(
                Cpu - other.Cpu,
                Memory - other.Memory,
                BlockIo - other.BlockIo,
                EphemeralDisk - other.EphemeralDisk,
                Bandwidth - other.Bandwidth,
                Pids - other.Pids,
                FileDescriptors - other.FileDescriptors,
                HugePages - other.HugePages);
        }
    }

    internal IEnumerable<(ResourceDimension Dimension, long Value)> OrderedValues()
    {
        yield return (ResourceDimension.Cpu, Cpu);
        yield return (ResourceDimension.Memory, Memory);
        yield return (ResourceDimension.BlockIo, BlockIo);
        yield return (ResourceDimension.EphemeralDisk, EphemeralDisk);
        yield return (ResourceDimension.Bandwidth, Bandwidth);
        yield return (ResourceDimension.Pids, Pids);
        yield return (ResourceDimension.FileDescriptors, FileDescriptors);
        yield return (ResourceDimension.HugePages, HugePages);
    }

    private static long RequireNonNegative(long value, string parameterName) =>
        value >= 0 ? value : throw new ArgumentOutOfRangeException(parameterName, value, "Resource quantities must be non-negative.");
}

public enum ResourceDimension
{
    Cpu,
    Memory,
    BlockIo,
    EphemeralDisk,
    Bandwidth,
    Pids,
    FileDescriptors,
    HugePages,
}

public sealed record CandidateVeto
{
    public CandidateVeto(string code, string detail)
    {
        Code = RequireText(code, nameof(code));
        Detail = RequireText(detail, nameof(detail));
    }

    public string Code { get; }

    public string Detail { get; }

    private static string RequireText(string value, string parameterName) =>
        !string.IsNullOrWhiteSpace(value) ? value : throw new ArgumentException("A nonempty value is required.", parameterName);
}

public sealed record AllocationSafetyCap
{
    public AllocationSafetyCap(long currentAllocations, long maximumAllocations)
    {
        if (currentAllocations < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(currentAllocations));
        }

        if (maximumAllocations < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumAllocations));
        }

        CurrentAllocations = currentAllocations;
        MaximumAllocations = maximumAllocations;
    }

    public long CurrentAllocations { get; }

    public long MaximumAllocations { get; }

    public bool CanAdmit => CurrentAllocations < MaximumAllocations;
}

public sealed record ScoreDimension
{
    public ScoreDimension(ResourceDimension dimension, long weight)
    {
        if (weight < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(weight));
        }

        Dimension = dimension;
        Weight = weight;
    }

    public ResourceDimension Dimension { get; }

    public long Weight { get; }
}

/// <summary>
/// Caller-owned least-waste policy. All dimensions must appear exactly once. List
/// order is the exact component tie-break order after weighted waste.
/// </summary>
public sealed class LeastWastePolicy
{
    public LeastWastePolicy(IEnumerable<ScoreDimension> dimensions)
    {
        ArgumentNullException.ThrowIfNull(dimensions);
        var copy = dimensions.ToArray();
        if (copy.Any(item => item is null))
        {
            throw new ArgumentException("Score dimensions cannot contain null.", nameof(dimensions));
        }

        var expected = Enum.GetValues<ResourceDimension>();
        if (copy.Length != expected.Length ||
            copy.Select(item => item.Dimension).Distinct().Count() != expected.Length ||
            expected.Any(dimension => copy.All(item => item.Dimension != dimension)))
        {
            throw new ArgumentException("Every resource dimension must appear exactly once.", nameof(dimensions));
        }

        if (copy.All(item => item.Weight == 0))
        {
            throw new ArgumentException("At least one score weight must be positive.", nameof(dimensions));
        }

        Dimensions = new ReadOnlyCollection<ScoreDimension>(copy);
    }

    public IReadOnlyList<ScoreDimension> Dimensions { get; }
}

public sealed class NodeCandidate
{
    public NodeCandidate(
        string id,
        string nodeClass,
        string architecture,
        string failureDomain,
        ResourceVector available,
        IEnumerable<int>? occupiedPorts = null,
        IReadOnlyDictionary<string, string>? labels = null,
        IEnumerable<string>? trustZones = null,
        IEnumerable<string>? networkZones = null,
        IEnumerable<string>? secretZones = null,
        IEnumerable<string>? affinityFacts = null,
        AllocationSafetyCap? safetyCap = null,
        CandidateVeto? veto = null)
    {
        Id = RequireText(id, nameof(id));
        NodeClass = RequireText(nodeClass, nameof(nodeClass));
        Architecture = RequireText(architecture, nameof(architecture));
        FailureDomain = RequireText(failureDomain, nameof(failureDomain));
        Available = available ?? throw new ArgumentNullException(nameof(available));
        OccupiedPorts = CopyPorts(occupiedPorts, nameof(occupiedPorts));
        Labels = CopyLabels(labels, nameof(labels));
        TrustZones = CopyFacts(trustZones);
        NetworkZones = CopyFacts(networkZones);
        SecretZones = CopyFacts(secretZones);
        AffinityFacts = CopyFacts(affinityFacts);
        SafetyCap = safetyCap;
        Veto = veto;
    }

    public string Id { get; }

    public string NodeClass { get; }

    public string Architecture { get; }

    public string FailureDomain { get; }

    public ResourceVector Available { get; }

    public IReadOnlySet<int> OccupiedPorts { get; }

    public IReadOnlyDictionary<string, string> Labels { get; }

    public IReadOnlySet<string> TrustZones { get; }

    public IReadOnlySet<string> NetworkZones { get; }

    public IReadOnlySet<string> SecretZones { get; }

    public IReadOnlySet<string> AffinityFacts { get; }

    public AllocationSafetyCap? SafetyCap { get; }

    public CandidateVeto? Veto { get; }

    private static FrozenSet<int> CopyPorts(IEnumerable<int>? ports, string parameterName)
    {
        var values = (ports ?? []).ToArray();
        if (values.Length != values.Distinct().Count())
        {
            throw new ArgumentException("Port collections cannot contain duplicates.", parameterName);
        }

        if (values.Any(port => port is < 1 or > 65535))
        {
            throw new ArgumentOutOfRangeException(parameterName, "Ports must be between 1 and 65535.");
        }

        return values.ToFrozenSet();
    }

    private static FrozenSet<string> CopyFacts(IEnumerable<string>? facts)
    {
        var values = (facts ?? []).ToArray();
        if (values.Any(string.IsNullOrWhiteSpace))
        {
            throw new ArgumentException("Facts and zone names must be nonempty.", nameof(facts));
        }

        if (values.Length != values.Distinct(StringComparer.Ordinal).Count())
        {
            throw new ArgumentException("Facts and zone names cannot contain duplicates.", nameof(facts));
        }

        return values.ToFrozenSet(StringComparer.Ordinal);
    }

    private static FrozenDictionary<string, string> CopyLabels(
        IReadOnlyDictionary<string, string>? labels,
        string parameterName)
    {
        var source = labels ?? new Dictionary<string, string>();
        if (source.Any(label => string.IsNullOrWhiteSpace(label.Key) || string.IsNullOrWhiteSpace(label.Value)))
        {
            throw new ArgumentException("Label keys and values must be nonempty.", parameterName);
        }

        return source.ToFrozenDictionary(StringComparer.Ordinal);
    }

    private static string RequireText(string value, string parameterName) =>
        !string.IsNullOrWhiteSpace(value) ? value : throw new ArgumentException("A nonempty value is required.", parameterName);
}

public sealed class WorkloadRequest
{
    public WorkloadRequest(
        string id,
        string architecture,
        ResourceVector resources,
        IEnumerable<int>? requiredPorts = null,
        string? requiredNodeClass = null,
        IReadOnlyDictionary<string, string>? requiredLabels = null,
        IEnumerable<string>? requiredTrustZones = null,
        IEnumerable<string>? requiredNetworkZones = null,
        IEnumerable<string>? requiredSecretZones = null,
        IEnumerable<string>? allowedFailureDomains = null,
        IEnumerable<string>? requiredAffinityFacts = null,
        IEnumerable<string>? prohibitedAffinityFacts = null)
    {
        Id = RequireText(id, nameof(id));
        Architecture = RequireText(architecture, nameof(architecture));
        Resources = resources ?? throw new ArgumentNullException(nameof(resources));
        RequiredPorts = CopyPorts(requiredPorts);
        RequiredNodeClass = string.IsNullOrWhiteSpace(requiredNodeClass) ? null : requiredNodeClass;
        RequiredLabels = CopyLabels(requiredLabels);
        RequiredTrustZones = CopyFacts(requiredTrustZones);
        RequiredNetworkZones = CopyFacts(requiredNetworkZones);
        RequiredSecretZones = CopyFacts(requiredSecretZones);
        AllowedFailureDomains = CopyFacts(allowedFailureDomains);
        RequiredAffinityFacts = CopyFacts(requiredAffinityFacts);
        ProhibitedAffinityFacts = CopyFacts(prohibitedAffinityFacts);
    }

    public string Id { get; }

    public string Architecture { get; }

    public ResourceVector Resources { get; }

    public IReadOnlySet<int> RequiredPorts { get; }

    public string? RequiredNodeClass { get; }

    public IReadOnlyDictionary<string, string> RequiredLabels { get; }

    public IReadOnlySet<string> RequiredTrustZones { get; }

    public IReadOnlySet<string> RequiredNetworkZones { get; }

    public IReadOnlySet<string> RequiredSecretZones { get; }

    public IReadOnlySet<string> AllowedFailureDomains { get; }

    public IReadOnlySet<string> RequiredAffinityFacts { get; }

    public IReadOnlySet<string> ProhibitedAffinityFacts { get; }

    private static FrozenSet<int> CopyPorts(IEnumerable<int>? ports)
    {
        var values = (ports ?? []).ToArray();
        if (values.Length != values.Distinct().Count())
        {
            throw new ArgumentException("Port collections cannot contain duplicates.", nameof(ports));
        }

        if (values.Any(port => port is < 1 or > 65535))
        {
            throw new ArgumentOutOfRangeException(nameof(ports), "Ports must be between 1 and 65535.");
        }

        return values.ToFrozenSet();
    }

    private static FrozenSet<string> CopyFacts(IEnumerable<string>? facts)
    {
        var values = (facts ?? []).ToArray();
        if (values.Any(string.IsNullOrWhiteSpace))
        {
            throw new ArgumentException("Facts and zone names must be nonempty.", nameof(facts));
        }

        if (values.Length != values.Distinct(StringComparer.Ordinal).Count())
        {
            throw new ArgumentException("Facts and zone names cannot contain duplicates.", nameof(facts));
        }

        return values.ToFrozenSet(StringComparer.Ordinal);
    }

    private static FrozenDictionary<string, string> CopyLabels(IReadOnlyDictionary<string, string>? labels)
    {
        var source = labels ?? new Dictionary<string, string>();
        if (source.Any(label => string.IsNullOrWhiteSpace(label.Key) || string.IsNullOrWhiteSpace(label.Value)))
        {
            throw new ArgumentException("Label keys and values must be nonempty.", nameof(labels));
        }

        return source.ToFrozenDictionary(StringComparer.Ordinal);
    }

    private static string RequireText(string value, string parameterName) =>
        !string.IsNullOrWhiteSpace(value) ? value : throw new ArgumentException("A nonempty value is required.", parameterName);
}

public enum PlacementCheck
{
    CallerVeto,
    Architecture,
    NodeClass,
    Labels,
    TrustZones,
    NetworkZones,
    SecretZones,
    FailureDomain,
    Affinity,
    AntiAffinity,
    Ports,
    SafetyCap,
    Cpu,
    Memory,
    BlockIo,
    EphemeralDisk,
    Bandwidth,
    Pids,
    FileDescriptors,
    HugePages,
    Score,
    Selection,
}

public enum CheckOutcome
{
    Passed,
    Rejected,
    NotApplicable,
}

public sealed record PlacementReason(PlacementCheck Check, CheckOutcome Outcome, string Detail);

public sealed record WasteComponent(ResourceDimension Dimension, long Remaining, long Weight, BigInteger WeightedWaste);

public sealed record WasteScore(
    BigInteger WeightedWaste,
    ResourceVector Remaining,
    IReadOnlyList<WasteComponent> Components);

public sealed record CandidateTrace(
    string CandidateId,
    bool Eligible,
    WasteScore? Score,
    IReadOnlyList<PlacementReason> Reasons);

public abstract record ScheduleResult(string WorkloadId, IReadOnlyList<CandidateTrace> Candidates);

public sealed record PlacementSelected(
    string WorkloadId,
    string SelectedCandidateId,
    IReadOnlyList<CandidateTrace> Candidates)
    : ScheduleResult(WorkloadId, Candidates);

public sealed record Unschedulable(
    string WorkloadId,
    IReadOnlyList<CandidateTrace> Candidates)
    : ScheduleResult(WorkloadId, Candidates);
