using System.Collections.ObjectModel;
using System.Globalization;
using System.Text;

namespace TerraScale.Orchestrator.Contracts.Resources;

public enum RuntimeDriver
{
    NativeSystemd = 1,
    OciContainer = 2,
}

public enum TransportProtocol
{
    Tcp = 1,
    Udp = 2,
}

public sealed record NetworkPort
{
    public NetworkPort(TransportProtocol protocol, ushort port)
    {
        if (!Enum.IsDefined(protocol))
        {
            throw new ArgumentOutOfRangeException(nameof(protocol));
        }

        if (port == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(port));
        }

        Protocol = protocol;
        Port = port;
    }

    public TransportProtocol Protocol { get; }

    public ushort Port { get; }

    public override string ToString() => $"{Protocol}:{Port.ToString(CultureInfo.InvariantCulture)}";
}

public enum RoleCapability
{
    PublicHttp = 1,
    ProductDatabase = 2,
    ControlAuthority = 3,
    ControlMessaging = 4,
    ProductMessaging = 5,
    TelemetryQuery = 6,
    TelemetryIngest = 7,
    Alerting = 8,
    SyntheticProbe = 9,
    NetworkCoordination = 10,
    RoutePolicy = 11,
    IsolatedBuild = 12,
}

public enum VolumePurpose
{
    TerraBaseData = 1,
    NatsControlStore = 2,
    NatsProductStore = 3,
    MetricsData = 4,
    LogData = 5,
    TraceData = 6,
    TelemetrySpool = 7,
    EphemeralBuild = 8,
}

public sealed record SecretProfileReference
{
    public SecretProfileReference(ResourceId profileId) =>
        ProfileId = profileId ?? throw new ArgumentNullException(nameof(profileId));

    public ResourceId ProfileId { get; }

    public override string ToString() => ProfileId.ToString();
}

public enum HealthSignal
{
    ProcessLiveness = 1,
    ApplicationLiveness = 2,
    Readiness = 3,
    DependencyReadiness = 4,
    DrainReadiness = 5,
    RolloutVerification = 6,
}

public sealed class HealthContract
{
    public HealthContract(IEnumerable<HealthSignal> signals)
    {
        Signals = StableEnumSet(signals, nameof(signals));
        if (Signals.Count == 0)
        {
            throw new ArgumentException("At least one health signal is required.", nameof(signals));
        }
    }

    public IReadOnlyList<HealthSignal> Signals { get; }

    private static IReadOnlyList<HealthSignal> StableEnumSet(IEnumerable<HealthSignal> source, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(source, parameterName);
        var values = source.ToArray();
        if (values.Any(value => !Enum.IsDefined(value)))
        {
            throw new ArgumentOutOfRangeException(parameterName, "Unknown enum value.");
        }

        if (values.Length != values.Distinct().Count())
        {
            throw new ArgumentException("Duplicate values are not allowed.", parameterName);
        }

        return new ReadOnlyCollection<HealthSignal>(values.Order().ToArray());
    }
}

public sealed record PlacementClassReference
{
    public PlacementClassReference(string id) => Id = CanonicalText.Token(id, nameof(id));

    public string Id { get; }

    public override string ToString() => Id;
}

public enum FailureDomainSpread
{
    None = 1,
    PreferDistinct = 2,
    RequireDistinct = 3,
}

public sealed record PlacementConstraints
{
    public PlacementConstraints(
        PlacementClassReference? requiredNodeClass,
        FailureDomainSpread failureDomainSpread,
        bool onePerHost)
    {
        if (!Enum.IsDefined(failureDomainSpread))
        {
            throw new ArgumentOutOfRangeException(nameof(failureDomainSpread));
        }

        RequiredNodeClass = requiredNodeClass;
        FailureDomainSpread = failureDomainSpread;
        OnePerHost = onePerHost;
    }

    public PlacementClassReference? RequiredNodeClass { get; }

    public FailureDomainSpread FailureDomainSpread { get; }

    public bool OnePerHost { get; }
}

public enum ScalingControllerOwner
{
    Fixed = 1,
    Stateless = 2,
    TerraBase = 3,
    ControlPlane = 4,
}

public sealed record ResourceEnvelope
{
    public ResourceEnvelope(long cpu, long memory, long blockIo, long ephemeralDisk, long bandwidth, long pids, long fileDescriptors, long hugePages)
    {
        Cpu = NonNegative(cpu, nameof(cpu));
        Memory = NonNegative(memory, nameof(memory));
        BlockIo = NonNegative(blockIo, nameof(blockIo));
        EphemeralDisk = NonNegative(ephemeralDisk, nameof(ephemeralDisk));
        Bandwidth = NonNegative(bandwidth, nameof(bandwidth));
        Pids = NonNegative(pids, nameof(pids));
        FileDescriptors = NonNegative(fileDescriptors, nameof(fileDescriptors));
        HugePages = NonNegative(hugePages, nameof(hugePages));
    }

    public long Cpu { get; }
    public long Memory { get; }
    public long BlockIo { get; }
    public long EphemeralDisk { get; }
    public long Bandwidth { get; }
    public long Pids { get; }
    public long FileDescriptors { get; }
    public long HugePages { get; }

    internal IEnumerable<long> Values()
    {
        yield return Cpu; yield return Memory; yield return BlockIo; yield return EphemeralDisk;
        yield return Bandwidth; yield return Pids; yield return FileDescriptors; yield return HugePages;
    }

    private static long NonNegative(long value, string name) =>
        value >= 0 ? value : throw new ArgumentOutOfRangeException(name);
}

public sealed record ResourceBounds
{
    public ResourceBounds(ResourceEnvelope minimum, ResourceEnvelope maximum)
    {
        Minimum = minimum ?? throw new ArgumentNullException(nameof(minimum));
        Maximum = maximum ?? throw new ArgumentNullException(nameof(maximum));
        if (minimum.Values().Zip(maximum.Values()).Any(pair => pair.First > pair.Second))
        {
            throw new ArgumentException("Every minimum resource must be less than or equal to its maximum.");
        }
    }

    public ResourceEnvelope Minimum { get; }

    public ResourceEnvelope Maximum { get; }
}

/// <summary>
/// Safe built-in descriptor surface for INV-017. It intentionally has no arbitrary
/// execution, privilege, Linux capability, host path, or NATS permission fields.
/// Canonical output contains references only and is safe for SEC-NO-SECRET-OUTPUT.
/// </summary>
public sealed class RoleDescriptor : IEquatable<RoleDescriptor>
{
    internal RoleDescriptor(
        ApiVersion apiVersion,
        AdmittedRole role,
        IEnumerable<RuntimeDriver> allowedRuntimes,
        IEnumerable<NetworkPort> ports,
        IEnumerable<RoleCapability> capabilities,
        IEnumerable<VolumePurpose> volumePurposes,
        IEnumerable<SecretProfileReference> secretProfiles,
        HealthContract health,
        PlacementConstraints placement,
        ScalingControllerOwner scalingControllerOwner,
        ResourceBounds resourceBounds)
    {
        ApiVersion = apiVersion ?? throw new ArgumentNullException(nameof(apiVersion));
        Role = role ?? throw new ArgumentNullException(nameof(role));
        AllowedRuntimes = StableEnums(allowedRuntimes, nameof(allowedRuntimes), requireNonempty: true);
        Ports = StableValues(ports, nameof(ports), port => ((int)port.Protocol, port.Port));
        Capabilities = StableEnums(capabilities, nameof(capabilities), requireNonempty: false);
        VolumePurposes = StableEnums(volumePurposes, nameof(volumePurposes), requireNonempty: false);
        SecretProfiles = StableValues(
            secretProfiles,
            nameof(secretProfiles),
            profile => profile.ProfileId.Value,
            StringComparer.Ordinal);
        Health = health ?? throw new ArgumentNullException(nameof(health));
        Placement = placement ?? throw new ArgumentNullException(nameof(placement));
        if (!Enum.IsDefined(scalingControllerOwner))
        {
            throw new ArgumentOutOfRangeException(nameof(scalingControllerOwner));
        }

        ScalingControllerOwner = scalingControllerOwner;
        ResourceBounds = resourceBounds ?? throw new ArgumentNullException(nameof(resourceBounds));
    }

    public ApiVersion ApiVersion { get; }
    public AdmittedRole Role { get; }
    public IReadOnlyList<RuntimeDriver> AllowedRuntimes { get; }
    public IReadOnlyList<NetworkPort> Ports { get; }
    public IReadOnlyList<RoleCapability> Capabilities { get; }
    public IReadOnlyList<VolumePurpose> VolumePurposes { get; }
    public IReadOnlyList<SecretProfileReference> SecretProfiles { get; }
    public HealthContract Health { get; }
    public PlacementConstraints Placement { get; }
    public ScalingControllerOwner ScalingControllerOwner { get; }
    public ResourceBounds ResourceBounds { get; }

    public string ToCanonicalString() => string.Join('|',
        $"apiVersion={ApiVersion}",
        $"role={Role.Projection}",
        $"runtimes={Join(AllowedRuntimes)}",
        $"ports={Join(Ports)}",
        $"capabilities={Join(Capabilities)}",
        $"volumes={Join(VolumePurposes)}",
        $"secrets={Join(SecretProfiles)}",
        $"health={Join(Health.Signals)}",
        $"placement={Placement.RequiredNodeClass?.Id ?? "-"}:{Placement.FailureDomainSpread}:{Placement.OnePerHost}",
        $"scaling={ScalingControllerOwner}",
        $"minimum={JoinNumbers(ResourceBounds.Minimum.Values())}",
        $"maximum={JoinNumbers(ResourceBounds.Maximum.Values())}");

    public byte[] GetCanonicalDigestInput() => Encoding.UTF8.GetBytes(ToCanonicalString());

    public bool Equals(RoleDescriptor? other) =>
        other is not null && string.Equals(ToCanonicalString(), other.ToCanonicalString(), StringComparison.Ordinal);

    public override bool Equals(object? obj) => obj is RoleDescriptor other && Equals(other);

    public override int GetHashCode()
    {
        const uint offset = 2166136261;
        const uint prime = 16777619;
        var hash = offset;
        foreach (var value in GetCanonicalDigestInput())
        {
            hash = unchecked((hash ^ value) * prime);
        }

        return unchecked((int)hash);
    }

    private static IReadOnlyList<T> StableEnums<T>(IEnumerable<T> source, string name, bool requireNonempty)
        where T : struct, Enum
    {
        ArgumentNullException.ThrowIfNull(source, name);
        var values = source.ToArray();
        if (values.Any(value => !Enum.IsDefined(value)))
        {
            throw new ArgumentOutOfRangeException(name, "Unknown enum value.");
        }

        if (values.Length != values.Distinct().Count())
        {
            throw new ArgumentException("Duplicate values are not allowed.", name);
        }

        if (requireNonempty && values.Length == 0)
        {
            throw new ArgumentException("At least one value is required.", name);
        }

        return new ReadOnlyCollection<T>(values.Order().ToArray());
    }

    private static IReadOnlyList<T> StableValues<T, TKey>(
        IEnumerable<T> source,
        string name,
        Func<T, TKey> key,
        IComparer<TKey>? comparer = null)
        where T : notnull
    {
        ArgumentNullException.ThrowIfNull(source, name);
        var values = source.ToArray();
        if (values.Any(value => value is null))
        {
            throw new ArgumentException("Null values are not allowed.", name);
        }

        if (values.Length != values.Distinct().Count())
        {
            throw new ArgumentException("Duplicate values are not allowed.", name);
        }

        return new ReadOnlyCollection<T>(values.OrderBy(key, comparer ?? Comparer<TKey>.Default).ToArray());
    }

    private static string Join<T>(IEnumerable<T> values) => string.Join(',', values);

    private static string JoinNumbers(IEnumerable<long> values) =>
        string.Join(',', values.Select(value => value.ToString(CultureInfo.InvariantCulture)));
}

