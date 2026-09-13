namespace TerraScale.Orchestrator.Contracts.StableIdentifiers;

/// <summary>
/// Permanent state-machine identifier from the GOAL.md "Stable contract
/// identifiers" table. Identifiers form a closed set: only values registered
/// in <see cref="StableIdentifierRegistry"/> construct successfully, the
/// canonical text of a live identifier never changes in place, and a
/// replacement decision marks the retired identifier superseded and adds a new
/// identifier instead of editing either one.
/// </summary>
public readonly record struct StateMachineId
{
    private readonly string? _value;

    private StateMachineId(string value) => _value = value;

    internal static StateMachineId FromValue(string value) => new(value);

    public string Value => _value ?? string.Empty;

    public bool IsRegistered => StableIdentifierRegistry.TryGetText(this, out _);

    public string CanonicalText => StableIdentifierRegistry.TryGetText(this, out var text)
        ? text
        : throw new InvalidOperationException($"State machine {Value} is not registered.");

    public static bool TryCreate(string? value, out StateMachineId result)
    {
        if (value is not null && StableIdentifierRegistry.TryGetText(new StateMachineId(value), out _))
        {
            result = new StateMachineId(value);
            return true;
        }

        result = default;
        return false;
    }

    public override string ToString() => Value;

    public static StateMachineId Bootstrap { get; } = new("SM-ORCH-BOOTSTRAP");
    public static StateMachineId GlobalAuthority { get; } = new("SM-ORCH-GLOBAL-AUTHORITY");
    public static StateMachineId RegionalAuthority { get; } = new("SM-ORCH-REGIONAL-AUTHORITY");
    public static StateMachineId RegionAdmission { get; } = new("SM-ORCH-REGION-ADMISSION");
    public static StateMachineId RegionRemoval { get; } = new("SM-ORCH-REGION-REMOVAL");
    public static StateMachineId ProviderOperation { get; } = new("SM-ORCH-PROVIDER-OPERATION");
    public static StateMachineId HostLifecycle { get; } = new("SM-ORCH-HOST-LIFECYCLE");
    public static StateMachineId WorkloadLifecycle { get; } = new("SM-ORCH-WORKLOAD-LIFECYCLE");
    public static StateMachineId MemberAdd { get; } = new("SM-ORCH-MEMBER-ADD");
    public static StateMachineId MemberReplace { get; } = new("SM-ORCH-MEMBER-REPLACE");
    public static StateMachineId Capacity { get; } = new("SM-ORCH-CAPACITY");
    public static StateMachineId Release { get; } = new("SM-ORCH-RELEASE");
    public static StateMachineId Reconnect { get; } = new("SM-ORCH-RECONNECT");
    public static StateMachineId TrustRotation { get; } = new("SM-ORCH-TRUST-ROTATION");
    public static StateMachineId ControlRestore { get; } = new("SM-ORCH-CONTROL-RESTORE");
    public static StateMachineId NodePressure { get; } = new("SM-ORCH-NODE-PRESSURE");
    public static StateMachineId WorkloadRestart { get; } = new("SM-ORCH-WORKLOAD-RESTART");
    public static StateMachineId ResourceDeletion { get; } = new("SM-ORCH-RESOURCE-DELETION");
}

