namespace TerraScale.Orchestrator.Contracts.StableIdentifiers;

/// <summary>
/// Permanent requirement identifier from the GOAL.md "Stable contract
/// identifiers" table. Identifiers form a closed set: only values registered
/// in <see cref="StableIdentifierRegistry"/> construct successfully, the
/// canonical text of a live identifier never changes in place, and a
/// replacement decision marks the retired identifier superseded and adds a new
/// identifier instead of editing either one.
/// </summary>
public readonly record struct RequirementId
{
    private readonly string? _value;

    private RequirementId(string value) => _value = value;

    internal static RequirementId FromValue(string value) => new(value);

    public string Value => _value ?? string.Empty;

    public bool IsRegistered => StableIdentifierRegistry.TryGetText(this, out _);

    public string CanonicalText => StableIdentifierRegistry.TryGetText(this, out var text)
        ? text
        : throw new InvalidOperationException($"Requirement {Value} is not registered.");

    public static bool TryCreate(string? value, out RequirementId result)
    {
        if (value is not null && StableIdentifierRegistry.TryGetText(new RequirementId(value), out _))
        {
            result = new RequirementId(value);
            return true;
        }

        result = default;
        return false;
    }

    public override string ToString() => Value;

    public static RequirementId GlobalAuthority { get; } = new("REQ-ORCH-001");
    public static RequirementId ThreeReplicaControllerGroups { get; } = new("REQ-ORCH-002");
    public static RequirementId JetStreamFileStorageR3 { get; } = new("REQ-ORCH-003");
    public static RequirementId RegionalAutonomyDuringAuthorityLoss { get; } = new("REQ-ORCH-004");
    public static RequirementId RegionalJournalCompletenessAfterReconnect { get; } = new("REQ-ORCH-005");
    public static RequirementId GreenfieldOciEstateOwnership { get; } = new("REQ-ORCH-006");
    public static RequirementId TypedRegionScopedProviderActuators { get; } = new("REQ-ORCH-007");
    public static RequirementId AdmittedImmutableWorkloadPlacement { get; } = new("REQ-ORCH-008");
    public static RequirementId TerraBaseTwoMemberPlacement { get; } = new("REQ-ORCH-009");
    public static RequirementId ProductServicesTwoInstancesPerRegion { get; } = new("REQ-ORCH-010");
    public static RequirementId WorkloadIdentityTrustAndBootstrapGrants { get; } = new("REQ-ORCH-011");
    public static RequirementId CloudflareRoutingTwentyRegionCeiling { get; } = new("REQ-ORCH-012");
    public static RequirementId ExactArtifactDeliveryAdmission { get; } = new("REQ-ORCH-013");
    public static RequirementId SustainedCapacityAutoscaling { get; } = new("REQ-ORCH-014");
    public static RequirementId DurableProgressAndTerminalReceipts { get; } = new("REQ-ORCH-015");
    public static RequirementId ControlStateBackupAndRestoreEvidence { get; } = new("REQ-ORCH-016");
    public static RequirementId TypedOperatorInterface { get; } = new("REQ-ORCH-017");
    public static RequirementId ProductionReleaseQualification { get; } = new("REQ-ORCH-018");
    public static RequirementId TwentyRegionSimulation { get; } = new("REQ-ORCH-019");
    public static RequirementId NoControlPlaneLookupOnCustomerPath { get; } = new("REQ-ORCH-020");
    public static RequirementId NoEmbeddedDevelopmentComposition { get; } = new("REQ-ORCH-021");
    public static RequirementId ParallelRegionalCandidateBeforeCutover { get; } = new("REQ-ORCH-022");
    public static RequirementId HostCapacityPublication { get; } = new("REQ-ORCH-023");
    public static RequirementId ClosedWorkloadExecutionContract { get; } = new("REQ-ORCH-024");
    public static RequirementId ResourceApiListWatchSurface { get; } = new("REQ-ORCH-025");
    public static RequirementId DependencyAwareDeletion { get; } = new("REQ-ORCH-026");
    public static RequirementId BoundedCoalescingWorkQueues { get; } = new("REQ-ORCH-027");
    public static RequirementId DisruptionSafeRebalancing { get; } = new("REQ-ORCH-028");
}
