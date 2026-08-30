namespace TerraScale.Orchestrator.Contracts.StableIdentifiers;

/// <summary>
/// Permanent invariant identifier from the GOAL.md "Stable contract
/// identifiers" table. Identifiers form a closed set: only values registered
/// in <see cref="StableIdentifierRegistry"/> construct successfully, the
/// canonical text of a live identifier never changes in place, and a
/// replacement decision marks the retired identifier superseded and adds a new
/// identifier instead of editing either one.
/// </summary>
public readonly record struct InvariantId
{
    private readonly string? _value;

    private InvariantId(string value) => _value = value;

    internal static InvariantId FromValue(string value) => new(value);

    public string Value => _value ?? string.Empty;

    public bool IsRegistered => StableIdentifierRegistry.TryGetText(this, out _);

    public string CanonicalText => StableIdentifierRegistry.TryGetText(this, out var text)
        ? text
        : throw new InvalidOperationException($"Invariant {Value} is not registered.");

    public static bool TryCreate(string? value, out InvariantId result)
    {
        if (value is not null && StableIdentifierRegistry.TryGetText(new InvariantId(value), out _))
        {
            result = new InvariantId(value);
            return true;
        }

        result = default;
        return false;
    }

    public override string ToString() => Value;

    public static InvariantId SingleAuthorityTermPerScope { get; } = new("INV-ORCH-001");
    public static InvariantId GlobalPolicySingleWriter { get; } = new("INV-ORCH-002");
    public static InvariantId RegionalMutationNeedsLocalTermAndQuorum { get; } = new("INV-ORCH-003");
    public static InvariantId IsolatedRegionCannotCreateGlobalGeneration { get; } = new("INV-ORCH-004");
    public static InvariantId ObservationsAreNeverErased { get; } = new("INV-ORCH-005");
    public static InvariantId DurableIntentBeforeExternalMutation { get; } = new("INV-ORCH-006");
    public static InvariantId UnknownOutcomeReconciledBeforeRetry { get; } = new("INV-ORCH-007");
    public static InvariantId SingleActiveLifecycleOwner { get; } = new("INV-ORCH-008");
    public static InvariantId TagsNeverGrantAuthority { get; } = new("INV-ORCH-009");
    public static InvariantId StaleLeaderCannotCompleteMutation { get; } = new("INV-ORCH-010");
    public static InvariantId CommittedTargetFixedAcrossLeadership { get; } = new("INV-ORCH-011");
    public static InvariantId NoCustomerDataInNats { get; } = new("INV-ORCH-012");
    public static InvariantId TerraBaseAloneAcceptsMembership { get; } = new("INV-ORCH-013");
    public static InvariantId ScaleInPreservesDurabilityHeadroom { get; } = new("INV-ORCH-014");
    public static InvariantId NoSecretsInStateOrTelemetry { get; } = new("INV-ORCH-015");
    public static InvariantId ExactQualifiedDigestActivation { get; } = new("INV-ORCH-016");
    public static InvariantId DiscoveryAndPublicationAreSeparate { get; } = new("INV-ORCH-017");
    public static InvariantId NoUnsafeIdentityReuse { get; } = new("INV-ORCH-018");
    public static InvariantId AdmissionPrecedesCapacity { get; } = new("INV-ORCH-019");
    public static InvariantId TelemetryNeverAuthorizesDestruction { get; } = new("INV-ORCH-020");
    public static InvariantId NoInPlaceReleaseMutation { get; } = new("INV-ORCH-021");
    public static InvariantId NoDevelopmentCompositionInProduction { get; } = new("INV-ORCH-022");
    public static InvariantId CandidateTrafficGates { get; } = new("INV-ORCH-023");
    public static InvariantId UniqueDurableEndpointLeases { get; } = new("INV-ORCH-024");
    public static InvariantId DeletionBlockersHoldResources { get; } = new("INV-ORCH-025");
    public static InvariantId ObservedGenerationGate { get; } = new("INV-ORCH-026");
    public static InvariantId PressureStopsPlacementBeforeEviction { get; } = new("INV-ORCH-027");
    public static InvariantId BoundedQueueOverload { get; } = new("INV-ORCH-028");
}
