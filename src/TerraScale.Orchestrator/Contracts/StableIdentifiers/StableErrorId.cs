namespace TerraScale.Orchestrator.Contracts.StableIdentifiers;

/// <summary>
/// Permanent stable-error identifier from the GOAL.md "Stable contract
/// identifiers" table. Identifiers form a closed set: only values registered
/// in <see cref="StableIdentifierRegistry"/> construct successfully, the
/// canonical text of a live identifier never changes in place, and a
/// replacement decision marks the retired identifier superseded and adds a new
/// identifier instead of editing either one. <see cref="Code"/> is the wire
/// error-code string surface (for example <c>ERR-ORCH-OUTCOME-UNKNOWN</c>) so
/// code sites can adopt the typed identifier incrementally wherever a raw
/// error string is emitted today.
/// </summary>
public readonly record struct StableErrorId
{
    private readonly string? _value;

    private StableErrorId(string value) => _value = value;

    internal static StableErrorId FromValue(string value) => new(value);

    public string Value => _value ?? string.Empty;

    /// <summary>The stable error code string surface, equal to <see cref="Value"/>.</summary>
    public string Code => Value;

    public bool IsRegistered => StableIdentifierRegistry.TryGetText(this, out _);

    public string CanonicalText => StableIdentifierRegistry.TryGetText(this, out var text)
        ? text
        : throw new InvalidOperationException($"Stable error {Value} is not registered.");

    public static bool TryCreate(string? value, out StableErrorId result)
    {
        if (value is not null && StableIdentifierRegistry.TryGetText(new StableErrorId(value), out _))
        {
            result = new StableErrorId(value);
            return true;
        }

        result = default;
        return false;
    }

    /// <summary>Resolves a wire error code such as <c>ERR-ORCH-OUTCOME-UNKNOWN</c>.</summary>
    public static bool TryCreateFromCode(string? code, out StableErrorId result) => TryCreate(code, out result);

    public override string ToString() => Code;

    public static StableErrorId AuthorityUnavailable { get; } = new("ERR-ORCH-AUTHORITY-UNAVAILABLE");
    public static StableErrorId StaleTerm { get; } = new("ERR-ORCH-STALE-TERM");
    public static StableErrorId GenerationConflict { get; } = new("ERR-ORCH-GENERATION-CONFLICT");
    public static StableErrorId RegionIsolated { get; } = new("ERR-ORCH-REGION-ISOLATED");
    public static StableErrorId OutcomeUnknown { get; } = new("ERR-ORCH-OUTCOME-UNKNOWN");
    public static StableErrorId OwnershipMismatch { get; } = new("ERR-ORCH-OWNERSHIP-MISMATCH");
    public static StableErrorId EvidenceIncomplete { get; } = new("ERR-ORCH-EVIDENCE-INCOMPLETE");
    public static StableErrorId CapacityUnavailable { get; } = new("ERR-ORCH-CAPACITY-UNAVAILABLE");
    public static StableErrorId BudgetApprovalRequired { get; } = new("ERR-ORCH-BUDGET-APPROVAL-REQUIRED");
    public static StableErrorId ProviderLimit { get; } = new("ERR-ORCH-PROVIDER-LIMIT");
    public static StableErrorId TerraBaseHold { get; } = new("ERR-ORCH-TERRABASE-HOLD");
    public static StableErrorId ArtifactDenied { get; } = new("ERR-ORCH-ARTIFACT-DENIED");
    public static StableErrorId RegionNotQualified { get; } = new("ERR-ORCH-REGION-NOT-QUALIFIED");
    public static StableErrorId RestoreGenerationConflict { get; } = new("ERR-ORCH-RESTORE-GENERATION-CONFLICT");
    public static StableErrorId CandidateNotReady { get; } = new("ERR-ORCH-CANDIDATE-NOT-READY");
    public static StableErrorId WorkloadQuarantined { get; } = new("ERR-ORCH-WORKLOAD-QUARANTINED");
    public static StableErrorId DeletionBlocked { get; } = new("ERR-ORCH-DELETION-BLOCKED");
    public static StableErrorId WatchExpired { get; } = new("ERR-ORCH-WATCH-EXPIRED");
}
