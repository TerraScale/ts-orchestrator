namespace TerraScale.Orchestrator.Contracts.StableIdentifiers;

/// <summary>
/// Permanent security-rule identifier from the GOAL.md "Stable contract
/// identifiers" table. Identifiers form a closed set: only values registered
/// in <see cref="StableIdentifierRegistry"/> construct successfully, the
/// canonical text of a live identifier never changes in place, and a
/// replacement decision marks the retired identifier superseded and adds a new
/// identifier instead of editing either one.
/// </summary>
public readonly record struct SecurityRuleId
{
    private readonly string? _value;

    private SecurityRuleId(string value) => _value = value;

    internal static SecurityRuleId FromValue(string value) => new(value);

    public string Value => _value ?? string.Empty;

    public bool IsRegistered => StableIdentifierRegistry.TryGetText(this, out _);

    public string CanonicalText => StableIdentifierRegistry.TryGetText(this, out var text)
        ? text
        : throw new InvalidOperationException($"Security rule {Value} is not registered.");

    public static bool TryCreate(string? value, out SecurityRuleId result)
    {
        if (value is not null && StableIdentifierRegistry.TryGetText(new SecurityRuleId(value), out _))
        {
            result = new SecurityRuleId(value);
            return true;
        }

        result = default;
        return false;
    }

    public override string ToString() => Value;

    public static SecurityRuleId Tls13MutualWorkloadIdentity { get; } = new("SEC-ORCH-001");
    public static SecurityRuleId NatsMutualTlsScopedIdentities { get; } = new("SEC-ORCH-002");
    public static SecurityRuleId DisjointIdentityPermissions { get; } = new("SEC-ORCH-003");
    public static SecurityRuleId RegionalCredentialScope { get; } = new("SEC-ORCH-004");
    public static SecurityRuleId GlobalControllersHoldNoRegionalCredentials { get; } = new("SEC-ORCH-005");
    public static SecurityRuleId SecretReferencesOnly { get; } = new("SEC-ORCH-006");
    public static SecurityRuleId NonExportablePrivateKeys { get; } = new("SEC-ORCH-007");
    public static SecurityRuleId BootstrapCredentialExpiry { get; } = new("SEC-ORCH-008");
    public static SecurityRuleId ArtifactSupplyChainEvidence { get; } = new("SEC-ORCH-009");
    public static SecurityRuleId NoInboundSsh { get; } = new("SEC-ORCH-010");
    public static SecurityRuleId BoundedBreakGlassAccess { get; } = new("SEC-ORCH-011");
    public static SecurityRuleId SecretRedactionBeforeEmission { get; } = new("SEC-ORCH-012");
    public static SecurityRuleId NoDevelopmentTrustInProduction { get; } = new("SEC-ORCH-013");
    public static SecurityRuleId AccessThroughAllocationContract { get; } = new("SEC-ORCH-014");
}

