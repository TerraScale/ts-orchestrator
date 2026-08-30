// Port of src/TerraScale.Orchestrator/Contracts/StableIdentifiers/SecurityRuleId.cs.
package contracts

// SecurityRuleId is a permanent security-rule identifier from the GOAL.md
// "Stable contract identifiers" table. Identifiers form a closed set: only
// values registered in StableIdentifierRegistry construct successfully, the
// canonical text of a live identifier never changes in place, and a
// replacement decision marks the retired identifier superseded and adds a new
// identifier instead of editing either one.
type SecurityRuleId struct {
	Value string
}

// IsRegistered reports whether this value is one of the registered security rules.
func (i SecurityRuleId) IsRegistered() bool {
	_, ok := StableIdentifierRegistry.tryGetSecurityRuleText(i)
	return ok
}

// CanonicalText returns the verbatim GOAL.md text; it panics for an
// unregistered identifier, mirroring the C# InvalidOperationException.
func (i SecurityRuleId) CanonicalText() string {
	if text, ok := StableIdentifierRegistry.tryGetSecurityRuleText(i); ok {
		return text
	}

	panic("Security rule " + i.Value + " is not registered.")
}

// TryGetText mirrors StableIdentifierRegistry.TryGetText(SecurityRuleId, out text).
func (i SecurityRuleId) TryGetText() (string, bool) {
	return StableIdentifierRegistry.tryGetSecurityRuleText(i)
}

// SecurityRuleIdTryCreate mirrors SecurityRuleId.TryCreate: only registered values pass.
func SecurityRuleIdTryCreate(value string) (SecurityRuleId, bool) {
	if _, ok := StableIdentifierRegistry.tryGetSecurityRuleText(SecurityRuleId{Value: value}); ok {
		return SecurityRuleId{Value: value}, true
	}

	return SecurityRuleId{}, false
}

// SupersededBy mirrors StableIdentifierRegistry.SupersededBy(SecurityRuleId).
func (i SecurityRuleId) SupersededBy() (SecurityRuleId, bool) {
	return StableIdentifierRegistry.supersededSecurityRule(i)
}

func (i SecurityRuleId) String() string { return i.Value }

// The registered security-rule identifiers (C# static properties).
var (
	SecurityRuleIdTls13MutualWorkloadIdentity                = SecurityRuleId{Value: "SEC-ORCH-001"}
	SecurityRuleIdNatsMutualTlsScopedIdentities              = SecurityRuleId{Value: "SEC-ORCH-002"}
	SecurityRuleIdDisjointIdentityPermissions                = SecurityRuleId{Value: "SEC-ORCH-003"}
	SecurityRuleIdRegionalCredentialScope                    = SecurityRuleId{Value: "SEC-ORCH-004"}
	SecurityRuleIdGlobalControllersHoldNoRegionalCredentials = SecurityRuleId{Value: "SEC-ORCH-005"}
	SecurityRuleIdSecretReferencesOnly                       = SecurityRuleId{Value: "SEC-ORCH-006"}
	SecurityRuleIdNonExportablePrivateKeys                   = SecurityRuleId{Value: "SEC-ORCH-007"}
	SecurityRuleIdBootstrapCredentialExpiry                  = SecurityRuleId{Value: "SEC-ORCH-008"}
	SecurityRuleIdArtifactSupplyChainEvidence                = SecurityRuleId{Value: "SEC-ORCH-009"}
	SecurityRuleIdNoInboundSsh                               = SecurityRuleId{Value: "SEC-ORCH-010"}
	SecurityRuleIdBoundedBreakGlassAccess                    = SecurityRuleId{Value: "SEC-ORCH-011"}
	SecurityRuleIdSecretRedactionBeforeEmission              = SecurityRuleId{Value: "SEC-ORCH-012"}
	SecurityRuleIdNoDevelopmentTrustInProduction             = SecurityRuleId{Value: "SEC-ORCH-013"}
	SecurityRuleIdAccessThroughAllocationContract            = SecurityRuleId{Value: "SEC-ORCH-014"}
)
