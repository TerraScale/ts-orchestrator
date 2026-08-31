// Port of src/TerraScale.Orchestrator/Contracts/StableIdentifiers/RequirementId.cs.
package contracts

import "fmt"

// RequirementId is a permanent requirement identifier from the GOAL.md "Stable
// contract identifiers" table. Identifiers form a closed set: only values
// registered in StableIdentifierRegistry construct successfully, the canonical
// text of a live identifier never changes in place, and a replacement decision
// marks the retired identifier superseded and adds a new identifier instead of
// editing either one.
type RequirementId struct {
	Value string
}

// IsRegistered reports whether this value is one of the registered requirements.
func (i RequirementId) IsRegistered() bool {
	_, ok := StableIdentifierRegistry.tryGetRequirementText(i)
	return ok
}

// CanonicalText returns the verbatim GOAL.md text.
func (i RequirementId) CanonicalText() (string, error) {
	if text, ok := StableIdentifierRegistry.tryGetRequirementText(i); ok {
		return text, nil
	}
	return "", fmt.Errorf("requirement %q is not registered", i.Value)
}

// TryGetText mirrors StableIdentifierRegistry.TryGetText(RequirementId, out text).
func (i RequirementId) TryGetText() (string, bool) {
	return StableIdentifierRegistry.tryGetRequirementText(i)
}

// RequirementIdTryCreate mirrors RequirementId.TryCreate: only registered values pass.
func RequirementIdTryCreate(value string) (RequirementId, bool) {
	if _, ok := StableIdentifierRegistry.tryGetRequirementText(RequirementId{Value: value}); ok {
		return RequirementId{Value: value}, true
	}

	return RequirementId{}, false
}

// SupersededBy mirrors StableIdentifierRegistry.SupersededBy(RequirementId).
func (i RequirementId) SupersededBy() (RequirementId, bool) {
	return StableIdentifierRegistry.supersededRequirement(i)
}

func (i RequirementId) String() string { return i.Value }

// The registered requirement identifiers (C# static properties).
var (
	RequirementIdGlobalAuthority                           = RequirementId{Value: "REQ-ORCH-001"}
	RequirementIdThreeReplicaControllerGroups              = RequirementId{Value: "REQ-ORCH-002"}
	RequirementIdJetStreamFileStorageR3                    = RequirementId{Value: "REQ-ORCH-003"}
	RequirementIdRegionalAutonomyDuringAuthorityLoss       = RequirementId{Value: "REQ-ORCH-004"}
	RequirementIdRegionalJournalCompletenessAfterReconnect = RequirementId{Value: "REQ-ORCH-005"}
	RequirementIdGreenfieldOciEstateOwnership              = RequirementId{Value: "REQ-ORCH-006"}
	RequirementIdTypedRegionScopedProviderActuators        = RequirementId{Value: "REQ-ORCH-007"}
	RequirementIdAdmittedImmutableWorkloadPlacement        = RequirementId{Value: "REQ-ORCH-008"}
	RequirementIdTerraBaseTwoMemberPlacement               = RequirementId{Value: "REQ-ORCH-009"}
	RequirementIdProductServicesTwoInstancesPerRegion      = RequirementId{Value: "REQ-ORCH-010"}
	RequirementIdWorkloadIdentityTrustAndBootstrapGrants   = RequirementId{Value: "REQ-ORCH-011"}
	RequirementIdCloudflareRoutingTwentyRegionCeiling      = RequirementId{Value: "REQ-ORCH-012"}
	RequirementIdExactArtifactDeliveryAdmission            = RequirementId{Value: "REQ-ORCH-013"}
	RequirementIdSustainedCapacityAutoscaling              = RequirementId{Value: "REQ-ORCH-014"}
	RequirementIdDurableProgressAndTerminalReceipts        = RequirementId{Value: "REQ-ORCH-015"}
	RequirementIdControlStateBackupAndRestoreEvidence      = RequirementId{Value: "REQ-ORCH-016"}
	RequirementIdTypedOperatorInterface                    = RequirementId{Value: "REQ-ORCH-017"}
	RequirementIdProductionReleaseQualification            = RequirementId{Value: "REQ-ORCH-018"}
	RequirementIdTwentyRegionSimulation                    = RequirementId{Value: "REQ-ORCH-019"}
	RequirementIdNoControlPlaneLookupOnCustomerPath        = RequirementId{Value: "REQ-ORCH-020"}
	RequirementIdNoEmbeddedDevelopmentComposition          = RequirementId{Value: "REQ-ORCH-021"}
	RequirementIdParallelRegionalCandidateBeforeCutover    = RequirementId{Value: "REQ-ORCH-022"}
	RequirementIdHostCapacityPublication                   = RequirementId{Value: "REQ-ORCH-023"}
	RequirementIdClosedWorkloadExecutionContract           = RequirementId{Value: "REQ-ORCH-024"}
	RequirementIdResourceApiListWatchSurface               = RequirementId{Value: "REQ-ORCH-025"}
	RequirementIdDependencyAwareDeletion                   = RequirementId{Value: "REQ-ORCH-026"}
	RequirementIdBoundedCoalescingWorkQueues               = RequirementId{Value: "REQ-ORCH-027"}
	RequirementIdDisruptionSafeRebalancing                 = RequirementId{Value: "REQ-ORCH-028"}
)
