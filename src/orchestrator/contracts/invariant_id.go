// Port of src/TerraScale.Orchestrator/Contracts/StableIdentifiers/InvariantId.cs.
package contracts

import "fmt"

// InvariantId is a permanent invariant identifier from the GOAL.md "Stable
// contract identifiers" table. Identifiers form a closed set: only values
// registered in StableIdentifierRegistry construct successfully, the canonical
// text of a live identifier never changes in place, and a replacement decision
// marks the retired identifier superseded and adds a new identifier instead of
// editing either one.
type InvariantId struct {
	Value string
}

// IsRegistered reports whether this value is one of the registered invariants.
func (i InvariantId) IsRegistered() bool {
	_, ok := StableIdentifierRegistry.tryGetInvariantText(i)
	return ok
}

// CanonicalText returns the verbatim GOAL.md text.
func (i InvariantId) CanonicalText() (string, error) {
	if text, ok := StableIdentifierRegistry.tryGetInvariantText(i); ok {
		return text, nil
	}
	return "", fmt.Errorf("invariant %q is not registered", i.Value)
}

// TryGetText mirrors StableIdentifierRegistry.TryGetText(InvariantId, out text).
func (i InvariantId) TryGetText() (string, bool) {
	return StableIdentifierRegistry.tryGetInvariantText(i)
}

// InvariantIdTryCreate mirrors InvariantId.TryCreate: only registered values pass.
func InvariantIdTryCreate(value string) (InvariantId, bool) {
	if _, ok := StableIdentifierRegistry.tryGetInvariantText(InvariantId{Value: value}); ok {
		return InvariantId{Value: value}, true
	}

	return InvariantId{}, false
}

// SupersededBy mirrors StableIdentifierRegistry.SupersededBy(InvariantId).
func (i InvariantId) SupersededBy() (InvariantId, bool) {
	return StableIdentifierRegistry.supersededInvariant(i)
}

func (i InvariantId) String() string { return i.Value }

// The registered invariant identifiers (C# static properties).
var (
	InvariantIdSingleAuthorityTermPerScope                = InvariantId{Value: "INV-ORCH-001"}
	InvariantIdGlobalPolicySingleWriter                   = InvariantId{Value: "INV-ORCH-002"}
	InvariantIdRegionalMutationNeedsLocalTermAndQuorum    = InvariantId{Value: "INV-ORCH-003"}
	InvariantIdIsolatedRegionCannotCreateGlobalGeneration = InvariantId{Value: "INV-ORCH-004"}
	InvariantIdObservationsAreNeverErased                 = InvariantId{Value: "INV-ORCH-005"}
	InvariantIdDurableIntentBeforeExternalMutation        = InvariantId{Value: "INV-ORCH-006"}
	InvariantIdUnknownOutcomeReconciledBeforeRetry        = InvariantId{Value: "INV-ORCH-007"}
	InvariantIdSingleActiveLifecycleOwner                 = InvariantId{Value: "INV-ORCH-008"}
	InvariantIdTagsNeverGrantAuthority                    = InvariantId{Value: "INV-ORCH-009"}
	InvariantIdStaleLeaderCannotCompleteMutation          = InvariantId{Value: "INV-ORCH-010"}
	InvariantIdCommittedTargetFixedAcrossLeadership       = InvariantId{Value: "INV-ORCH-011"}
	InvariantIdNoCustomerDataInNats                       = InvariantId{Value: "INV-ORCH-012"}
	InvariantIdTerraBaseAloneAcceptsMembership            = InvariantId{Value: "INV-ORCH-013"}
	InvariantIdScaleInPreservesDurabilityHeadroom         = InvariantId{Value: "INV-ORCH-014"}
	InvariantIdNoSecretsInStateOrTelemetry                = InvariantId{Value: "INV-ORCH-015"}
	InvariantIdExactQualifiedDigestActivation             = InvariantId{Value: "INV-ORCH-016"}
	InvariantIdDiscoveryAndPublicationAreSeparate         = InvariantId{Value: "INV-ORCH-017"}
	InvariantIdNoUnsafeIdentityReuse                      = InvariantId{Value: "INV-ORCH-018"}
	InvariantIdAdmissionPrecedesCapacity                  = InvariantId{Value: "INV-ORCH-019"}
	InvariantIdTelemetryNeverAuthorizesDestruction        = InvariantId{Value: "INV-ORCH-020"}
	InvariantIdNoInPlaceReleaseMutation                   = InvariantId{Value: "INV-ORCH-021"}
	InvariantIdNoDevelopmentCompositionInProduction       = InvariantId{Value: "INV-ORCH-022"}
	InvariantIdCandidateTrafficGates                      = InvariantId{Value: "INV-ORCH-023"}
	InvariantIdUniqueDurableEndpointLeases                = InvariantId{Value: "INV-ORCH-024"}
	InvariantIdDeletionBlockersHoldResources              = InvariantId{Value: "INV-ORCH-025"}
	InvariantIdObservedGenerationGate                     = InvariantId{Value: "INV-ORCH-026"}
	InvariantIdPressureStopsPlacementBeforeEviction       = InvariantId{Value: "INV-ORCH-027"}
	InvariantIdBoundedQueueOverload                       = InvariantId{Value: "INV-ORCH-028"}
)
