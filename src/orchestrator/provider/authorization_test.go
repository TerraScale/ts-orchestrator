package provider

import "testing"

func TestAuthorizeRejectsUnknownCallStatus(t *testing.T) {
	context := testContext(t, ActionExpandVolume,
		ExistingProviderResource{ProviderResourceId{"ocid1.volume.oc1.x"}},
		ExpandVolumeProviderParameters{ProviderByteCount{2 << 30}})
	request := ProviderAuthorizationRequest{
		Context: context,
		Authority: &RegionalProviderAuthority{
			CellId: context.CellId, CompartmentId: context.CompartmentId,
			CurrentEpoch: context.ControllerEpoch,
		},
		OwnershipRecords: []ProviderOwnershipRecord{{
			ResourceId: context.Target.(ExistingProviderResource).Id,
			CellId:     context.CellId, CompartmentId: context.CompartmentId,
			Generation: context.ExpectedGeneration,
		}},
		ObservationCompleteness: EvidenceComplete,
		Observations: []ProviderResourceObservation{{
			ResourceId: context.Target.(ExistingProviderResource).Id,
			Generation: context.ExpectedGeneration, State: context.ExpectedObservedState,
		}},
		CallEvidence: ProviderCallEvidence{Context: context, Status: ProviderCallStatus(99)},
	}

	decision := Authorize(request)
	if decision.Authorized || len(decision.Intents) != 0 {
		t.Fatalf("unknown call status must not authorize a provider intent: %+v", decision)
	}
}

func TestEvaluateHandoffRejectsInvalidInventoryAndScope(t *testing.T) {
	// A literal can bypass NewFreshBootstrapInventory/NewHandoffScope, so the
	// evaluator must fail closed at its own trust boundary as well.
	scope := HandoffScope{}
	proof := HandoffProof{Scope: scope, Status: HandoffVerified}
	decision := EvaluateHandoff(HandoffRequest{
		ExpectedScope:                      scope,
		CurrentAcceptedBootstrapGeneration: ProviderGeneration{Value: 0},
		Evidence: HandoffEvidence{
			RetainUnmanage: proof, RegionalJournalReceipt: proof, ProviderReady: proof,
			TrustReady: proof, BackupReady: proof, RegionalFenceActivated: proof,
		},
	})
	if decision.Ready || decision.Intent != nil {
		t.Fatalf("invalid handoff evidence must not be ready: %+v", decision)
	}
}
