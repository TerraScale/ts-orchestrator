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
			CellId: context.CellId, CompartmentId: context.CompartmentId,
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
