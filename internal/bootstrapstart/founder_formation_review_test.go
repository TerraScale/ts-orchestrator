package bootstrapstart

import (
	"context"
	"errors"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
)

// A co-located plan is refused before its peer row is reserved in the
// ledger, so a corrected, re-signed plan can still reserve the slot.
func TestAntiAffinityRefusalLeavesThePeerSlotUnreserved(t *testing.T) {
	fixture, caller, _, fake := newUnreservedFounderRuntimeFixture(t)
	slot := fixture.plan.Peers[0].Slot
	caller.placement = func(context.Context) (bootstrap.ControllerPlacement, error) {
		return bootstrap.ControllerPlacement{AvailabilityDomain: "Abcd:SA-SAOPAULO-1-AD-1",
			FaultDomain: fixture.plan.Peers[0].FaultDomain}, nil
	}
	if err := caller.runPeer(t.Context(), slot); !errors.Is(err, bootstrap.ErrControllerAntiAffinity) {
		t.Fatalf("co-located founder launch was not refused: %v", err)
	}
	if _, err := caller.fresh(t.Context(), slot); !errors.Is(err, errFounderPeerUnreserved) {
		t.Fatalf("refused plan reserved the peer slot: %v", err)
	}
	if fake.launches != 0 {
		t.Fatalf("refused anti-affinity launched %d instances", fake.launches)
	}
}
