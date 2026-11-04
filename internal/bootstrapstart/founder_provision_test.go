package bootstrapstart

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
)

func TestInitialSeedAdmissionInvokesFloorBeforeMarkerAndRestartNeverReinitializes(t *testing.T) {
	fixture := newAdmissionFlowFixture(t)
	fixture.ledger.state.Intent.Mode = bootstrap.IntentModeExternalSeed
	calls := 0
	fixture.gate.InitialFounderFloor = func(_ context.Context, marker AcceptedInstall, at time.Time) error {
		calls++
		if marker.Slot != marker.SeedSlot || marker.HeadAttempt != 1 || at.IsZero() {
			t.Fatalf("unverified initial seed floor inputs: %+v, %s", marker, at)
		}
		if _, err := fixture.gate.Markers.ReadIdentity(); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("marker persisted before durable floor: %v", err)
		}
		return nil
	}
	if _, err := fixture.gate.AdmitInitial(t.Context()); err != nil || calls != 1 {
		t.Fatalf("initial floor callback: calls=%d err=%v", calls, err)
	}
	if _, err := fixture.gate.AdmitRestart(t.Context()); err != nil || calls != 1 {
		t.Fatalf("restart reinitialized initial floor: calls=%d err=%v", calls, err)
	}
}
