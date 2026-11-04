package bootstrapstart

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
)

func TestLocalRestartAdmissionNeedsNoInitialInputsOCIOrClock(t *testing.T) {
	fixture := newAdmissionFlowFixture(t)
	if _, err := fixture.gate.AdmitInitial(t.Context()); err != nil {
		t.Fatal(err)
	}
	accepted, err := fixture.gate.Markers.ReadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(fixture.gate.Markers.directory, initialFormationName)); err != nil {
		t.Fatal(err)
	}
	local := fixture.gate
	local.Roots, local.AnchorWire, local.Expected = nil, nil, bootstrap.BootstrapAnchorExpectation{}
	local.Instances, local.Ledgers, local.InitialIdentity = nil, nil, nil
	local.ClockCheck = func() error { t.Fatal("local routes checked NTP"); return nil }
	fixture.ledger.state = bootstrap.SlotState{}
	calls, published := fixture.ledger.currentCalls, len(fixture.ledger.published)
	admitted, err := local.AdmitRestartLocal(t.Context())
	if err != nil || admitted.OperationID != accepted.OperationID {
		t.Fatalf("local restart without initial files/history = %+v, %v", admitted, err)
	}
	if fixture.ledger.currentCalls != calls || fixture.ledger.historyCalls != 0 || len(fixture.ledger.published) != published {
		t.Fatal("local admission touched the ledger")
	}
	if fixture.material.restartCalls != 1 || fixture.credentials.calls != 2 {
		t.Fatal("local admission skipped installed material or live credentials")
	}
	for name, mutate := range map[string]func(*Gate){
		"another instance": func(g *Gate) {
			g.Descriptor = fixedDescriptor{slot: accepted.Slot, instance: "ocid1.instance.oc1.sa-saopaulo-1.other"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			gate := local
			mutate(&gate)
			if _, err := gate.AdmitRestartLocal(t.Context()); !errors.Is(err, ErrAdmission) {
				t.Fatalf("accepted invalid local boundary: %v", err)
			}
		})
	}
	fixture.credentials.err = ErrLiveCredentials
	if _, err := local.AdmitRestartLocal(t.Context()); !errors.Is(err, ErrLiveCredentials) {
		t.Fatalf("invalid live credentials admitted: %v", err)
	}
}

type instanceObserverFunc func(context.Context, string) (InstanceObservation, error)

func (observe instanceObserverFunc) ObserveInstance(ctx context.Context, id string) (InstanceObservation, error) {
	return observe(ctx, id)
}
