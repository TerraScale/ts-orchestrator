package app

import (
	"context"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
)

// Backoff bounds for the supervised seed founder and for repeated full
// restart admission in offline-first mode. Tests shorten them.
var ()

// admitProductionControllerRestartLocal runs in the service-account
// controller itself: it makes no OCI SDK call, so it needs no child process.
func admitProductionControllerRestartLocal(ctx context.Context, cfg Config) error {
	gate, _, err := acceptedControllerAdmissionGate(cfg, bootstrapstart.NewMarkerStore(), nil)
	if err != nil {
		return err
	}
	_, err = gate.AdmitRestartLocal(ctx)
	return err
}
