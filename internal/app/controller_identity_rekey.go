package app

import (
	"context"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
)

// checkControllerIdentityRekeyCompletion makes no cloud or broker mutation.
func checkControllerIdentityRekeyCompletion(ctx context.Context, cfg Config) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	gate, _, err := acceptedControllerAdmissionGate(cfg, bootstrapstart.NewMarkerStore(), nil)
	if err != nil {
		return err
	}
	accepted, err := gate.AdmitIdentityRekeyCompletion(ctx)
	if err != nil {
		return err
	}
	client := cfg.NATS
	client.Embedded, client.ClientRole = nil, "controller"
	runtime, err := natscell.Start(ctx, client)
	if err != nil {
		return err
	}
	defer runtime.Close()
	return bootstrapstart.VerifyIdentityRekeyCompletion(ctx, accepted, runtime.JetStream())
}
