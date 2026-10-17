package bootstrapstart

import (
	"context"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
)

func TestRuntimeSDKAcquisitionRejectsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, input := range []context.Context{nil, ctx} {
		if observer, err := (instancePrincipalControllerSDK{}).instanceObserver(input, bootstrap.LedgerConfig{}); err == nil || observer != nil {
			t.Fatal("invalid caller context reached instance-principal observer acquisition")
		}
		if ledger, err := (instancePrincipalControllerSDK{}).ledger(input, bootstrap.LedgerConfig{}); err == nil || ledger != nil {
			t.Fatal("invalid caller context reached instance-principal ledger acquisition")
		}
	}
}
