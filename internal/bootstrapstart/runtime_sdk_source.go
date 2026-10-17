package bootstrapstart

import (
	"context"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
)

// Runtime observations retain the acquisition source chosen by their reader.
// Production readers always acquire the original instance-principal SDKs.
type controllerRuntimeSDKSource interface {
	instanceObserver(context.Context, bootstrap.LedgerConfig) (*OCIInstanceObserver, error)
	ledger(context.Context, bootstrap.LedgerConfig) (SlotReader, error)
}

type instancePrincipalControllerSDK struct{}

func (instancePrincipalControllerSDK) instanceObserver(ctx context.Context, config bootstrap.LedgerConfig) (*OCIInstanceObserver, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrInstanceObservation
	}
	provider, err := newOCIAdmissionProvider(config)
	if err != nil {
		return nil, err
	}
	return NewOCIInstanceObserver(config.Cell, provider)
}

func (instancePrincipalControllerSDK) ledger(ctx context.Context, config bootstrap.LedgerConfig) (SlotReader, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrAdmission
	}
	return openInstancePrincipalLedger(ctx, config, nil)
}
