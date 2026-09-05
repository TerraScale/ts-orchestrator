package vmqualruntime

import (
	"context"

	"terrascale.tech/orchestrator/src/orchestrator/guestdiagnostic"
)

func (v *sandboxVM) failStartup(ctx context.Context, cause error) error {
	return guestdiagnostic.RetainStartupFailure(ctx, v.executor, cause, func(stopCtx context.Context) error { return v.provider.Stop(stopCtx, v.id) })
}
