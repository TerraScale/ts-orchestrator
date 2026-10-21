package region

import (
	"context"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

type originalCheckpointContext struct {
	context.Context
	values context.Context
}

func (ctx originalCheckpointContext) Value(key any) any {
	return ctx.values.Value(key)
}

// Preserve the owning lease and root guard values, with the active dispatch lifetime.
func originalProviderCheckpointContext(dispatch, lease context.Context) context.Context {
	return ociclient.CheckpointContext(originalCheckpointContext{
		Context: dispatch,
		values:  lease,
	})
}
