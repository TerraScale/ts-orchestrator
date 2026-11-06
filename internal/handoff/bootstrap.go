package handoff

import (
	"context"
	"errors"
	"github.com/TerraScale/ts-orchestrator/internal/rolloutmaintenance"
	"sync/atomic"
)

type bootstrapCall func(context.Context, string, rolloutmaintenance.Job) error

var bootstrapRPC atomic.Pointer[bootstrapCall]

func SetBootstrap(call func(context.Context, string, rolloutmaintenance.Job) error) {
	fn := bootstrapCall(call)
	bootstrapRPC.Store(&fn)
}
func Bootstrap(ctx context.Context, action string, j rolloutmaintenance.Job) error {
	fn := bootstrapRPC.Load()
	if fn == nil {
		return errors.New("regional bootstrap coordinator unavailable")
	}
	return (*fn)(ctx, action, j)
}
