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

type clearPeerCall func(context.Context, string, string) error

var clearPeerRPC atomic.Pointer[clearPeerCall]

// SetClearPeer binds the mesh request that clears a regional peer's verified fence.
func SetClearPeer(call func(context.Context, string, string) error) {
	fn := clearPeerCall(call)
	clearPeerRPC.Store(&fn)
}

func ClearPeer(ctx context.Context, peer, id string) error {
	fn := clearPeerRPC.Load()
	if fn == nil {
		return errors.New("regional mesh unavailable")
	}
	return (*fn)(ctx, peer, id)
}
