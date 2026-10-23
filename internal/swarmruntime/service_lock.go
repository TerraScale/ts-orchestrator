package swarmruntime

import (
	"context"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
	"github.com/moby/swarmkit/v2/api"
)

type singleHostControl struct {
	api.ControlClient
	state string
}

// All CLI and mesh writers lock the same root, including hostname claims.
func lockServiceSpecs(ctx context.Context, client api.ControlClient) (func(), error) {
	local, ok := client.(singleHostControl)
	if !ok {
		return func() {}, nil
	}
	lock := flock.New(filepath.Join(local.state, "service-spec.lock"))
	if _, err := lock.TryLockContext(ctx, 10*time.Millisecond); err != nil {
		return nil, err
	}
	return func() { _ = lock.Unlock() }, nil
}
