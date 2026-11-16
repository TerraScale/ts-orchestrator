package swarmruntime

import (
	"context"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
	"github.com/moby/swarmkit/v2/api"
)

type localControl struct {
	api.ControlClient
	state string
}

func isLocalNode(ctx context.Context, client api.ControlClient, node *api.Node, hostname string) bool {
	if node.Description.Hostname == hostname {
		return true
	}
	local, ok := client.(localControl)
	if !ok {
		return false
	}
	id, err := LocalNodeID(ctx, local.state)
	return err == nil && id == node.ID
}

// All CLI and mesh writers lock the same root, including hostname claims.
func lockServiceSpecs(ctx context.Context, client api.ControlClient) (func(), error) {
	local, ok := client.(localControl)
	if !ok {
		return func() {}, nil
	}
	lock := flock.New(filepath.Join(local.state, "service-spec.lock"))
	if _, err := lock.TryLockContext(ctx, 10*time.Millisecond); err != nil {
		return nil, err
	}
	return func() { _ = lock.Unlock() }, nil
}
