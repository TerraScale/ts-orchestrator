//go:build linux

package controlleractivation

import (
	"context"
	"errors"

	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager"
)

// Activate submits once, preserving the original call, lease and deadline.
func (admitted *Admission) Activate(ctx context.Context, nodeID string, expectedVersion uint64) (*api.Node, error) {
	if err := admitted.guard(ctx); err != nil {
		return nil, err
	}
	ctx, cancel, err := admitted.operationContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	updated, err := admitted.node.ActivateControllerNode(ctx, nodeID, expectedVersion, admitted.lease.Epoch())
	if err != nil {
		return nil, err
	}
	if err := admitted.guard(ctx); err != nil {
		return nil, errors.Join(manager.ErrMutationAmbiguous, err)
	}
	return updated, nil
}
