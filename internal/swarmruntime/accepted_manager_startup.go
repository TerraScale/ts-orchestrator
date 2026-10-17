package swarmruntime

import (
	"context"
	"errors"
	"fmt"

	"github.com/moby/swarmkit/v2/agent/exec"
	"github.com/moby/swarmkit/v2/api"
	swarmnode "github.com/moby/swarmkit/v2/node"
)

type pausedManagerExecutor struct {
	exec.Executor
	ready chan struct{}
}

func (e *pausedManagerExecutor) Describe(ctx context.Context) (*api.NodeDescription, error) {
	// Describe precedes agent registration and restoration of persisted tasks.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-e.ready:
		return e.Executor.Describe(ctx)
	}
}

func pauseManagerBeforeAgent(ctx context.Context, node *swarmnode.Node) error {
	// Config.Availability does not replace a persisted ACTIVE node spec.
	waitCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	for conn := range node.ListenControlSocket(waitCtx) {
		if conn == nil {
			continue
		}
		client := api.NewControlClient(conn)
		current, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: node.NodeID()})
		if err != nil {
			return fmt.Errorf("observe manager before agent registration: %w", err)
		}
		if current.Node == nil || current.Node.Certificate.CN != node.NodeID() || current.Node.Certificate.Role != api.NodeRoleManager {
			return errors.New("manager startup barrier requires its persisted manager identity")
		}
		spec := current.Node.Spec.Copy()
		spec.Availability = api.NodeAvailabilityPause
		if _, err := client.UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: current.Node.ID, NodeVersion: &current.Node.Meta.Version, Spec: spec}); err != nil {
			return fmt.Errorf("pause manager before agent registration: %w", err)
		}
		paused, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: current.Node.ID})
		if err != nil {
			return fmt.Errorf("verify manager startup pause: %w", err)
		}
		if paused.Node == nil || paused.Node.Spec.Availability != api.NodeAvailabilityPause {
			return errors.New("manager availability changed before agent registration")
		}
		return nil
	}
	return ctx.Err()
}
