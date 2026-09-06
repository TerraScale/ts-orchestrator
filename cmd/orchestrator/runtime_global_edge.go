package main

import (
	"context"
	"errors"

	"terrascale.tech/orchestrator/src/orchestrator/control"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
)

// The master outlives individual elected sessions. Every call resolves the
// current session and rechecks its authority before reaching provider clients.
type productionGlobalEdge struct{ runtime *productionRuntime }

func (e productionGlobalEdge) current(ctx context.Context) (control.GlobalEdgeDelivery, error) {
	if e.runtime == nil {
		return nil, errors.New("global edge runtime is unavailable")
	}
	e.runtime.mu.Lock()
	group := e.runtime.active
	e.runtime.mu.Unlock()
	if group == nil || group.edge == nil || group.check == nil {
		return nil, errors.New("global edge authority is unavailable")
	}
	if err := group.check(ctx); err != nil {
		return nil, err
	}
	return group.edge, nil
}

func (e productionGlobalEdge) Observe(ctx context.Context, request *delivery.Request, artifact *delivery.ReleaseArtifact, fence delivery.OperationFence, check func(delivery.OperationFence) error) (bool, error) {
	provider, err := e.current(ctx)
	if err != nil {
		return false, err
	}
	return provider.Observe(ctx, request, artifact, fence, check)
}

func (e productionGlobalEdge) Apply(ctx context.Context, request *delivery.Request, artifact *delivery.ReleaseArtifact, fence delivery.OperationFence, check func(delivery.OperationFence) error) error {
	provider, err := e.current(ctx)
	if err != nil {
		return err
	}
	return provider.Apply(ctx, request, artifact, fence, check)
}
