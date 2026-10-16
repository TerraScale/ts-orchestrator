package nodescale

import (
	"context"
	"fmt"
	"sync"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

// ChosenPool binds OCI mutations to the recipe retained in the scaler's
// existing record. Restarting never substitutes the controller's own shape.
type ChosenPool struct {
	observed *OCIPool
	store    RecordStore
	mu       sync.Mutex
	chosen   *OCIPool
}

func NewChosenPool(observed *OCIPool, store RecordStore) (*ChosenPool, error) {
	if observed == nil || store == nil {
		return nil, fmt.Errorf("chosen capacity requires observed OCI pools and durable scaler state")
	}
	return &ChosenPool{observed: observed, store: store}, nil
}

func (pool *ChosenPool) selected(ctx context.Context) (*OCIPool, *Recipe, error) {
	record, _, err := pool.store.Load(ctx)
	if err != nil {
		return nil, nil, err
	}
	if record.Recipe == nil {
		return pool.observed, nil, nil
	}
	if err := record.Recipe.Validate(); err != nil || record.Recipe.Cell != pool.observed.cell || record.Recipe.Capacity.Role != pool.observed.capacity.Role {
		return nil, nil, fmt.Errorf("%w: durable chosen pool recipe is invalid", ErrCapacityPending)
	}
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if pool.chosen == nil || pool.chosen.capacity != record.Recipe.Capacity {
		chosen, err := newOCIPool(pool.observed.management, pool.observed.compute, pool.observed.network,
			pool.observed.cell, pool.observed.compartmentID, record.Recipe.Capacity)
		if err != nil {
			return nil, nil, err
		}
		if pool.observed.Admit != nil {
			chosen.Admit = func(ctx context.Context, recipe Recipe) (func(), error) {
				release, err := pool.observed.admit(ctx, recipe)
				if err != nil {
					return nil, err
				}
				current, _, err := pool.store.Load(ctx)
				if err != nil || current.Recipe == nil || current.Recipe.SHA256() != recipe.SHA256() || current.Action == nil ||
					current.Action.Kind != Up || current.Action.ID != chosen.operationID {
					release()
					return nil, fmt.Errorf("%w: durable chosen pool recipe changed", ErrCapacityPending)
				}
				return release, nil
			}
		}
		pool.chosen = chosen
	}
	operationID := ""
	if record.Action != nil && record.Action.Kind == Up {
		operationID = record.Action.ID
	}
	if pool.chosen.operationID != operationID {
		pool.chosen.recipe, pool.chosen.configurationID = nil, ""
		pool.chosen.operationID = operationID
	}
	return pool.chosen, record.Recipe, nil
}

func (pool *ChosenPool) Observe(ctx context.Context) (PoolState, error) {
	chosen, _, err := pool.selected(ctx)
	if err != nil {
		return PoolState{}, err
	}
	return chosen.Observe(ctx)
}

func (pool *ChosenPool) Ensure(ctx context.Context, recipe Recipe) (PoolState, error) {
	chosen, current, err := pool.selected(ctx)
	if err != nil {
		return PoolState{}, err
	}
	if current == nil || current.SHA256() != recipe.SHA256() || !entityid.Valid(chosen.operationID) {
		return PoolState{}, fmt.Errorf("%w: launch recipe has not been chosen durably", ErrCapacityPending)
	}
	return chosen.Ensure(ctx, recipe)
}

func (pool *ChosenPool) Grow(ctx context.Context, from int) error {
	chosen, current, err := pool.selected(ctx)
	if err != nil {
		return err
	}
	if current == nil || !entityid.Valid(chosen.operationID) {
		return fmt.Errorf("%w: launch recipe has not been chosen durably", ErrCapacityPending)
	}
	return chosen.Grow(ctx, from)
}

func (pool *ChosenPool) Name(ctx context.Context, instanceID, node string) error {
	chosen, _, err := pool.selected(ctx)
	if err != nil {
		return err
	}
	return chosen.Name(ctx, instanceID, node)
}

func (pool *ChosenPool) Remove(ctx context.Context, instanceID string) error {
	chosen, _, err := pool.selected(ctx)
	if err != nil {
		return err
	}
	return chosen.Remove(ctx, instanceID)
}

var _ Pool = (*ChosenPool)(nil)
