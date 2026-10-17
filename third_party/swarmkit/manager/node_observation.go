package manager

import (
	"context"
	"errors"
	"fmt"

	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager/controlapi"
	"github.com/moby/swarmkit/v2/manager/internal/mutationcontext"
	"github.com/moby/swarmkit/v2/manager/state/store"
)

// ErrMutationAmbiguous requires reconciliation of the same admitted operation.
// Neither cancellation nor leadership loss rolls back a committed Raft entry.
var ErrMutationAmbiguous = mutationcontext.ErrAmbiguous

// UpdateNodeAtObservation performs the native update against the full captured
// node and original leadership epoch. The check must use only its supplied
// ReadTx and in-memory owner guards; it must not perform I/O or open a new view.
func (m *Manager) UpdateNodeAtObservation(ctx context.Context, original *Observation, expected *api.Node, request *api.UpdateNodeRequest, check func(store.ReadTx) error) (*api.UpdateNodeResponse, error) {
	guarded, validate, err := m.nodeMutationContext(ctx, original, check)
	if err != nil {
		return nil, err
	}
	server := controlapi.NewServer(m.raftNode.MemoryStore(), m.raftNode, nil, nil, nil)
	response, err := server.UpdateNodeAtObservation(guarded, expected, request, validate)
	if err := m.nodeMutationResult(guarded, original, err); err != nil {
		return nil, err
	}
	return response, nil
}

// RemoveNodeAtObservation retains native Force=false removal and supplements
// its unversioned request with the exact original node in the locked transaction.
func (m *Manager) RemoveNodeAtObservation(ctx context.Context, original *Observation, expected *api.Node, check func(store.ReadTx) error) (*api.RemoveNodeResponse, error) {
	guarded, validate, err := m.nodeMutationContext(ctx, original, check)
	if err != nil {
		return nil, err
	}
	server := controlapi.NewServer(m.raftNode.MemoryStore(), m.raftNode, nil, nil, nil)
	response, err := server.RemoveNodeAtObservation(guarded, expected, validate)
	if err := m.nodeMutationResult(guarded, original, err); err != nil {
		return nil, err
	}
	return response, nil
}

func (m *Manager) nodeMutationContext(ctx context.Context, original *Observation, check func(store.ReadTx) error) (context.Context, func(store.ReadTx) error, error) {
	if ctx == nil || original == nil || check == nil {
		return nil, nil, errors.New("node mutation requires original authority and observation")
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if err := m.ValidateObservation(original); err != nil {
		return nil, nil, err
	}
	guarded := mutationcontext.WithEpoch(ctx, original.Term, original.Leader)
	validate := func(tx store.ReadTx) error {
		if err := guarded.Err(); err != nil {
			return err
		}
		if err := m.ValidateObservation(original); err != nil {
			return err
		}
		return check(tx)
	}
	return guarded, validate, nil
}

func (m *Manager) nodeMutationResult(ctx context.Context, original *Observation, result error) error {
	guardErr := ctx.Err()
	if guardErr == nil {
		guardErr = m.ValidateObservation(original)
	}
	if mutationcontext.Submitted(ctx) && (result != nil || guardErr != nil) {
		return fmt.Errorf("%w: %w", ErrMutationAmbiguous, errors.Join(result, guardErr))
	}
	return errors.Join(result, guardErr)
}
