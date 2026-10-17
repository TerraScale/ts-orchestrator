package controlapi

import (
	"context"
	"errors"

	"github.com/gogo/protobuf/proto"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager/state/store"
)

type nodeObservationKey struct{}
type nodeObservation struct {
	expected *api.Node
	check    func(store.ReadTx) error
}

// UpdateNodeAtObservation retains native validation and NodeVersion CAS while
// checking the complete original node inside the same store transaction.
func (s *Server) UpdateNodeAtObservation(ctx context.Context, expected *api.Node, request *api.UpdateNodeRequest, check func(store.ReadTx) error) (*api.UpdateNodeResponse, error) {
	if ctx == nil || expected == nil || request == nil || request.NodeVersion == nil || check == nil ||
		request.NodeID != expected.ID || request.NodeVersion.Index != expected.Meta.Version.Index {
		return nil, errors.New("observed node update requires the exact captured node and version")
	}
	ctx = context.WithValue(ctx, nodeObservationKey{}, nodeObservation{expected.Copy(), check})
	return s.UpdateNode(ctx, request.Copy())
}

// RemoveNodeAtObservation adds the missing full-node CAS to native non-force
// removal, retaining certificate blacklisting and task orphaning atomically.
func (s *Server) RemoveNodeAtObservation(ctx context.Context, expected *api.Node, check func(store.ReadTx) error) (*api.RemoveNodeResponse, error) {
	if ctx == nil || expected == nil || expected.ID == "" || check == nil {
		return nil, errors.New("observed node removal requires the exact captured node")
	}
	ctx = context.WithValue(ctx, nodeObservationKey{}, nodeObservation{expected.Copy(), check})
	return s.RemoveNode(ctx, &api.RemoveNodeRequest{NodeID: expected.ID, Force: false})
}

func (s *Server) updateObservedNode(ctx context.Context, update func(store.Tx) error) error {
	original, observed := ctx.Value(nodeObservationKey{}).(nodeObservation)
	if !observed {
		return s.store.Update(update)
	}
	return s.store.UpdateContext(ctx, func(tx store.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		current := store.GetNode(tx, original.expected.ID)
		if current == nil || !proto.Equal(current, original.expected) {
			return errors.New("observed node changed before native mutation")
		}
		if err := original.check(tx); err != nil {
			return err
		}
		return update(tx)
	})
}
