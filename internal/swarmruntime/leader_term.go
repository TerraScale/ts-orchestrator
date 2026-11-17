package swarmruntime

import (
	"context"
	"errors"

	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager/state/store"
)

func (n *Node) LeaderTerm(ctx context.Context) (uint64, func(context.Context) error, error) {
	manager := n.upstream.Manager()
	if manager == nil {
		return 0, nil, errors.New("leader term requires a current manager")
	}
	epoch, err := manager.Observe(nil, func(store.ReadTx) error { return nil })
	if err != nil {
		return 0, nil, err
	}
	epoch.Cancel()
	client, err := n.ControlClient(ctx)
	if err != nil {
		return 0, nil, err
	}
	listed, err := client.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil {
		return 0, nil, err
	}
	if !IsLeader(listed.Nodes, n.ID()) {
		return 0, nil, errors.New("this manager is not the Raft leader")
	}
	guard := func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if n.upstream.Manager() != manager {
			return errors.New("the manager was replaced")
		}
		return manager.ValidateObservation(epoch)
	}
	return epoch.Term, guard, guard(ctx)
}
