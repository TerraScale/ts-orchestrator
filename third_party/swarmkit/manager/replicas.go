package manager

import (
	"context"
	"errors"

	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager/state/store"
)

func (m *Manager) ReplicaAuthority() (uint64, error) {
	if m == nil || m.raftNode == nil || !m.raftNode.IsMember() {
		return 0, errors.New("replica authority unavailable")
	}
	current := m.raftNode.Status()
	if current.Lead == 0 || current.Lead != current.ID {
		return 0, errors.New("replica authority requires the local Raft leader")
	}
	return current.Term, nil
}

func (m *Manager) ScaleReplicas(ctx context.Context, term uint64, id string, version api.Version, replicas uint64) error {
	if _, err := m.ReplicaAuthority(); err != nil {
		return err
	}
	return m.raftNode.MemoryStore().Update(func(tx store.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		current, err := m.ReplicaAuthority()
		if err != nil {
			return err
		}
		if term != current {
			return errors.New("replica authority term changed")
		}
		service := store.GetService(tx, id)
		if service == nil || service.Meta.Version != version || service.Spec.GetReplicated() == nil {
			return errors.New("replica decision was superseded")
		}
		service.Spec.GetReplicated().Replicas = replicas
		service.SpecVersion = service.Meta.Version.Copy()
		return store.UpdateService(tx, service)
	})
}
