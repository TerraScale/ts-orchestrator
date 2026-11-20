package manager

import (
	"errors"

	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager/state/store"
	etcdraft "go.etcd.io/raft/v3"
)

var ErrNotRaftLeader = errors.New("raft voters are read and changed on the Raft leader")

type Voter struct {
	NodeID    string
	Reachable bool
	CaughtUp  bool
}

func (m *Manager) voters(observation *Observation) ([]Voter, error) {
	if err := m.ValidateObservation(observation); err != nil {
		return nil, err
	}
	status := m.raftNode.Status()
	if status.RaftState != etcdraft.StateLeader || status.Lead != status.ID {
		return nil, ErrNotRaftLeader
	}
	members := m.raftNode.GetMemberlist()
	voters := make([]Voter, 0, len(members))
	for raftID, member := range members {
		progress, tracked := status.Progress[raftID]
		voters = append(voters, Voter{NodeID: member.NodeID, Reachable: member.Status.Reachability == api.RaftMemberStatus_REACHABLE,
			CaughtUp: tracked && progress.Match >= status.Commit})
	}
	return voters, nil
}

func (m *Manager) ViewMembership(observation *Observation, view func(store.ReadTx, []Voter) error) error {
	if m == nil || m.raftNode == nil {
		return errors.New("raft membership unavailable")
	}
	var err error
	m.raftNode.MemoryStore().View(func(tx store.ReadTx) {
		var voters []Voter
		if voters, err = m.voters(observation); err == nil {
			err = view(tx, voters)
		}
	})
	return err
}

func (m *Manager) UpdateMembership(observation *Observation, update func(store.Tx, []Voter) error) error {
	if m == nil || m.raftNode == nil {
		return errors.New("raft membership unavailable")
	}
	return m.raftNode.MemoryStore().Update(func(tx store.Tx) error {
		voters, err := m.voters(observation)
		if err != nil {
			return err
		}
		return update(tx, voters)
	})
}
