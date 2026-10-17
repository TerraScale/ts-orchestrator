package manager

import (
	"errors"

	"github.com/docker/go-events"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager/state"
	"github.com/moby/swarmkit/v2/manager/state/store"
)

// Observation is a read-only capture of one manager's applied store boundary.
// Its identity must remain current; cancellation, close or leadership change
// invalidates continuity. Replay updates do not contain old objects.
type Observation struct {
	Version api.Version
	Term    uint64
	Leader  uint64
	Replay  []state.Change
	Events  <-chan events.Event
	Closed  <-chan struct{}
	Cancel  func()
}

// Observe atomically captures the supplied read-only projection and subscribes
// to subsequent transactions, with exact available WAL replay after from.
func (m *Manager) Observe(from *api.Version, view func(store.ReadTx) error, specifiers ...api.Event) (*Observation, error) {
	if m == nil || m.raftNode == nil || view == nil {
		return nil, errors.New("manager observation unavailable")
	}
	current := m.raftNode.Status()
	if current.Lead == 0 || current.Term == 0 || !m.raftNode.IsMember() {
		return nil, errors.New("manager observation requires current Raft membership and leader")
	}
	at, replay, live, closed, cancel, err := m.raftNode.MemoryStore().Observe(from, view, specifiers...)
	if err != nil {
		return nil, err
	}
	observation := &Observation{Version: at, Term: current.Term, Leader: current.Lead, Replay: replay, Events: live, Closed: closed, Cancel: cancel}
	if err := m.ValidateObservation(observation); err != nil {
		cancel()
		return nil, err
	}
	return observation, nil
}

// ValidateObservation rejects a stopped, replaced or changed leadership epoch.
func (m *Manager) ValidateObservation(observation *Observation) error {
	if m == nil || m.raftNode == nil || observation == nil || !m.raftNode.IsMember() {
		return errors.New("manager observation membership changed")
	}
	select {
	case <-m.raftNode.Done():
		return errors.New("manager observation stopped")
	default:
	}
	current := m.raftNode.Status()
	if current.Term != observation.Term || current.Lead != observation.Leader || current.Lead == 0 {
		return errors.New("manager observation leadership changed")
	}
	return nil
}
