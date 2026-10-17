package store

import (
	"context"
	"errors"

	"github.com/docker/go-events"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager/state"
)

func proposeAt(proposer state.Proposer, actions []api.StoreAction, commit func(*api.Version)) error {
	if versioned, ok := proposer.(interface {
		ProposeValueAt(context.Context, []api.StoreAction, func(api.Version)) error
	}); ok {
		return versioned.ProposeValueAt(context.Background(), actions, func(version api.Version) { commit(&version) })
	}
	return proposer.ProposeValue(context.Background(), actions, func() { commit(nil) })
}

// Observe captures a read-only view and live subscription at the same applied
// Raft boundary. Replay contains every committed action after from through at;
// historical update events have no old object and must not imply no change.
func (s *MemoryStore) Observe(from *api.Version, view func(ReadTx) error, specifiers ...api.Event) (at api.Version, replay []state.Change, live chan events.Event, cancel func(), err error) {
	s.updateLock.Lock()
	if s.appliedVersion == nil || s.proposer == nil {
		s.updateLock.Unlock()
		return at, nil, nil, nil, errors.New("applied Raft observation version unavailable")
	}
	at = *s.appliedVersion
	if from != nil && from.Index > at.Index {
		s.updateLock.Unlock()
		return at, nil, nil, nil, errors.New("observation resume version is ahead of applied state")
	}
	s.View(func(tx ReadTx) { err = view(tx) })
	if err == nil {
		live, cancel = s.queue.CallbackWatchBounded(state.Matcher(specifiers...))
	}
	s.updateLock.Unlock()
	if err != nil {
		return at, nil, nil, nil, err
	}
	if from != nil {
		if history, ok := s.proposer.(interface {
			ObservationChangesBetween(api.Version, api.Version) ([]state.Change, error)
		}); ok {
			replay, err = history.ObservationChangesBetween(*from, at)
		} else {
			err = errors.New("bounded observation replay unavailable")
		}
		if err != nil {
			cancel()
			return at, nil, nil, nil, err
		}
	}
	return at, replay, live, cancel, nil
}
