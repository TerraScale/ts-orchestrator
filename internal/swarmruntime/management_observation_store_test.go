package swarmruntime

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager/state"
	"github.com/moby/swarmkit/v2/manager/state/store"
	"github.com/moby/swarmkit/v2/watch"
)

type observationTestProposer struct {
	index   uint64
	floor   uint64
	changes []state.Change
}

func (p *observationTestProposer) ProposeValue(ctx context.Context, actions []api.StoreAction, commit func()) error {
	return p.ProposeValueAt(ctx, actions, func(api.Version) { commit() })
}

func (p *observationTestProposer) ProposeValueAt(_ context.Context, actions []api.StoreAction, commit func(api.Version)) error {
	p.index++
	version := api.Version{Index: p.index}
	p.changes = append(p.changes, state.Change{Version: version, StoreActions: actions})
	commit(version)
	return nil
}

// A committed log head and object metadata can lead the applied transaction.
func (p *observationTestProposer) GetVersion() *api.Version {
	return &api.Version{Index: p.index + 1000}
}

func (p *observationTestProposer) ChangesBetween(from, to api.Version) ([]state.Change, error) {
	if from.Index < p.floor || to.Index > p.index || from.Index > to.Index {
		return nil, errors.New("compacted or unavailable history")
	}
	var result []state.Change
	for _, change := range p.changes {
		if change.Version.Index > from.Index && change.Version.Index <= to.Index {
			result = append(result, change)
		}
	}
	return result, nil
}

func (p *observationTestProposer) ObservationChangesBetween(from, to api.Version) ([]state.Change, error) {
	return p.ChangesBetween(from, to)
}

func TestManagementObservationStoreBoundaries(t *testing.T) {
	p := new(observationTestProposer)
	s := store.NewMemoryStore(p)
	defer s.Close()
	if err := s.Update(func(tx store.Tx) error { return store.CreateNode(tx, &api.Node{ID: "first"}) }); err != nil {
		t.Fatal(err)
	}
	var node *api.Node
	at, _, live, _, cancel, err := s.Observe(nil, func(tx store.ReadTx) error { node = store.GetNode(tx, "first"); return nil }, api.EventCreateNode{}, state.EventCommit{})
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	if at.Index != 1 || node == nil || node.Meta.Version.Index <= at.Index {
		t.Fatalf("watermark came from committed head or object metadata: %+v %+v", at, node)
	}
	if err := s.Batch(func(batch *store.Batch) error {
		return batch.Update(func(tx store.Tx) error { return store.CreateNode(tx, &api.Node{ID: "second"}) })
	}); err != nil {
		t.Fatal(err)
	}
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case event := <-live:
			if committed, ok := event.(state.EventCommit); ok {
				if committed.Version == nil || committed.Version.Index != 2 {
					t.Fatalf("batch lost exact committed version: %+v", committed)
				}
				goto captured
			}
		case <-deadline.C:
			t.Fatal("batch did not deliver a transaction boundary")
		}
	}
captured:
	current, replay, _, _, stop, err := s.Observe(&at, func(store.ReadTx) error { return nil }, state.EventCommit{})
	if err != nil {
		t.Fatal(err)
	}
	stop()
	if current.Index != 2 || len(replay) != 1 || replay[0].Version.Index != 2 {
		t.Fatalf("bounded replay missed committed batch: %+v %+v", current, replay)
	}
	p.floor = 2
	if _, _, _, _, _, err := s.Observe(&at, func(store.ReadTx) error { return nil }, state.EventCommit{}); err == nil {
		t.Fatal("compaction gap accepted as continuous")
	}
	if _, _, _, _, _, err := s.Observe(&api.Version{Index: 3}, func(store.ReadTx) error { return nil }, state.EventCommit{}); err == nil {
		t.Fatal("future resume accepted as continuous")
	}
	// Restores bind their real snapshot index, without fake writes.
	if err := s.RestoreAt(&api.StoreSnapshot{}, api.Version{Index: 40}); err != nil {
		t.Fatal(err)
	}
	version, _, _, _, stop, err := s.Observe(nil, func(tx store.ReadTx) error {
		if store.GetNode(tx, "first") != nil || store.GetNode(tx, "second") != nil {
			return errors.New("restore did not replace state")
		}
		return nil
	}, state.EventCommit{})
	if err != nil {
		t.Fatal(err)
	}
	stop()
	if version.Index != 40 {
		t.Fatalf("restored snapshot lost exact applied version: %+v", version)
	}
	if err := s.RestoreAt(&api.StoreSnapshot{}, api.Version{Index: 41}); err != nil {
		t.Fatal(err)
	}
	version, _, _, _, stop, err = s.Observe(nil, func(store.ReadTx) error { return nil }, state.EventCommit{})
	if err != nil {
		t.Fatal(err)
	}
	stop()
	if version.Index != 41 {
		t.Fatalf("unchanged empty restore lost exact applied version: %+v", version)
	}
	action, err := api.NewStoreAction(api.EventCreateNode{Node: &api.Node{ID: "follower"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyStoreActionsAt([]api.StoreAction{action}, api.Version{Index: 42}); err != nil {
		t.Fatal(err)
	}
	version, _, _, _, stop, err = s.Observe(nil, func(tx store.ReadTx) error {
		if store.GetNode(tx, "follower") == nil {
			return errors.New("follower transaction missing from snapshot")
		}
		return nil
	}, state.EventCommit{})
	if err != nil {
		t.Fatal(err)
	}
	stop()
	if version.Index != 42 {
		t.Fatalf("follower transaction lost its applied version: %+v", version)
	}
}

func TestManagementObservationSlowConsumer(t *testing.T) {
	queue := watch.NewQueue()
	defer queue.Close()
	events, cancel, closed := queue.CallbackWatchBounded(nil)
	defer cancel()
	for i := range 4096 {
		queue.Publish(i)
	}
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case _, ok := <-events:
			if !ok {
				return
			}
		case <-closed:
			return
		case <-deadline.C:
			t.Fatal("overflow left a blocked stream or silently dropped continuity")
		}
	}
}
