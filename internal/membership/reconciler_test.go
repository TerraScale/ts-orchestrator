package membership

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
)

type fakeLeadership struct {
	mu       sync.Mutex
	snapshot authority.Snapshot
	guardErr error
	guards   int
}

func leaderSnapshot(epoch uint64) authority.Snapshot {
	return authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Ready: true, Leader: true, Epoch: epoch, Revision: 1,
		ExpiresAt: time.Now().Add(time.Hour)}
}

func (f *fakeLeadership) Current() authority.Snapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.snapshot
}

func (f *fakeLeadership) Guard(_ context.Context, epoch uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.guards++
	if f.guardErr != nil {
		return f.guardErr
	}
	if f.snapshot.Epoch != epoch {
		return authority.ErrFenced
	}
	return nil
}

type fakeCell struct {
	mu        sync.Mutex
	meta      Meta
	ledger    map[string]LedgerSlot
	lifecycle map[string]string
	evidence  map[string]Evidence
	metaErr   error
	replaced  []Action
	replace   func(Action) error
}

func (f *fakeCell) Meta(context.Context) (Meta, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.meta, f.metaErr
}

func (f *fakeCell) Slots(_ context.Context, slots []string) (map[string]LedgerSlot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]LedgerSlot, len(slots))
	for _, slot := range slots {
		out[slot] = f.ledger[slot]
	}
	return out, nil
}

func (f *fakeCell) Lifecycle(_ context.Context, instance string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	state, ok := f.lifecycle[instance]
	if !ok {
		return "", errors.New("instance not found")
	}
	return state, nil
}

func (f *fakeCell) Evidence(context.Context) (map[string]Evidence, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.evidence, nil
}

func (f *fakeCell) Replace(_ context.Context, action Action) error {
	f.mu.Lock()
	f.replaced = append(f.replaced, action)
	replace := f.replace
	f.mu.Unlock()
	if replace != nil {
		return replace(action)
	}
	return nil
}

func newFakeCell() *fakeCell {
	observation := lostB(testEpoch)
	return &fakeCell{meta: observation.Meta, ledger: observation.Ledger,
		lifecycle: map[string]string{instanceB: LifecycleTerminated, instanceC: LifecycleRunning},
		evidence:  map[string]Evidence{"controller-b": evidenceFor("controller-b", 1, instanceB)}}
}

func newTestReconciler(t *testing.T, leader *fakeLeadership, cell *fakeCell, replacer Replacer,
	clock *time.Time,
) *Reconciler {
	t.Helper()
	reconciler, err := New(testTopology(), Dependencies{Leadership: leader, Peers: cell, Ledger: cell,
		Instances: cell, Evidence: cell, Replacer: replacer, Now: func() time.Time { return *clock },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	return reconciler
}

func statusOf(r *Reconciler, slot string) SlotStatus {
	for _, status := range r.Statuses() {
		if status.Slot == slot {
			return status
		}
	}
	return SlotStatus{}
}

func TestReconcilerActsOnlyAsFencedLeader(t *testing.T) {
	clock := testEpoch
	leader := &fakeLeadership{}
	cell := newFakeCell()
	reconciler := newTestReconciler(t, leader, cell, cell, &clock)
	if err := reconciler.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(cell.replaced) != 0 || len(reconciler.Statuses()) != 0 {
		t.Fatal("follower evaluated or replaced")
	}
	leader.snapshot = leaderSnapshot(4)
	leader.guardErr = authority.ErrFenced
	if err := reconciler.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(cell.replaced) != 0 || statusOf(reconciler, "controller-b").LastFailure.IsZero() {
		t.Fatalf("fenced leader replaced: %+v", statusOf(reconciler, "controller-b"))
	}
	leader.guardErr = nil
	clock = clock.Add(DefaultRetryBackoff)
	if err := reconciler.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(cell.replaced) != 1 || cell.replaced[0].Slot != "controller-b" ||
		statusOf(reconciler, "controller-b").Phase != PhaseReplacing {
		t.Fatalf("leader did not replace: %+v %+v", cell.replaced, statusOf(reconciler, "controller-b"))
	}
	// A new authority term forgets the previous term's in-flight memory and
	// re-derives everything from fresh observations and the durable ledger.
	leader.snapshot = leaderSnapshot(5)
	cell.ledger["controller-b"] = LedgerSlot{Attempt: 2, InstanceOCID: instanceB + "-a2", Complete: true}
	cell.lifecycle[instanceB+"-a2"] = LifecycleRunning
	cell.meta.Peers[0].Online = true
	if err := reconciler.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if status := statusOf(reconciler, "controller-b"); status.Phase != PhaseHealthy || status.Attempt != 2 {
		t.Fatalf("new term status = %+v", status)
	}
}
