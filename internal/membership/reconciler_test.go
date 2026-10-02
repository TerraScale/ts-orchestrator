package membership

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

type fakeLeadership struct {
	mu       sync.Mutex
	snapshot authority.Snapshot
	guardErr error
	guards   int
}

func leaderSnapshot(epoch uint64) authority.Snapshot {
	return authority.Snapshot{Ready: true, Leader: true, Epoch: epoch, Revision: 1,
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

func newTestReconciler(t *testing.T, cfg Config, leader *fakeLeadership, cell *fakeCell, replacer Replacer,
	clock *time.Time,
) *Reconciler {
	t.Helper()
	reconciler, err := New(cfg, testTopology(), Dependencies{Leadership: leader, Peers: cell, Ledger: cell,
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
	reconciler := newTestReconciler(t, testConfig(), leader, cell, cell, &clock)
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

func TestReconcilerHoldsWithoutReplacerAndOnPartialObservation(t *testing.T) {
	clock := testEpoch
	leader := &fakeLeadership{snapshot: leaderSnapshot(2)}
	cell := newFakeCell()
	reconciler := newTestReconciler(t, testConfig(), leader, cell, nil, &clock)
	if err := reconciler.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if status := statusOf(reconciler, "controller-b"); status.Phase != PhaseHeld ||
		status.Reason != ErrReplacerUnavailable.Error() {
		t.Fatalf("no replacer status = %+v", status)
	}
	cell.metaErr = errors.New("jsz unavailable")
	if err := reconciler.Tick(t.Context()); err == nil {
		t.Fatal("partial observation was evaluated")
	}
}

func TestReconcilerRetriesFailedReplacementAfterBackoff(t *testing.T) {
	clock := testEpoch
	leader := &fakeLeadership{snapshot: leaderSnapshot(3)}
	cell := newFakeCell()
	failures := 1
	cell.replace = func(Action) error {
		if failures > 0 {
			failures--
			return errors.New("OCI launch throttled")
		}
		return nil
	}
	reconciler := newTestReconciler(t, testConfig(), leader, cell, cell, &clock)
	for range 3 {
		if err := reconciler.Tick(t.Context()); err != nil {
			t.Fatal(err)
		}
		clock = clock.Add(time.Minute)
	}
	if len(cell.replaced) != 1 || statusOf(reconciler, "controller-b").Reason != ReasonRetryBackoff {
		t.Fatalf("retry before backoff: %d %+v", len(cell.replaced), statusOf(reconciler, "controller-b"))
	}
	clock = clock.Add(DefaultRetryBackoff)
	if err := reconciler.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(cell.replaced) != 2 || cell.replaced[1].PreviousAttempt != 1 ||
		statusOf(reconciler, "controller-b").LastError != "" {
		t.Fatalf("retry after backoff: %+v %+v", cell.replaced, statusOf(reconciler, "controller-b"))
	}
}

func TestFileEvidenceRoutesOnlyWellFormedOwnerOnlyEnvelopes(t *testing.T) {
	dir := t.TempDir()
	_, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	candidate := bootstrap.RetirementEvidence{SchemaVersion: 1, DeploymentID: "deployment-1", Cell: "GRU",
		Environment: "production", Role: "controller", Slot: "controller-b", PreviousAttempt: 1,
		PreviousGeneration: 1, PreviousResultDigest: strings.Repeat("c", 64), PriorInstanceOCID: instanceB,
		PriorCreateKey: "founder-controller-b-key", Disposition: bootstrap.SlotRetirementDisposition,
		ObservedEvidenceDigest: evidenceID, FencingAuthority: "authority-epoch-2", ObservedAt: now}
	envelope, err := bootstrap.SignSlotRetirement(candidate, now, now.Add(time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "controller-b.retirement"), wire, 0o600); err != nil {
		t.Fatal(err)
	}
	// Misplaced evidence for b under c's name is ignored.
	if err := os.WriteFile(filepath.Join(dir, "controller-c.retirement"), wire, 0o600); err != nil {
		t.Fatal(err)
	}
	source := FileEvidence{Dir: dir, Slots: testTopology().Slots}
	evidence, err := source.Evidence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) != 1 || evidence["controller-b"].PreviousAttempt != 1 ||
		evidence["controller-b"].PriorInstanceOCID != instanceB || len(evidence["controller-b"].Digest) != 64 {
		t.Fatalf("evidence = %+v", evidence)
	}
	if err := os.Chmod(filepath.Join(dir, "controller-b.retirement"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Evidence(t.Context()); err == nil {
		t.Fatal("group-readable evidence accepted")
	}
	if err := os.Remove(filepath.Join(dir, "controller-b.retirement")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "controller-c.retirement"), filepath.Join(dir, "controller-b.retirement")); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Evidence(t.Context()); err == nil {
		t.Fatal("symlinked evidence accepted")
	}
}
