package membership

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// fakeLease is the durable lease as the seed reads it.
type fakeLease struct {
	mu        sync.Mutex
	epoch     uint64
	candidate string
	owner     string
	checks    int
}

func (f *fakeLease) VerifyLeaseHolder(_ context.Context, epoch uint64, candidate, owner string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checks++
	if epoch == 0 || epoch != f.epoch || candidate != f.candidate || owner != f.owner {
		return authority.ErrFenced
	}
	return nil
}

func (f *fakeLease) set(epoch uint64, candidate, owner string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.epoch, f.candidate, f.owner = epoch, candidate, owner
}

// seedFounderStub records actions and blocks each until released or
// cancelled.
type seedFounderStub struct {
	mu       sync.Mutex
	actions  []Action
	started  chan Action
	release  chan error
	canceled chan error
}

func newSeedFounderStub() *seedFounderStub {
	return &seedFounderStub{started: make(chan Action, 4), release: make(chan error, 4), canceled: make(chan error, 4)}
}

func (f *seedFounderStub) Replace(ctx context.Context, action Action) error {
	f.mu.Lock()
	f.actions = append(f.actions, action)
	f.mu.Unlock()
	if action.Fence != nil {
		if err := action.Fence(ctx); err != nil {
			return err
		}
	}
	f.started <- action
	select {
	case err := <-f.release:
		return err
	case <-ctx.Done():
		f.canceled <- context.Cause(ctx)
		return ctx.Err()
	}
}

func signedRetirement(t *testing.T, slot string, attempt uint64, instance string) []byte {
	t.Helper()
	_, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	candidate := bootstrap.RetirementEvidence{SchemaVersion: 1, DeploymentID: "0000000000DMC7WFP9VHV640EP", Cell: "GRU",
		Environment: "production", Role: "controller", Slot: slot, PreviousAttempt: attempt,
		PreviousGeneration: 1, PreviousResultDigest: strings.Repeat("c", 64), PriorInstanceOCID: instance,
		PriorCreateKey: "founder-" + slot + "-key", Disposition: bootstrap.SlotRetirementDisposition,
		ObservedEvidenceDigest: evidenceID, FencingAuthority: "authority-epoch-2", ObservedAt: now}
	envelope, err := bootstrap.SignSlotRetirement(candidate, now, now.Add(time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func seedTopology() Topology {
	return Topology{Cell: "gru", Slots: []string{"controller-a", "controller-b", "controller-c"},
		SeedSlot: "controller-a", SelfSlot: "controller-a"}
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

type seedHarness struct {
	lease    *fakeLease
	cell     *fakeCell
	replacer *seedFounderStub
	server   *SeedServer
}

func newSeedHarness(t *testing.T) *seedHarness {
	t.Helper()
	harness := &seedHarness{lease: &fakeLease{}, cell: newFakeCell(), replacer: newSeedFounderStub()}
	harness.lease.set(seedTermEpoch, "000000000057DFR5HRY5QD68EQ", "0000000000P2GFAE1EE5N7T3Q1")
	server, err := NewSeedServer(t.Context(), seedTopology(), SeedServerDependencies{Leases: harness.lease,
		Instances: harness.cell, Replacer: harness.replacer, Logger: quietLogger()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	harness.server = server
	return harness
}

func (h *seedHarness) request(t *testing.T, mutate func(*SeedReplaceRequest)) SeedReplaceReply {
	t.Helper()
	request := SeedReplaceRequest{Version: SeedReplaceRequestVersion, Cell: "gru", Slot: "controller-b",
		PreviousAttempt: 1, PriorInstanceOCID: instanceB,
		Retirement: signedRetirement(t, "controller-b", 1, instanceB), Epoch: seedTermEpoch,
		CandidateID: "000000000057DFR5HRY5QD68EQ", OwnerID: "0000000000P2GFAE1EE5N7T3Q1"}
	if mutate != nil {
		mutate(&request)
	}
	payload, err := protocol.EncodeJSON(request)
	if err != nil {
		t.Fatal(err)
	}
	return h.server.Handle(t.Context(), payload)
}

func awaitStarted(t *testing.T, replacer *seedFounderStub) Action {
	t.Helper()
	select {
	case action := <-replacer.started:
		return action
	case <-time.After(5 * time.Second):
		t.Fatal("routed replacement never started")
	}
	return Action{}
}

func TestNonSeedLeaderRoutesReplacementToTheSeed(t *testing.T) {
	harness := newSeedHarness(t)
	leader := &fakeLeadership{snapshot: leaderSnapshot(seedTermEpoch)}
	leader.snapshot.CandidateID, leader.snapshot.OwnerID = "000000000057DFR5HRY5QD68EQ", "0000000000P2GFAE1EE5N7T3Q1"
	cell := newFakeCell()
	wire := signedRetirement(t, "controller-b", 1, instanceB)
	evidence := cell.evidence["controller-b"]
	evidence.Wire = wire
	cell.evidence["controller-b"] = evidence
	var requests int
	routed := SeedRoutedReplacer{Cell: "gru", Leadership: leader,
		Request: func(ctx context.Context, payload []byte) ([]byte, error) {
			requests++
			return protocol.EncodeJSON(harness.server.Handle(ctx, payload))
		}}
	clock := time.Now().UTC()
	topology := testTopology()
	topology.SelfSlot = "controller-c"
	reconciler, err := New(testConfig(), topology, Dependencies{Leadership: leader, Peers: cell, Ledger: cell,
		Instances: cell, Evidence: cell, Replacer: routed, Now: func() time.Time { return clock },
		Logger: quietLogger()})
	if err != nil {
		t.Fatal(err)
	}
	// The local slot is c, so the lost peer b is routed to the seed a.
	cell.meta.Peers = []Peer{{Name: "gru-1-ctl-1", Online: true, Current: true}}
	if err := reconciler.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	action := awaitStarted(t, harness.replacer)
	if action.Slot != "controller-b" || action.PreviousAttempt != 1 || action.PriorInstanceOCID != instanceB ||
		action.Epoch != seedTermEpoch || string(action.Retirement.Wire) != string(wire) {
		t.Fatalf("seed executed %+v", action)
	}
	if status := statusOf(reconciler, "controller-b"); status.Phase != PhaseReplacing || status.LastError != "" {
		t.Fatalf("leader status after an accepted routed replacement: %+v", status)
	}
	if leader.guards == 0 {
		t.Fatal("leader routed without renewing its own lease first")
	}
	// The leader replays the action each tick; the seed reports progress
	// without starting a second replacement.
	if err := reconciler.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if requests != 2 || len(harness.replacer.actions) != 1 {
		t.Fatalf("requests=%d seed replacements=%d, want 2 and 1", requests, len(harness.replacer.actions))
	}
	harness.replacer.release <- nil
	waitFor(t, func() bool {
		harness.server.mu.Lock()
		defer harness.server.mu.Unlock()
		return harness.server.job != nil && !harness.server.job.running
	})
	if reply := harness.request(t, func(request *SeedReplaceRequest) { request.Retirement = wire }); reply.Status != SeedDone {
		t.Fatalf("reply after completion = %+v", reply)
	}
}

func TestSeedRefusesRequestsOutsideTheCurrentTermOrScope(t *testing.T) {
	harness := newSeedHarness(t)
	for name, mutate := range map[string]func(*SeedReplaceRequest){
		"stale epoch":           func(r *SeedReplaceRequest) { r.Epoch = seedTermEpoch - 1 },
		"other candidate":       func(r *SeedReplaceRequest) { r.CandidateID = "0000000000RQQB0PSJ84MK6YCM" },
		"other owner":           func(r *SeedReplaceRequest) { r.OwnerID = "0000000000DKT0SAM6NFTCGPGT" },
		"other cell":            func(r *SeedReplaceRequest) { r.Cell = "sfo" },
		"seed slot":             func(r *SeedReplaceRequest) { r.Slot = "controller-a" },
		"unknown slot":          func(r *SeedReplaceRequest) { r.Slot = "controller-z" },
		"schema":                func(r *SeedReplaceRequest) { r.Version = 2 },
		"retirement other slot": func(r *SeedReplaceRequest) { r.Slot = "controller-c"; r.PriorInstanceOCID = instanceC },
		"retirement other attempt": func(r *SeedReplaceRequest) {
			r.PreviousAttempt = 2
		},
		"retirement other instance": func(r *SeedReplaceRequest) { r.PriorInstanceOCID = instanceC },
		"no retirement":             func(r *SeedReplaceRequest) { r.Retirement = nil },
		"garbage retirement":        func(r *SeedReplaceRequest) { r.Retirement = []byte("{}") },
	} {
		if reply := harness.request(t, mutate); reply.Status != SeedRefused || reply.Error == "" {
			t.Errorf("%s: reply = %+v, want refused", name, reply)
		}
	}
	if reply := harness.server.Handle(t.Context(), []byte(`{"version":1,"unknown":true}`)); reply.Status != SeedRefused {
		t.Errorf("unknown field: reply = %+v", reply)
	}
	if len(harness.replacer.actions) != 0 {
		t.Fatalf("a refused request reached the founder: %+v", harness.replacer.actions)
	}
}

func TestSeedRoutedReplacementEndsWithTheRequestingTerm(t *testing.T) {
	previous := seedFencePoll
	seedFencePoll = 10 * time.Millisecond
	t.Cleanup(func() { seedFencePoll = previous })
	harness := newSeedHarness(t)
	if reply := harness.request(t, nil); reply.Status != SeedAccepted {
		t.Fatalf("reply = %+v", reply)
	}
	action := awaitStarted(t, harness.replacer)
	// Another controller takes the lease: the seed must stop acting for
	// the old term, and its fence must refuse every later mutation.
	harness.lease.set(seedTermEpoch+1, "gru-controller-b-5678", "owner-b")
	select {
	case cause := <-harness.replacer.canceled:
		if cause == nil || !strings.Contains(cause.Error(), "term ended") {
			t.Fatalf("cancellation cause = %v", cause)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("routed replacement outlived the requesting term")
	}
	if err := action.Fence(t.Context()); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("fence after the term ended = %v", err)
	}
	waitFor(t, func() bool {
		harness.server.mu.Lock()
		defer harness.server.mu.Unlock()
		return harness.server.job != nil && !harness.server.job.running && harness.server.job.err != nil
	})
	// The old term can no longer even learn the outcome.
	if reply := harness.request(t, nil); reply.Status != SeedRefused {
		t.Fatalf("stale term reply = %+v", reply)
	}
	// The next term resumes the same retirement at once instead of first
	// collecting the failure the old term's fence caused.
	if reply := harness.request(t, func(request *SeedReplaceRequest) {
		request.Retirement = action.Retirement.Wire
		request.Epoch, request.CandidateID, request.OwnerID = seedTermEpoch+1, "gru-controller-b-5678", "owner-b"
	}); reply.Status != SeedAccepted {
		t.Fatalf("new term reply = %+v", reply)
	}
	resumed := awaitStarted(t, harness.replacer)
	if resumed.Epoch != seedTermEpoch+1 {
		t.Fatalf("resumed under epoch %d", resumed.Epoch)
	}
	harness.replacer.release <- nil
}

func TestSeedRunsOneRoutedReplacementAtATimeAndReportsFailuresOnce(t *testing.T) {
	harness := newSeedHarness(t)
	harness.cell.lifecycle[instanceC] = LifecycleTerminated
	if reply := harness.request(t, nil); reply.Status != SeedAccepted {
		t.Fatalf("reply = %+v", reply)
	}
	awaitStarted(t, harness.replacer)
	other := func(request *SeedReplaceRequest) {
		request.Slot, request.PriorInstanceOCID = "controller-c", instanceC
		request.Retirement = signedRetirement(t, "controller-c", 1, instanceC)
	}
	if reply := harness.request(t, other); reply.Status != SeedRefused ||
		!strings.Contains(reply.Error, "already replacing slot controller-b") {
		t.Fatalf("concurrent request reply = %+v", reply)
	}
	harness.replacer.release <- errors.New("launch failed")
	waitFor(t, func() bool {
		harness.server.mu.Lock()
		defer harness.server.mu.Unlock()
		return !harness.server.job.running
	})
	wire := harness.replacer.actions[0].Retirement.Wire
	same := func(request *SeedReplaceRequest) { request.Retirement = wire }
	if reply := harness.request(t, same); reply.Status != SeedFailed || !strings.Contains(reply.Error, "launch failed") {
		t.Fatalf("failure reply = %+v", reply)
	}
	// The failure was reported; the next request starts a fresh attempt.
	if reply := harness.request(t, same); reply.Status != SeedAccepted {
		t.Fatalf("retry reply = %+v", reply)
	}
	awaitStarted(t, harness.replacer)
	harness.replacer.release <- nil
}

func TestSeedNeverReplacesAPriorInstanceThatMayStillRun(t *testing.T) {
	harness := newSeedHarness(t)
	harness.cell.lifecycle[instanceB] = LifecycleRunning
	if reply := harness.request(t, nil); reply.Status != SeedAccepted {
		t.Fatalf("reply = %+v", reply)
	}
	waitFor(t, func() bool {
		harness.server.mu.Lock()
		defer harness.server.mu.Unlock()
		return !harness.server.job.running
	})
	if len(harness.replacer.actions) != 0 {
		t.Fatal("the founder ran for an instance the seed observed RUNNING")
	}
	harness.server.mu.Lock()
	err := harness.server.job.err
	harness.server.mu.Unlock()
	if err == nil || !strings.Contains(err.Error(), "RUNNING") {
		t.Fatalf("job error = %v", err)
	}
}

func TestSeedRoutedReplacerRefusesAfterItsTermEnds(t *testing.T) {
	leader := &fakeLeadership{snapshot: leaderSnapshot(seedTermEpoch + 1)}
	called := false
	routed := SeedRoutedReplacer{Cell: "gru", Leadership: leader,
		Request: func(context.Context, []byte) ([]byte, error) { called = true; return nil, nil }}
	err := routed.Replace(t.Context(), Action{Slot: "controller-b", PreviousAttempt: 1, Epoch: seedTermEpoch})
	if err == nil || called {
		t.Fatalf("stale term routed: err=%v called=%v", err, called)
	}
	if err := (SeedRoutedReplacer{}).Replace(t.Context(), Action{}); !errors.Is(err, ErrReplacerUnavailable) {
		t.Fatalf("unwired replacer = %v", err)
	}
	leader.snapshot = leaderSnapshot(seedTermEpoch)
	routed.Request = func(context.Context, []byte) ([]byte, error) {
		return protocol.EncodeJSON(SeedReplaceReply{Status: SeedRefused, Error: "fenced"})
	}
	if err := routed.Replace(t.Context(), Action{Slot: "controller-b", PreviousAttempt: 1, Epoch: seedTermEpoch}); !errors.Is(err, ErrSeedRefused) {
		t.Fatalf("refusal = %v", err)
	}
}

func TestSeedServerRequiresTheSeedSlot(t *testing.T) {
	topology := seedTopology()
	topology.SelfSlot = "controller-b"
	if _, err := NewSeedServer(t.Context(), topology, SeedServerDependencies{Leases: &fakeLease{},
		Instances: newFakeCell(), Replacer: newSeedFounderStub()}); err == nil {
		t.Fatal("a non-seed controller served replacement requests")
	}
	if err := (Config{Enabled: true, RouteToSeed: true}).Validate(); err == nil {
		t.Fatal("route_to_seed without replace validated")
	}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

const seedTermEpoch uint64 = 7
