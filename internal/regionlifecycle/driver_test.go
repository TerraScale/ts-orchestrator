package regionlifecycle

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// fakeEffector models OCI resources keyed by their CreateKey tag.
type fakeEffector struct {
	mu        sync.Mutex
	resources map[string]string
	executes  map[Step]int
	fail      map[Step]error
}

func newFakeEffector() *fakeEffector {
	return &fakeEffector{resources: map[string]string{}, executes: map[Step]int{}, fail: map[Step]error{}}
}

func (e *fakeEffector) Execute(_ context.Context, _ Record, intent StepIntent) (StepResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.executes[intent.Step]++
	if err := e.fail[intent.Step]; err != nil {
		return StepResult{}, err
	}
	if _, exists := e.resources[intent.CreateKey]; !exists {
		e.resources[intent.CreateKey] = "ocid1.test." + string(intent.Step)
	}
	return StepResult{Step: intent.Step, CreateKey: intent.CreateKey, ResourceID: e.resources[intent.CreateKey],
		EvidenceDigest: digest(intent.CreateKey)}, nil
}

func (e *fakeEffector) Observe(_ context.Context, _ Record, intent StepIntent) (Observation, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	id, found := e.resources[intent.CreateKey]
	return Observation{Step: intent.Step, CreateKey: intent.CreateKey, Found: found, ResourceID: id,
		EvidenceDigest: digest("observed " + intent.CreateKey)}, nil
}

func TestStoreAndDriverJournalIntentBeforeEffect(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	js := newTestJetStream(t)
	global := startGlobalAuthority(ctx, t, js)
	epoch := global.Current().Epoch
	store, err := OpenStore(ctx, js, 1, global)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(ctx, js, 3, global); err == nil {
		t.Fatal("existing bucket reopened with different durability")
	}
	f := newFixture(t)
	proposed, err := f.machine.Propose(f.proposal(), f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, epoch+1, proposed); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("create with a foreign epoch = %v", err)
	}
	revision, err := store.Create(ctx, epoch, proposed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, epoch, proposed); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate proposal = %v", err)
	}
	approved, err := f.machine.Approve(proposed, f.approval(t, proposed), f.now)
	if err != nil {
		t.Fatal(err)
	}
	created := revision
	revision, err = store.Update(ctx, epoch, proposed, approved, revision)
	if err != nil {
		t.Fatal(err)
	}
	// A second writer that read the proposal loses the compare-and-set.
	if _, err := store.Update(ctx, epoch, proposed, approved, created); !errors.Is(err, ErrConflict) {
		t.Fatalf("update against an advanced revision = %v", err)
	}
	admitted, err := f.machine.Admit(approved, f.admission(), Fleet{Regions: 1}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(ctx, epoch, proposed, admitted, revision); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("update skipping a generation = %v", err)
	}
	if _, err := store.Update(ctx, epoch+1, approved, admitted, revision); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("update with a foreign epoch = %v", err)
	}
	if _, err = store.Update(ctx, epoch, approved, admitted, revision); err != nil {
		t.Fatal(err)
	}
	read, _, err := store.Get(ctx, "sfo")
	if err != nil || read.Phase != Admitted || read.Approval == nil {
		t.Fatalf("stored record = %+v, %v", read, err)
	}
	if err := protocol.VerifyEnvelope(*read.Approval, protocol.EnvelopeScope{Region: "sfo", Kind: ApproveExpansionKind,
		Actor: approver, OperationID: read.Proposal.ID, Generation: read.ProposalGeneration}, f.machine.Policy.Approvers[approver], f.now,
		protocol.VerifyPolicy{MaxLifetime: 72 * time.Hour}); err != nil {
		t.Fatalf("approval did not survive storage byte for byte: %v", err)
	}

	effector := newFakeEffector()
	driver := Driver{Machine: f.machine, Store: store, Effector: effector, Now: func() time.Time { return f.now }}
	next, err := driver.Advance(ctx, epoch, "sfo")
	if err != nil || next.Phase != Subscribed || effector.executes[StepSubscribe] != 1 {
		t.Fatalf("advance = %s, %v, executes %v", next.Phase, err, effector.executes)
	}

	// Crash after the effect: the intent is durable, the result is not. The
	// next leader observes the resource and completes without re-executing.
	record, revision, err := store.Get(ctx, "sfo")
	if err != nil {
		t.Fatal(err)
	}
	running, intent, err := f.machine.BeginStep(record, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(ctx, epoch, record, running, revision); err != nil {
		t.Fatal(err)
	}
	if _, err := effector.Execute(ctx, running, intent); err != nil {
		t.Fatal(err)
	}
	executed := effector.executes[StepFoundation]
	next, err = driver.Advance(ctx, epoch, "sfo")
	if err != nil || next.Phase != FoundationReady || effector.executes[StepFoundation] != executed {
		t.Fatalf("recovery = %s, %v; executes %d -> %d", next.Phase, err, executed, effector.executes[StepFoundation])
	}

	// Crash before the effect: observation finds nothing and the step is
	// retried once with the same create key.
	record, revision, err = store.Get(ctx, "sfo")
	if err != nil {
		t.Fatal(err)
	}
	running, intent, err = f.machine.BeginStep(record, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(ctx, epoch, record, running, revision); err != nil {
		t.Fatal(err)
	}
	next, err = driver.Advance(ctx, epoch, "sfo")
	if err != nil || next.Phase != ImageReady || effector.executes[StepImage] != 1 ||
		next.Completed[len(next.Completed)-1].CreateKey != intent.CreateKey {
		t.Fatalf("retry = %s, %v, executes %v", next.Phase, err, effector.executes)
	}

	// A failing effect holds the region with its intent kept.
	effector.fail[StepMaterial] = errors.New("vault unavailable")
	next, err = driver.Advance(ctx, epoch, "sfo")
	if err == nil || next.Phase != Held || next.Hold.Step != StepMaterial || next.Pending == nil {
		t.Fatalf("failed step = %+v, %v", next, err)
	}
	if again, err := driver.Advance(ctx, epoch, "sfo"); err != nil || again.Phase != Held || effector.executes[StepMaterial] != 1 {
		t.Fatalf("driver advanced a held region: %s, %v", again.Phase, err)
	}

	// Resume by observation: the material was never minted, so the step
	// returns to running with its key and the next advance completes it.
	held, revision, err := store.Get(ctx, "sfo")
	if err != nil {
		t.Fatal(err)
	}
	observation, _ := effector.Observe(ctx, held, *held.Pending)
	resumed, err := f.machine.Resume(held, &observation, f.now)
	if err != nil || resumed.Phase != MaterialMinting {
		t.Fatalf("resume = %s, %v", resumed.Phase, err)
	}
	if _, err := store.Update(ctx, epoch, held, resumed, revision); err != nil {
		t.Fatal(err)
	}
	delete(effector.fail, StepMaterial)
	if next, err = driver.Advance(ctx, epoch, "sfo"); err != nil || next.Phase != Signed || effector.executes[StepMaterial] != 2 {
		t.Fatalf("advance after resume = %s, %v, executes %v", next.Phase, err, effector.executes)
	}
	// A stale admission parks the driver at a spending step without holding.
	late := Driver{Machine: f.machine, Store: store, Effector: effector, Now: func() time.Time { return f.now.Add(time.Hour) }}
	if next, err = driver.Advance(ctx, epoch, "sfo"); err != nil || next.Phase != SeedReserved {
		t.Fatalf("seed reservation = %s, %v", next.Phase, err)
	}
	if parked, err := late.Advance(ctx, epoch, "sfo"); !errors.Is(err, ErrAdmissionStale) || parked.Phase != SeedReserved {
		t.Fatalf("stale admission advance = %s, %v", parked.Phase, err)
	}
	records, err := store.List(ctx)
	if err != nil || len(records) != 1 || records[0].Cell != "sfo" {
		t.Fatalf("list = %+v, %v", records, err)
	}
}

func startGlobalAuthority(ctx context.Context, t *testing.T, js jetstream.JetStream) *authority.Runtime {
	t.Helper()
	runtime, err := authority.Start(ctx, js, authority.Config{
		Scope: protocol.GlobalScope, CandidateID: "0000000000F2D374M7NMRHJJQT", Replicas: 1,
		LeaseDuration: 5 * time.Second, RenewInterval: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	for !runtime.Current().CanMutate() {
		if ctx.Err() != nil {
			t.Fatal("global authority never became leader")
		}
		time.Sleep(20 * time.Millisecond)
	}
	return runtime
}

func newTestJetStream(t *testing.T) jetstream.JetStream {
	t.Helper()
	srv, err := server.NewServer(&server.Options{
		Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: filepath.Join(t.TempDir(), "jetstream"),
	})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	return js
}
