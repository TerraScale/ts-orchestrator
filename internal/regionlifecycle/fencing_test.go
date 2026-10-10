package regionlifecycle

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go/jetstream"
)

// switchableFencer passes Guard only for its current epoch.
type switchableFencer struct {
	mu    sync.Mutex
	epoch uint64
}

func (f *switchableFencer) Current() authority.Snapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	return authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Scope: protocol.GlobalScope, Epoch: f.epoch, Leader: true}
}

func (f *switchableFencer) Guard(_ context.Context, epoch uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if epoch == 0 || epoch != f.epoch {
		return authority.ErrFenced
	}
	return nil
}

func (f *switchableFencer) set(epoch uint64) {
	f.mu.Lock()
	f.epoch = epoch
	f.mu.Unlock()
}

// runTo drives a record with the pure machine until it reaches phase.
func (f *fixture) runTo(t *testing.T, record Record, phase Phase) Record {
	t.Helper()
	for record.Phase != phase {
		record = f.runStep(t, record)
	}
	return record
}

func TestFleetCountsTheHomeRegionAndSaturates(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	admitted := f.admitted(t)
	home := Home{Cell: "gru"}
	if err := home.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []Home{{}, {Cell: "global"}, {Cell: "GRU"}} {
		if invalid.Validate() == nil {
			t.Errorf("home %+v validated", invalid)
		}
	}
	// The home takes a slot but its spend is already in the budget headroom.
	fleet := FleetOf([]Record{admitted}, "fra", home)
	if fleet.Regions != 2 || fleet.CommittedMonthlyCents != 9_000 {
		t.Fatalf("fleet with home = %+v", fleet)
	}
	// The home is never counted twice, nor for its own guard.
	if own := FleetOf([]Record{admitted}, "gru", home); own.Regions != 1 || own.CommittedMonthlyCents != 9_000 {
		t.Fatalf("fleet for the home cell = %+v", own)
	}
	withRecord := admitted
	withRecord.Cell = "gru"
	if fleet := FleetOf([]Record{admitted, withRecord}, "fra", home); fleet.Regions != 2 {
		t.Fatalf("home with a lifecycle record counted twice: %+v", fleet)
	}
	// Absurd estimates saturate instead of wrapping to a small total.
	huge := admitted
	huge.Cell = "iad"
	huge.Admission = &CostAdmission{EstimatedMonthlyCents: math.MaxUint64 - 10, EvidenceDigest: digest("x"), AdmittedAt: f.now}
	if fleet := FleetOf([]Record{admitted, huge}, "fra", home); fleet.CommittedMonthlyCents != math.MaxUint64 {
		t.Fatalf("wrapped fleet total = %d", fleet.CommittedMonthlyCents)
	}
	if SaturatingAdd(math.MaxUint64, 1) != math.MaxUint64 || SaturatingAdd(2, 3) != 5 {
		t.Fatal("saturating add")
	}
}

func TestHomeRegionTakesASlotAtAdmission(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	record, err := f.machine.Propose(f.proposal(), f.now)
	if err != nil {
		t.Fatal(err)
	}
	if record, err = f.machine.Approve(record, f.now); err != nil {
		t.Fatal(err)
	}
	// MaxRegions-1 other regions fill every slot but the one the home holds.
	var others []Record
	for index := range MaxRegions - 1 {
		other := record
		other.Cell, other.Phase = fmt.Sprintf("region-%02d", index), Active
		others = append(others, other)
	}
	if _, err := f.machine.Admit(record, f.admission(), FleetOf(others, "sfo", Home{Cell: "gru"}), f.now); !errors.Is(err, ErrRegionLimit) {
		t.Fatalf("admission ignoring the home region = %v", err)
	}
	if _, err := f.machine.Admit(record, f.admission(), FleetOf(others, "sfo", Home{}), f.now); err != nil {
		t.Fatalf("admission into the last free slot = %v", err)
	}
}

func TestBudgetArithmeticCannotWrap(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	record, err := f.machine.Propose(f.proposal(), f.now)
	if err != nil {
		t.Fatal(err)
	}
	if record, err = f.machine.Approve(record, f.now); err != nil {
		t.Fatal(err)
	}
	// 9,000 + (MaxUint64 - 8,999) wraps to 0 in unchecked arithmetic.
	admission := CostAdmission{EstimatedMonthlyCents: math.MaxUint64 - 8_999, HeadroomCents: 20_000, EvidenceDigest: digest("x"), AdmittedAt: f.now}
	if _, err := f.machine.Admit(record, admission, Fleet{Regions: 1, CommittedMonthlyCents: 9_000}, f.now); !errors.Is(err, ErrBudgetCeiling) {
		t.Fatalf("wrapping estimate admitted: %v", err)
	}
	if _, err := f.machine.Admit(record, f.admission(), Fleet{Regions: 1, CommittedMonthlyCents: math.MaxUint64}, f.now); !errors.Is(err, ErrBudgetCeiling) {
		t.Fatalf("saturated fleet admitted: %v", err)
	}
}

func TestHeldProposalDoesNotTakeASlot(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	proposed, err := f.machine.Propose(f.proposal(), f.now)
	if err != nil {
		t.Fatal(err)
	}
	held, err := f.machine.Fail(proposed, "operator paused", "", f.now)
	if err != nil {
		t.Fatal(err)
	}
	if held.OccupiesSlot() {
		t.Fatal("a held, unapproved proposal occupies a region slot")
	}
	heldAdmitted, err := f.machine.Fail(f.admitted(t), "paused", "", f.now)
	if err != nil {
		t.Fatal(err)
	}
	if !heldAdmitted.OccupiesSlot() {
		t.Fatal("a held, admitted region released its slot")
	}
	if fleet := FleetOf([]Record{held, heldAdmitted}, "fra", Home{}); fleet.Regions != 1 {
		t.Fatalf("fleet = %+v", fleet)
	}
}

func TestClaimStepRechecksGuardsAndEpoch(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	record := f.runTo(t, f.admitted(t), Subscribed)
	running, _, err := f.machine.BeginStep(record, f.now)
	if err != nil {
		t.Fatal(err)
	}
	running.Pending.Epoch = 3
	if _, _, err := f.machine.ClaimStep(running, 2, f.now); !errors.Is(err, ErrStaleEpoch) {
		t.Fatalf("older leader claimed a newer intent: %v", err)
	}
	if _, _, err := f.machine.ClaimStep(running, 0, f.now); !errors.Is(err, ErrStaleEpoch) {
		t.Fatalf("zero epoch claimed: %v", err)
	}
	// Foundation spends: an admission older than its TTL blocks re-execution.
	if _, _, err := f.machine.ClaimStep(running, 3, f.now.Add(AdmissionTTL)); !errors.Is(err, ErrAdmissionStale) {
		t.Fatalf("claim with a stale admission = %v", err)
	}
	claimed, intent, err := f.machine.ClaimStep(running, 4, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if claimed.Phase != running.Phase || claimed.Generation != running.Generation+1 || intent.Epoch != 4 ||
		intent.Attempt != 1 || intent.CreateKey != running.Pending.CreateKey || *claimed.Pending != intent {
		t.Fatalf("claim = %+v, %+v", claimed, intent)
	}
	if err := claimed.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.machine.ClaimStep(record, 4, f.now); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("claim outside a running step = %v", err)
	}
}

func TestFailedBringUpRetiresAfterTheSeedLaunch(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	reserved := f.runTo(t, f.admitted(t), SeedReserved)
	if _, err := f.machine.ProposeFailedRetire(reserved, "x", digest("x"), f.now); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("pre-launch failure took the retire path (cancel rolls it back): %v", err)
	}
	launching, _, err := f.machine.BeginStep(reserved, f.now)
	if err != nil {
		t.Fatal(err)
	}
	held, err := f.machine.Fail(launching, "seed never booted", digest("boot"), f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.machine.Cancel(held, "give up", f.now); !errors.Is(err, ErrUseRetire) {
		t.Fatalf("cancel after launch = %v", err)
	}
	if _, err := f.machine.ProposeFailedRetire(held, "seed never booted", "nope", f.now); err == nil {
		t.Fatal("failed retire without evidence")
	}
	proposed, err := f.machine.ProposeFailedRetire(held, "seed never booted", digest("boot"), f.now)
	if err != nil {
		t.Fatal(err)
	}
	if proposed.Phase != RetireProposed || proposed.RetireFrom != SeedLaunching || proposed.Pending == nil ||
		proposed.Hold != nil || !proposed.OccupiesSlot() {
		t.Fatalf("failed retire proposal = %+v", proposed)
	}
	if err := proposed.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.machine.BeginStep(proposed, f.now); err == nil {
		t.Fatal("teardown began without a retirement approval")
	}
	approved, err := f.machine.ApproveRetire(proposed, f.now)
	if err != nil {
		t.Fatal(err)
	}
	// The pending launch must be reconciled before any teardown step.
	if _, _, err := f.machine.BeginStep(approved, f.now); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("teardown began with an unreconciled intent: %v", err)
	}
	if _, err := f.machine.ReconcileRetirePending(approved, Observation{Step: StepFoundation, CreateKey: approved.Pending.CreateKey, EvidenceDigest: digest("o")}, f.now); !errors.Is(err, ErrStepMismatch) {
		t.Fatalf("foreign observation reconciled the launch: %v", err)
	}
	found := Observation{Step: StepSeedLaunch, CreateKey: approved.Pending.CreateKey, Found: true, ResourceID: "ocid1.instance.seed", EvidenceDigest: digest("seen")}
	reconciled, err := f.machine.ReconcileRetirePending(approved, found, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if reconciled.Phase != RetireApproved || reconciled.Pending != nil ||
		reconciled.Completed[len(reconciled.Completed)-1].ResourceID != "ocid1.instance.seed" {
		t.Fatalf("reconciled = %+v", reconciled)
	}
	retired := f.runTo(t, reconciled, Retired)
	assertTerminal(t, f, retired)

	// From Active or a terminal phase the failed-retire path is closed.
	active := f.runTo(t, reserved, Active)
	if _, err := f.machine.ProposeFailedRetire(active, "x", digest("x"), f.now); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("active region took the failed-retire path: %v", err)
	}
	if _, err := f.machine.ProposeFailedRetire(retired, "x", digest("x"), f.now); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("retired region took the failed-retire path: %v", err)
	}
	corrupt := proposed
	corrupt.RetireFrom = Signed
	if corrupt.Validate() == nil {
		t.Fatal("record retiring from a pre-launch phase validated")
	}
}

// openFakeStore opens a lifecycle store guarded by a switchable fencer.
func openFakeStore(ctx context.Context, t *testing.T, fencer authority.Fencer) *Store {
	t.Helper()
	js := newTestJetStream(t)
	kv, err := js.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: Bucket, History: 16})
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(kv, fencer)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

// storeRunning stores a record whose step intent was journaled under epoch
// but whose effect never ran (a crash before Execute).
func storeRunning(ctx context.Context, t *testing.T, f *fixture, store *Store, epoch uint64, phase Phase) {
	t.Helper()
	record := f.runTo(t, f.admitted(t), phase)
	running, _, err := f.machine.BeginStep(record, f.now)
	if err != nil {
		t.Fatal(err)
	}
	running.Pending.Epoch = epoch
	data, err := encode(running)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.kv.Put(ctx, running.Cell, data); err != nil {
		t.Fatal(err)
	}
}

// TestDriverNeverExecutesForAStaleLeader: a leader whose lease Guard still
// passes (it paused after its Guard) cannot re-execute an intent a newer
// leader claimed, and a fenced leader never reaches Execute.
func TestDriverNeverExecutesForAStaleLeader(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	f := newFixture(t)
	fencer := &switchableFencer{epoch: 5}
	store := openFakeStore(ctx, t, fencer)
	effector := newFakeEffector()
	driver := Driver{Machine: f.machine, Store: store, Effector: effector, Now: func() time.Time { return f.now }}
	storeRunning(ctx, t, f, store, 5, Subscribed)

	// Epoch 4 passes its own (paused) Guard but the intent belongs to 5.
	fencer.set(4)
	if _, err := driver.Advance(ctx, 4, "sfo"); !errors.Is(err, ErrStaleEpoch) {
		t.Fatalf("stale leader advance = %v", err)
	}
	// Epoch 6 is the leader now, but this caller is fenced at its Guard.
	fencer.set(6)
	if _, err := driver.Advance(ctx, 5, "sfo"); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("fenced leader advance = %v", err)
	}
	if effector.executes[StepFoundation] != 0 {
		t.Fatalf("a stale or fenced leader executed the effect %d times", effector.executes[StepFoundation])
	}
	next, err := driver.Advance(ctx, 6, "sfo")
	if err != nil || next.Phase != FoundationReady || effector.executes[StepFoundation] != 1 {
		t.Fatalf("current leader advance = %s, %v, executes %v", next.Phase, err, effector.executes)
	}
	last := next.Completed[len(next.Completed)-1]
	if last.Step != StepFoundation {
		t.Fatalf("completed = %+v", next.Completed)
	}
}

// TestDriverFencesBetweenClaimAndExecute: if the lease moves after the claim
// is durable but before the effect, Execute does not run.
func TestDriverFencesBetweenClaimAndExecute(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	f := newFixture(t)
	fencer := &switchableFencer{epoch: 2}
	store := openFakeStore(ctx, t, fencer)
	effector := newFakeEffector()
	storeRunning(ctx, t, f, store, 0, Subscribed)
	// The fencing store passes the claim's Guard, then the lease moves.
	fenceAfter := &countingFencer{inner: fencer, after: 1, then: func() { fencer.set(3) }}
	store.fencer = fenceAfter
	driver := Driver{Machine: f.machine, Store: store, Effector: effector, Now: func() time.Time { return f.now }}
	if _, err := driver.Advance(ctx, 2, "sfo"); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("advance across a lease change = %v", err)
	}
	if effector.executes[StepFoundation] != 0 {
		t.Fatal("effect ran after the lease moved")
	}
	stored, _, err := store.Get(ctx, "sfo")
	if err != nil || stored.Pending == nil || stored.Pending.Epoch != 2 || stored.Phase != FoundationProvisioning {
		t.Fatalf("claimed record = %+v, %v", stored, err)
	}
	// The new leader reclaims the same intent with the same key and runs it once.
	store.fencer = fencer
	next, err := driver.Advance(ctx, 3, "sfo")
	if err != nil || next.Phase != FoundationReady || effector.executes[StepFoundation] != 1 {
		t.Fatalf("new leader = %s, %v", next.Phase, err)
	}
}

// TestDriverRecoveryRechecksAdmission: a crash-recovered spending step does not
// re-execute on a stale admission.
func TestDriverRecoveryRechecksAdmission(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	f := newFixture(t)
	fencer := &switchableFencer{epoch: 1}
	store := openFakeStore(ctx, t, fencer)
	effector := newFakeEffector()
	storeRunning(ctx, t, f, store, 1, Subscribed)
	stale := Driver{Machine: f.machine, Store: store, Effector: effector, Now: func() time.Time { return f.now.Add(time.Hour) }}
	if parked, err := stale.Advance(ctx, 1, "sfo"); !errors.Is(err, ErrAdmissionStale) || parked.Phase != FoundationProvisioning {
		t.Fatalf("recovery with a stale admission = %s, %v", parked.Phase, err)
	}
	if effector.executes[StepFoundation] != 0 {
		t.Fatal("recovery re-executed without a fresh admission")
	}
	// Readmission of the running step unblocks it.
	record, revision, err := store.Get(ctx, "sfo")
	if err != nil {
		t.Fatal(err)
	}
	later := f.now.Add(time.Hour)
	readmitted, err := f.machine.Readmit(record, CostAdmission{EstimatedMonthlyCents: 9_000, HeadroomCents: 20_000,
		EvidenceDigest: digest("r"), AdmittedAt: later}, Fleet{}, later)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(ctx, 1, record, readmitted, revision); err != nil {
		t.Fatal(err)
	}
	if next, err := stale.Advance(ctx, 1, "sfo"); err != nil || next.Phase != FoundationReady || effector.executes[StepFoundation] != 1 {
		t.Fatalf("recovery after readmission = %s, %v", next.Phase, err)
	}
}

// TestDriverReconcilesAFailedLaunchBeforeTeardown drives the failed-retire
// path through the store: the launch intent is observed, then teardown runs.
func TestDriverReconcilesAFailedLaunchBeforeTeardown(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	f := newFixture(t)
	fencer := &switchableFencer{epoch: 1}
	store := openFakeStore(ctx, t, fencer)
	effector := newFakeEffector()
	storeRunning(ctx, t, f, store, 1, SeedReserved)
	record, revision, err := store.Get(ctx, "sfo")
	if err != nil {
		t.Fatal(err)
	}
	// The seed exists (the launch ran) but the region never came up.
	effector.resources[record.Pending.CreateKey] = "ocid1.instance.seed"
	proposed, err := f.machine.ProposeFailedRetire(record, "seed admission never completed", digest("x"), f.now)
	if err != nil {
		t.Fatal(err)
	}
	if revision, err = store.Update(ctx, 1, record, proposed, revision); err != nil {
		t.Fatal(err)
	}
	approved, err := f.machine.ApproveRetire(proposed, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(ctx, 1, proposed, approved, revision); err != nil {
		t.Fatal(err)
	}
	driver := Driver{Machine: f.machine, Store: store, Effector: effector, Now: func() time.Time { return f.now }}
	next, err := driver.Advance(ctx, 1, "sfo")
	if err != nil || next.Phase != RetireApproved || next.Pending != nil ||
		next.Completed[len(next.Completed)-1].ResourceID != "ocid1.instance.seed" {
		t.Fatalf("reconcile = %+v, %v", next, err)
	}
	for next.Phase != Retired {
		if next, err = driver.Advance(ctx, 1, "sfo"); err != nil {
			t.Fatalf("teardown at %s: %v", next.Phase, err)
		}
	}
	if effector.executes[StepSeedLaunch] != 0 {
		t.Fatal("retirement re-ran the seed launch")
	}
}

// countingFencer delegates and runs then after the given number of
// successful guards.
type countingFencer struct {
	inner authority.Fencer
	after int
	count int
	then  func()
}

func (c *countingFencer) Current() authority.Snapshot { return c.inner.Current() }

func (c *countingFencer) Guard(ctx context.Context, epoch uint64) error {
	if err := c.inner.Guard(ctx, epoch); err != nil {
		return err
	}
	c.count++
	if c.count == c.after {
		c.then()
	}
	return nil
}
