package rolloutexec

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
)

type fakeUnit struct {
	digest string
	pid    int64
	nonce  string
	down   bool
	// age makes the unit's newest proof this old.
	age time.Duration
}

// fakeFleet simulates unit agents and their health proofs. Proofs are
// observed at the test clock's current time.
type fakeFleet struct {
	mu    sync.Mutex
	clock *clock
	units map[string]*fakeUnit
	steps []string
	// wrongBinary units restart on their old release (a watchdog rollback).
	wrongBinary    map[string]bool
	refuseRollback bool
	// retryRollbacks answers this many rollback steps with retry first.
	retryRollbacks int
	// failSteps fails this many steps to a unit as undelivered.
	failSteps map[string]int
	// slowRestart units accept a forward step but keep proving the old
	// incarnation until the test restarts them.
	slowRestart map[string]bool
	nextPID     int64
}

func newFleet(c *clock, digest string, units ...string) *fakeFleet {
	fleet := &fakeFleet{clock: c, units: map[string]*fakeUnit{}, wrongBinary: map[string]bool{},
		failSteps: map[string]int{}, slowRestart: map[string]bool{}, nextPID: 100}
	for _, unit := range units {
		fleet.units[unit] = &fakeUnit{digest: digest}
		fleet.restart(unit)
	}
	return fleet
}

func (f *fakeFleet) restart(unit string) {
	f.nextPID++
	u := f.units[unit]
	u.pid, u.nonce = f.nextPID, fmt.Sprintf("%032x", f.nextPID)
}

func (f *fakeFleet) Latest(unit string) (HealthProof, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, exists := f.units[unit]
	if !exists || u.down {
		return HealthProof{}, false
	}
	return HealthProof{Schema: HealthSchema, Cell: "gru", Unit: unit, BinarySHA256: u.digest, ProcessID: u.pid,
		StartNonce: u.nonce, ObservedAt: f.clock.Now().Add(-u.age)}, true
}

func (f *fakeFleet) Step(_ context.Context, step Step) (StepReply, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.steps = append(f.steps, string(step.Action)+":"+step.Unit)
	if f.failSteps[step.Unit] > 0 {
		f.failSteps[step.Unit]--
		return StepReply{}, errors.New("no responders")
	}
	reply := StepReply{OperationID: step.OperationID, Unit: step.Unit}
	u := f.units[step.Unit]
	switch {
	case step.Action == StepPrepare && f.slowRestart[step.Unit]:
		reply.Outcome = OutcomeActivated
	case step.Action == StepRollback && f.refuseRollback:
		reply.Outcome, reply.Reason = OutcomeRefused, "release is known bad on this node"
	case step.Action == StepRollback && f.retryRollbacks > 0:
		f.retryRollbacks--
		reply.Outcome, reply.Reason = OutcomeRetry, "unit restart failed"
	case u.digest == step.Digest:
		reply.Outcome = OutcomeCurrent
	default:
		if !(step.Action == StepPrepare && f.wrongBinary[step.Unit]) {
			u.digest = step.Digest
		}
		f.restart(step.Unit)
		reply.Outcome = OutcomeActivated
	}
	return reply, nil
}

func (f *fakeFleet) stepLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.steps)
}

type fakeGate struct {
	mu    sync.Mutex
	holds map[string]int
	calls int
}

func (g *fakeGate) Check(_ context.Context, _ rollout.Record, unit string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls++
	if g.holds[unit] > 0 {
		g.holds[unit]--
		return fmt.Errorf("%w: test hold", ErrGateHeld)
	}
	return nil
}

type statusLog struct {
	mu       sync.Mutex
	statuses []Status
}

func (s *statusLog) PublishStatus(status Status) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.statuses = append(s.statuses, status)
}

func (s *statusLog) heldUnits() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var units []string
	for _, status := range s.statuses {
		for unit := range status.Holds {
			if !slices.Contains(units, unit) {
				units = append(units, unit)
			}
		}
	}
	return units
}

type harness struct {
	t        *testing.T
	clock    *clock
	fence    *epochFence
	store    *rollout.Store
	fleet    *fakeFleet
	gate     *fakeGate
	status   *statusLog
	executor *Executor
	program  Program
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	c := &clock{now: testStart}
	fence := newFence(7)
	h := &harness{t: t, clock: c, fence: fence, store: testStore(t, fence),
		fleet: newFleet(c, fromDigest, "ctl-a", "ctl-b", "ctl-c", "h1", "h2", "h3", "h4"),
		gate:  &fakeGate{holds: map[string]int{}}, status: &statusLog{}}
	controllers, err := ControllerUnits([]string{"ctl-a", "ctl-b", "ctl-c"}, "ctl-a")
	if err != nil {
		t.Fatal(err)
	}
	hosts := HostUnits(map[string][]string{"h1": {"p1"}, "h2": {"p1"}, "h3": {"p2"}, "h4": {"p3"}})
	policy := testPolicy()
	policy.BatchSize = 2
	h.program = SelfUpdateProgram("rel1", "gru", fromDigest, toDigest, controllers, hosts, policy)
	h.executor = &Executor{Cell: "gru", Store: h.store, Fencer: fence, Driver: h.fleet, Proofs: h.fleet, Gate: h.gate,
		Status: h.status, Now: c.Now,
		Program: func(context.Context) (Program, error) { return h.program, nil }}
	return h
}

// run ticks until done reports true, advancing the clock between ticks.
func (h *harness) run(limit int, done func() bool) {
	h.t.Helper()
	for range limit {
		if err := h.executor.Tick(h.t.Context()); err != nil {
			h.t.Fatalf("tick: %v", err)
		}
		if done() {
			return
		}
		h.clock.Advance(20 * time.Second)
	}
	h.t.Fatalf("not done after %d ticks; steps %v", limit, h.fleet.stepLog())
}

func (h *harness) load(id string) (rollout.Record, bool) {
	h.t.Helper()
	record, _, err := h.store.Load(h.t.Context(), id)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return rollout.Record{}, false
	}
	if err != nil {
		h.t.Fatal(err)
	}
	return record, true
}

func (h *harness) phase(id string) rollout.Phase {
	record, exists := h.load(id)
	if !exists {
		return ""
	}
	return record.Phase
}

func TestExecutorRunsControllersSeedLastThenHostsOneSeatPerPartition(t *testing.T) {
	h := newHarness(t)
	// The cluster gate holds the second controller step twice; the step
	// waits and the hold is reported in the status.
	h.gate.holds["ctl-c"] = 2
	h.run(200, func() bool { return h.phase("rel1-hosts") == rollout.PhaseComplete })

	if got := h.phase("rel1-controllers"); got != rollout.PhaseComplete {
		t.Fatalf("controller rollout = %s", got)
	}
	steps := h.fleet.stepLog()
	want := []string{"prepare:ctl-b", "prepare:ctl-c", "prepare:ctl-a"}
	if len(steps) < 3 || !slices.Equal(steps[:3], want) {
		t.Fatalf("controllers moved as %v, want non-seed first and the seed last: %v", steps, want)
	}
	for _, step := range steps[3:] {
		if step == "prepare:ctl-a" || step == "prepare:ctl-b" || step == "prepare:ctl-c" {
			t.Fatalf("a controller moved after the hosts started: %v", steps)
		}
	}
	hosts, _ := h.load("rel1-hosts")
	for _, wave := range hosts.Waves {
		if slices.Contains(wave, "h1") && slices.Contains(wave, "h2") {
			t.Fatalf("two seats of partition p1 moved in one wave: %v", hosts.Waves)
		}
	}
	if len(hosts.Waves) != 3 {
		t.Fatalf("host waves = %v, want a canary and two batches", hosts.Waves)
	}
	for unit, u := range h.fleet.units {
		if u.digest != toDigest {
			t.Fatalf("unit %s still runs %s", unit, u.digest)
		}
	}
	if !slices.Contains(h.status.heldUnits(), "ctl-c") {
		t.Fatalf("the gate hold of ctl-c was not reported: %v", h.status.heldUnits())
	}
	if h.gate.calls < len(h.fleet.units) {
		t.Fatalf("gate checked %d times for %d steps", h.gate.calls, len(h.fleet.units))
	}
}

func TestExecutorRollsBackACanaryThatRestartsOnTheWrongBinary(t *testing.T) {
	h := newHarness(t)
	h.fleet.wrongBinary["ctl-b"] = true
	// Well inside the 600s proof deadline: the new incarnation on the old
	// release is detected directly, not by the deadline.
	h.run(10, func() bool { return h.phase("rel1-controllers") == rollout.PhaseRolledBack })

	if steps := h.fleet.stepLog(); !slices.Equal(steps, []string{"prepare:ctl-b", "rollback:ctl-b"}) {
		t.Fatalf("steps = %v", steps)
	}
	bad, err := h.store.IsKnownBad(t.Context(), toDigest)
	if err != nil || !bad {
		t.Fatalf("rolled-back target is not known bad: %v %v", bad, err)
	}
	// The program stops: the hosts never start on a release the
	// controllers rejected.
	for range 3 {
		if err := h.executor.Tick(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if _, exists := h.load("rel1-hosts"); exists {
		t.Fatal("the host rollout started after the controller rollout was rolled back")
	}
}

func TestExecutorFreezesWhenARollbackIsRefused(t *testing.T) {
	h := newHarness(t)
	h.fleet.wrongBinary["ctl-b"] = true
	h.fleet.refuseRollback = true
	h.run(10, func() bool { return h.phase("rel1-controllers") == rollout.PhaseFrozen })
	if err := h.executor.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if steps := h.fleet.stepLog(); slices.Contains(steps, "prepare:ctl-c") {
		t.Fatalf("a frozen rollout kept moving forward: %v", steps)
	}
}

func TestExecutorFollowerIsIdleAndANewLeaderAdopts(t *testing.T) {
	h := newHarness(t)
	h.run(20, func() bool {
		record, exists := h.load("rel1-controllers")
		return exists && record.Phase == rollout.PhaseCanarySoak
	})
	steps := len(h.fleet.stepLog())
	h.fence.leader.Store(false)
	for range 5 {
		h.clock.Advance(20 * time.Second)
		if err := h.executor.Tick(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if len(h.fleet.stepLog()) != steps {
		t.Fatal("a follower sent steps")
	}
	h.fence.epoch.Store(8)
	h.fence.leader.Store(true)
	h.run(200, func() bool { return h.phase("rel1-controllers") == rollout.PhaseComplete })
	record, _ := h.load("rel1-controllers")
	if record.AuthorityEpoch != 8 {
		t.Fatalf("the new leader did not adopt the rollout: epoch %d", record.AuthorityEpoch)
	}
}

func TestExecutorHoldsAStepWhileAGroupPeerIsNotServing(t *testing.T) {
	h := newHarness(t)
	h.program = h.program[:1]
	// Pass preflight, then lose a peer before the canary step is sent.
	h.gate.holds["ctl-b"] = 1
	if err := h.executor.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := h.phase("rel1-controllers"); got != rollout.PhaseCanary {
		t.Fatalf("phase = %s", got)
	}
	h.fleet.units["ctl-c"].down = true
	for range 5 {
		h.clock.Advance(20 * time.Second)
		if err := h.executor.Tick(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if steps := h.fleet.stepLog(); len(steps) != 0 {
		t.Fatalf("a step was sent while its group peer was down: %v", steps)
	}
	h.fleet.units["ctl-c"].down = false
	h.run(200, func() bool { return h.phase("rel1-controllers") == rollout.PhaseComplete })
}

func TestExecutorPreflightWaitsForProofsAndAbortsOnAForeignRelease(t *testing.T) {
	h := newHarness(t)
	h.program = h.program[:1]
	h.fleet.units["ctl-c"].down = true
	for range 3 {
		if err := h.executor.Tick(t.Context()); err != nil {
			t.Fatal(err)
		}
		h.clock.Advance(20 * time.Second)
	}
	if got := h.phase("rel1-controllers"); got != rollout.PhasePreflight {
		t.Fatalf("phase = %s, want preflight held for the missing proof", got)
	}
	if !slices.Contains(h.status.heldUnits(), "preflight") {
		t.Fatal("the preflight hold was not reported")
	}
	h.fleet.units["ctl-c"].down = false
	h.fleet.units["ctl-c"].digest = otherBad
	h.run(5, func() bool { return h.phase("rel1-controllers") == rollout.PhaseAborted })
	if len(h.fleet.stepLog()) != 0 {
		t.Fatalf("an aborted preflight sent steps: %v", h.fleet.stepLog())
	}
}

func TestExecutorFencesEveryStepAndIgnoresStaleProofs(t *testing.T) {
	h := newHarness(t)
	h.program = h.program[:1]
	h.gate.holds["ctl-b"] = 1
	if err := h.executor.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	// The lease is lost after the tick's snapshot: no step leaves.
	h.fence.lost.Store(true)
	if err := h.executor.Tick(t.Context()); err == nil {
		t.Fatal("a tick whose lease was lost before the step succeeded")
	}
	if steps := h.fleet.stepLog(); len(steps) != 0 {
		t.Fatalf("a step left after the lease was lost: %v", steps)
	}
	h.fence.lost.Store(false)
	// The canary only ever reports stale proofs: they never count towards
	// its soak, however much later they were observed than the phase start.
	h.fleet.units["ctl-b"].age = 2 * DefaultProofFreshness
	for range 14 {
		h.clock.Advance(20 * time.Second)
		if err := h.executor.Tick(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	record, _ := h.load("rel1-controllers")
	if record.Phase != rollout.PhaseCanarySoak || record.Units["ctl-b"].HealthyReports != 0 {
		t.Fatalf("stale proofs advanced the canary: %s %+v", record.Phase, record.Units["ctl-b"])
	}
	if steps := h.fleet.stepLog(); !slices.Equal(steps, []string{"prepare:ctl-b"}) {
		t.Fatalf("steps = %v", steps)
	}
}

func TestExecutorCommitsAnExpiredDeadlineBeforeSendingAStep(t *testing.T) {
	h := newHarness(t)
	h.program = h.program[:1]
	h.gate.holds["ctl-b"] = 1
	if err := h.executor.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	// The leader resumes long after the canary's prepare deadline.
	h.clock.Advance(time.Duration(testPolicy().ProofDeadlineSeconds+60) * time.Second)
	h.run(5, func() bool { return h.phase("rel1-controllers") == rollout.PhaseRolledBack })
	if slices.Contains(h.fleet.stepLog(), "prepare:ctl-b") {
		t.Fatalf("an expired prepare was still sent: %v", h.fleet.stepLog())
	}
}

// A unit that restarts on the target after meeting its soak rolls the wave
// back, even when another unit's report would complete the wave first.
func TestExecutorRollsBackAWaveWhoseSoakedUnitRestarted(t *testing.T) {
	h := newHarness(t)
	policy := testPolicy()
	policy.BatchSize = 2
	h.program = Program{{RolloutID: "rel1-hosts", Kind: rollout.KindHost, Cell: "gru", FromDigest: fromDigest,
		ToDigest: toDigest, Policy: policy,
		Units: HostUnits(map[string][]string{"h1": {"p1"}, "h3": {"p2"}, "h4": {"p3"}})}}
	if err := h.executor.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	// h3 starts reporting one tick after h4, so h4 meets its soak one tick
	// before h3's next report would complete the wave.
	h.fleet.units["h3"].age = 2 * DefaultProofFreshness
	h.run(30, func() bool {
		record, _ := h.load("rel1-hosts")
		return record.WaveIndex == 1 && record.Units["h4"].HealthyReports == 1
	})
	h.fleet.units["h3"].age = 0
	h.clock.Advance(20 * time.Second)
	soak := time.Duration(policy.BatchSoakSeconds) * time.Second
	h.run(10, func() bool {
		record, _ := h.load("rel1-hosts")
		h4 := record.Units["h4"]
		return h4.HealthyReports >= policy.MinHealthyReports && !h4.LastHealthyAt.Before(h4.FirstHealthyAt.Add(soak))
	})
	if record, _ := h.load("rel1-hosts"); record.Phase != rollout.PhaseBatchSoak {
		t.Fatalf("before the restart: %s %+v", record.Phase, record.Units)
	}
	// h4 restarts on the target; h3's next report alone would complete the
	// wave from h4's stored reports.
	h.fleet.restart("h4")
	h.clock.Advance(20 * time.Second)
	if err := h.executor.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if phase := h.phase("rel1-hosts"); phase != rollout.PhaseRollingBack && phase != rollout.PhaseRolledBack {
		t.Fatalf("a wave with a restarted unit ended %s", phase)
	}
}

// Leader-local memory belongs to one rollout: a hold of an ended rollout
// never shows up in the next one's status.
func TestExecutorForgetsTheMemoryOfAnEndedRollout(t *testing.T) {
	h := newHarness(t)
	h.program = h.program[:1]
	h.fleet.units["ctl-c"].down = true
	if err := h.executor.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	h.fleet.units["ctl-c"].down = false
	h.fleet.units["ctl-c"].digest = otherBad
	h.run(5, func() bool { return h.phase("rel1-controllers") == rollout.PhaseAborted })
	h.fleet.units["ctl-c"].digest = fromDigest
	// Memory left from the ended rollout must not reach the next one.
	h.executor.holds["ctl-z"] = "left over from rel1"
	next := h.program[0]
	next.RolloutID, next.ToDigest = "rel2-controllers", strings.Repeat("d", 64)
	h.program = Program{next}
	h.run(5, func() bool { return h.phase("rel2-controllers") == rollout.PhaseCanarySoak })
	h.status.mu.Lock()
	last := h.status.statuses[len(h.status.statuses)-1]
	h.status.mu.Unlock()
	if last.RolloutID != "rel2-controllers" || len(last.Holds) != 0 {
		t.Fatalf("status of the next rollout = %s holds %v", last.RolloutID, last.Holds)
	}
}

// A two-unit wave is not promoted around a unit that stopped proving it
// serves after it had already met its soak.
func TestExecutorDoesNotPromoteAWaveAroundAUnitThatStoppedReporting(t *testing.T) {
	h := newHarness(t)
	policy := testPolicy()
	policy.BatchSize = 2
	h.program = Program{{RolloutID: "rel1-hosts", Kind: rollout.KindHost, Cell: "gru", FromDigest: fromDigest,
		ToDigest: toDigest, Policy: policy,
		Units: HostUnits(map[string][]string{"h1": {"p1"}, "h3": {"p2"}, "h4": {"p3"}})}}
	if err := h.executor.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	// h3 is slow to report; h4 meets its soak first and then goes quiet.
	h.fleet.units["h3"].age = 2 * DefaultProofFreshness
	h.run(30, func() bool {
		record, _ := h.load("rel1-hosts")
		h4 := record.Units["h4"]
		return record.WaveIndex == 1 && h4.HealthyReports >= policy.MinHealthyReports &&
			!h4.LastHealthyAt.Before(h4.FirstHealthyAt.Add(time.Duration(policy.BatchSoakSeconds)*time.Second))
	})
	h.fleet.units["h4"].down = true
	h.fleet.units["h3"].age = 0
	for range 10 {
		h.clock.Advance(20 * time.Second)
		if err := h.executor.Tick(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	record, _ := h.load("rel1-hosts")
	if record.Phase != rollout.PhaseBatchSoak || record.Units["h3"].HealthyReports != 0 {
		t.Fatalf("the wave was promoted around a silent unit: %s %+v", record.Phase, record.Units["h3"])
	}
	if !slices.Contains(h.status.heldUnits(), "soak") {
		t.Fatal("the soak hold was not reported")
	}
}

// rollback-serving needs a proof observed after the accepted rollback
// attempt, not one cached from before it, even when an earlier attempt
// failed.
func TestExecutorNeedsAProofAfterTheAcceptedRollback(t *testing.T) {
	h := newHarness(t)
	h.program = h.program[:1]
	h.fleet.wrongBinary["ctl-b"] = true
	h.fleet.retryRollbacks = 1
	h.run(10, func() bool {
		return slices.Contains(h.fleet.stepLog(), "rollback:ctl-b")
	})
	h.clock.Advance(20 * time.Second)
	if err := h.executor.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if steps := h.fleet.stepLog(); len(steps) != 3 || steps[2] != "rollback:ctl-b" {
		t.Fatalf("steps = %v, want the retried rollback accepted", steps)
	}
	if phase := h.phase("rel1-controllers"); phase != rollout.PhaseRollingBack {
		t.Fatalf("rollback completed on a proof from before its accepted attempt: %s", phase)
	}
	h.run(3, func() bool { return h.phase("rel1-controllers") == rollout.PhaseRolledBack })
}

// A completed program step only counts for the spec it was planned from:
// the same ID retargeted stops the program instead of starting the hosts.
func TestExecutorStopsAProgramWhoseCompletedStepNoLongerMatches(t *testing.T) {
	h := newHarness(t)
	h.run(200, func() bool { return h.phase("rel1-controllers") == rollout.PhaseComplete })
	for index := range h.program {
		h.program[index].ToDigest = strings.Repeat("d", 64)
	}
	for range 3 {
		h.clock.Advance(20 * time.Second)
		if err := h.executor.Tick(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if _, exists := h.load("rel1-hosts"); exists {
		t.Fatal("the hosts started on a target the controllers never ran")
	}
}

// A unit that restarted on its old release before the forward step that
// finally reached it was accepted did not restart onto the wrong binary:
// only an incarnation newer than the accepted attempt speaks for the step.
func TestExecutorJudgesTheStepByTheAttemptThatWasAccepted(t *testing.T) {
	h := newHarness(t)
	h.fleet.failSteps["ctl-b"] = 1
	h.run(10, func() bool { return slices.Contains(h.fleet.stepLog(), "prepare:ctl-b") })
	// An unrelated restart on the old release, before the retry.
	h.fleet.mu.Lock()
	h.fleet.restart("ctl-b")
	h.fleet.slowRestart["ctl-b"] = true
	h.fleet.mu.Unlock()
	h.clock.Advance(20 * time.Second)
	for range 3 {
		if err := h.executor.Tick(t.Context()); err != nil {
			t.Fatal(err)
		}
		h.clock.Advance(5 * time.Second)
	}
	if phase := h.phase("rel1-controllers"); phase == rollout.PhaseRollingBack || phase == rollout.PhaseRolledBack {
		t.Fatalf("a restart before the accepted step rolled the rollout back: %v", h.fleet.stepLog())
	}
	// The unit now restarts onto the target and the rollout moves on.
	h.fleet.mu.Lock()
	h.fleet.slowRestart["ctl-b"] = false
	h.fleet.units["ctl-b"].digest = toDigest
	h.fleet.restart("ctl-b")
	h.fleet.mu.Unlock()
	h.run(40, func() bool { return h.phase("rel1-controllers") == rollout.PhaseComplete })
	if slices.Contains(h.fleet.stepLog(), "rollback:ctl-b") {
		t.Fatalf("steps = %v", h.fleet.stepLog())
	}
}

// A canary promoted by an earlier wave that later proves the old release
// rolls the rollout back: later waves never complete around it, so the
// host rollout never starts.
func TestExecutorRollsBackWhenAPromotedUnitRegresses(t *testing.T) {
	h := newHarness(t)
	h.run(40, func() bool {
		record, exists := h.load("rel1-controllers")
		return exists && record.Units["ctl-b"].State == rollout.UnitPromoted
	})
	h.fleet.mu.Lock()
	h.fleet.units["ctl-b"].digest = fromDigest
	h.fleet.restart("ctl-b")
	h.fleet.mu.Unlock()
	h.clock.Advance(5 * time.Second)
	h.run(10, func() bool { return h.phase("rel1-controllers") == rollout.PhaseRolledBack })
	record, _ := h.load("rel1-controllers")
	if !strings.Contains(record.Reason, "promoted unit ctl-b") {
		t.Fatalf("reason = %q", record.Reason)
	}
	if _, exists := h.load("rel1-hosts"); exists {
		t.Fatal("the host rollout started after a promoted controller regressed")
	}
}

// A successor leader that never saw a unit's accepted step still detects
// the unit coming back on the wrong binary, well before the proof deadline.
func TestExecutorSuccessorDetectsAWrongBinaryAfterFailover(t *testing.T) {
	h := newHarness(t)
	h.fleet.slowRestart["ctl-b"] = true
	h.run(20, func() bool { return h.phase("rel1-controllers") == rollout.PhaseCanarySoak })
	// A new leader with no memory of the step takes over.
	h.fence.epoch.Store(8)
	h.executor = &Executor{Cell: "gru", Store: h.store, Fencer: h.fence, Driver: h.fleet, Proofs: h.fleet,
		Gate: h.gate, Status: h.status, Now: h.clock.Now,
		Program: func(context.Context) (Program, error) { return h.program, nil }}
	for range 2 {
		h.clock.Advance(5 * time.Second)
		if err := h.executor.Tick(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	// The watchdog restarts the unit on its old release.
	h.fleet.mu.Lock()
	h.fleet.restart("ctl-b")
	h.fleet.mu.Unlock()
	start := h.clock.Now()
	h.run(5, func() bool {
		phase := h.phase("rel1-controllers")
		return phase == rollout.PhaseRollingBack || phase == rollout.PhaseRolledBack
	})
	if waited := h.clock.Now().Sub(start); waited >= 600*time.Second {
		t.Fatalf("detected only after %v", waited)
	}
}
