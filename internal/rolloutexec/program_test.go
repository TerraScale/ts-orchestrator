package rolloutexec

import (
	"context"
	"slices"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
)

// releaseHarness drives the executor from the store's desired release.
func releaseHarness(t *testing.T) (*harness, ReleaseProgram) {
	t.Helper()
	h := newHarness(t)
	controllers, err := ControllerUnits([]string{"ctl-a", "ctl-b", "ctl-c"}, "ctl-a")
	if err != nil {
		t.Fatal(err)
	}
	program := ReleaseProgram{Store: h.store, Proofs: h.fleet, Controllers: controllers, Policy: testPolicy(),
		Now: h.clock.Now}
	h.executor.Program = program.Program
	return h, program
}

func (h *harness) publish(digest string) rollout.Release {
	h.t.Helper()
	release, err := h.store.PublishRelease(h.t.Context(), 7, rollout.Release{Digest: digest, Actor: "ci", CreatedAt: h.clock.Now()})
	if err != nil {
		h.t.Fatalf("publish %s: %v", digest[:4], err)
	}
	return release
}

func (h *harness) digests(units ...string) []string {
	var digests []string
	for _, unit := range units {
		digests = append(digests, h.fleet.units[unit].digest)
	}
	return digests
}

func TestReleaseProgramMovesEveryControllerToTheDesiredReleaseSeedLast(t *testing.T) {
	h, program := releaseHarness(t)
	if got, err := program.Program(t.Context()); got != nil || err != nil {
		t.Fatalf("program without a desired release = %v %v", got, err)
	}
	// Generation 1 names what the controllers already run: nothing starts.
	h.publish(fromDigest)
	if got, err := program.Program(t.Context()); got != nil || err != nil {
		t.Fatalf("program for the running release = %v %v", got, err)
	}
	h.publish(toDigest)
	h.run(100, func() bool {
		return h.phase(entityid.Derive("release-controllers", ReleaseRolloutID(2))) == rollout.PhaseComplete
	})
	if steps := h.fleet.stepLog(); !slices.Equal(steps, []string{"prepare:ctl-b", "prepare:ctl-c", "prepare:ctl-a"}) {
		t.Fatalf("steps = %v, want one controller per wave and the seed last", steps)
	}
	if got := h.digests("h1", "h2", "h3", "h4"); slices.ContainsFunc(got, func(d string) bool { return d != fromDigest }) {
		t.Fatalf("hosts moved: %v", got)
	}
	// The completed program starts nothing more.
	for range 3 {
		if err := h.executor.Tick(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if steps := h.fleet.stepLog(); len(steps) != 3 {
		t.Fatalf("a completed release moved units again: %v", steps)
	}
}

func TestReleaseProgramHonorsPauseAndRollsBackToAnEarlierGeneration(t *testing.T) {
	h, _ := releaseHarness(t)
	h.publish(fromDigest)
	if _, err := h.store.PauseReleases(t.Context(), 7, true); err != nil {
		t.Fatal(err)
	}
	h.publish(toDigest)
	for range 3 {
		if err := h.executor.Tick(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if steps := h.fleet.stepLog(); len(steps) != 0 {
		t.Fatalf("a paused cell started a rollout: %v", steps)
	}
	if _, err := h.store.PauseReleases(t.Context(), 7, false); err != nil {
		t.Fatal(err)
	}
	h.run(100, func() bool {
		return h.phase(entityid.Derive("release-controllers", ReleaseRolloutID(2))) == rollout.PhaseComplete
	})

	back, err := h.store.RollbackRelease(t.Context(), 7, 1, "ops", h.clock.Now())
	if err != nil || back.Generation != 3 || back.Digest != fromDigest {
		t.Fatalf("rollback = %+v %v", back, err)
	}
	h.run(100, func() bool {
		return h.phase(entityid.Derive("release-controllers", ReleaseRolloutID(3))) == rollout.PhaseComplete
	})
	if got := h.digests("ctl-a", "ctl-b", "ctl-c"); slices.ContainsFunc(got, func(d string) bool { return d != fromDigest }) {
		t.Fatalf("controllers after the rollback generation: %v", got)
	}
	// A rollback generation is a forward rollout to the earlier release: the
	// release it left is not known bad.
	if bad, err := h.store.IsKnownBad(t.Context(), toDigest); err != nil || bad {
		t.Fatalf("rolled-back-to generation marked its predecessor known bad: %v %v", bad, err)
	}
}

func TestAbortRollsBackARolloutTheOperatorSuperseded(t *testing.T) {
	h, program := releaseHarness(t)
	h.publish(fromDigest)
	h.publish(toDigest)
	h.run(20, func() bool { return h.fleet.units["ctl-b"].digest == toDigest })
	back, err := h.store.RollbackRelease(t.Context(), 7, 1, "ops", h.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if id, err := Abort(t.Context(), h.store, 7, back.Digest, "rolled back to generation 1", h.clock.Now()); err != nil || id != entityid.Derive("release-controllers", ReleaseRolloutID(2)) {
		t.Fatalf("abort = %q %v", id, err)
	}
	h.run(20, func() bool {
		return h.phase(entityid.Derive("release-controllers", ReleaseRolloutID(2))) == rollout.PhaseRolledBack
	})
	if got := h.digests("ctl-a", "ctl-b", "ctl-c"); slices.ContainsFunc(got, func(d string) bool { return d != fromDigest }) {
		t.Fatalf("controllers after the abort: %v", got)
	}
	if bad, err := h.store.IsKnownBad(t.Context(), toDigest); err != nil || !bad {
		t.Fatalf("the aborted target is not known bad: %v %v", bad, err)
	}
	// Generation 3 names what every controller runs again: nothing starts,
	// and a later publish of the rejected binary is refused.
	if got, err := program.Program(t.Context()); got != nil || err != nil {
		t.Fatalf("program after the rollback = %v %v", got, err)
	}
	if _, err := h.store.PublishRelease(t.Context(), 7, rollout.Release{Digest: toDigest, Actor: "ci", CreatedAt: h.clock.Now()}); err == nil {
		t.Fatal("the rejected binary was published again")
	}
	// Aborting with nothing active, or a rollout that already targets the
	// digest, does nothing.
	if id, err := Abort(t.Context(), h.store, 7, fromDigest, "again", h.clock.Now()); err != nil || id != "" {
		t.Fatalf("abort without an active rollout = %q %v", id, err)
	}
}

func TestResumeRetriesTheRollbackOfAFrozenRollout(t *testing.T) {
	h, _ := releaseHarness(t)
	h.fleet.wrongBinary["ctl-b"] = true
	h.fleet.refuseRollback = true
	h.publish(fromDigest)
	h.publish(toDigest)
	h.run(10, func() bool {
		return h.phase(entityid.Derive("release-controllers", ReleaseRolloutID(2))) == rollout.PhaseFrozen
	})
	if id, err := Resume(t.Context(), h.store, h.fleet, 7, h.clock.Now()); err != nil || id != entityid.Derive("release-controllers", ReleaseRolloutID(2)) {
		t.Fatalf("resume = %q %v", id, err)
	}
	h.fleet.refuseRollback = false
	h.run(10, func() bool {
		return h.phase(entityid.Derive("release-controllers", ReleaseRolloutID(2))) == rollout.PhaseRolledBack
	})
	if id, err := Resume(t.Context(), h.store, h.fleet, 7, h.clock.Now()); err != nil || id != "" {
		t.Fatalf("resume without a frozen rollout = %q %v", id, err)
	}
}

// A resume that leaves one controller on the release an operator installed
// still rolls its group peer back: the left controller serves as its peer.
func TestResumeRollsBackThePeersOfAUnitAnOperatorMovedOffTheTarget(t *testing.T) {
	h, _ := releaseHarness(t)
	h.fleet.wrongBinary["ctl-c"] = true
	h.fleet.refuseRollback = true
	h.publish(fromDigest)
	h.publish(toDigest)
	h.run(100, func() bool {
		return h.phase(entityid.Derive("release-controllers", ReleaseRolloutID(2))) == rollout.PhaseFrozen
	})
	if record, _ := h.load(entityid.Derive("release-controllers", ReleaseRolloutID(2))); record.Units["ctl-b"].State != rollout.UnitRollingBack {
		t.Fatalf("ctl-b = %s, want it waiting for its rollback", record.Units["ctl-b"].State)
	}
	fixed := strings.Repeat("d", 64)
	h.fleet.units["ctl-c"].digest = fixed
	h.fleet.restart("ctl-c")
	h.fleet.refuseRollback = false
	steps := len(h.fleet.stepLog())
	if id, err := Resume(t.Context(), h.store, h.fleet, 7, h.clock.Now()); err != nil || id != entityid.Derive("release-controllers", ReleaseRolloutID(2)) {
		t.Fatalf("resume = %q %v", id, err)
	}
	h.run(20, func() bool {
		return h.phase(entityid.Derive("release-controllers", ReleaseRolloutID(2))) == rollout.PhaseRolledBack
	})
	if got := h.fleet.stepLog()[steps:]; !slices.Equal(got, []string{"rollback:ctl-b"}) {
		t.Fatalf("steps after the resume = %v, want ctl-b's rollback only", got)
	}
	if got := h.digests("ctl-a", "ctl-b", "ctl-c"); !slices.Equal(got, []string{fromDigest, fromDigest, fixed}) {
		t.Fatalf("controllers after the resume: %v", got)
	}
}

// A frozen canary rollback resumes once an operator moved a pending peer to
// a newer release: the peer is not stepped and serves as the canary's peer.
func TestResumeRollsBackACanaryWhosePendingPeerAnOperatorMoved(t *testing.T) {
	h, _ := releaseHarness(t)
	h.fleet.wrongBinary["ctl-b"] = true
	h.fleet.refuseRollback = true
	h.publish(fromDigest)
	h.publish(toDigest)
	h.run(10, func() bool {
		return h.phase(entityid.Derive("release-controllers", ReleaseRolloutID(2))) == rollout.PhaseFrozen
	})
	fixed := strings.Repeat("d", 64)
	h.fleet.units["ctl-c"].digest = fixed
	h.fleet.restart("ctl-c")
	h.fleet.refuseRollback = false
	steps := len(h.fleet.stepLog())
	if id, err := Resume(t.Context(), h.store, h.fleet, 7, h.clock.Now()); err != nil || id != entityid.Derive("release-controllers", ReleaseRolloutID(2)) {
		t.Fatalf("resume = %q %v", id, err)
	}
	h.run(20, func() bool {
		return h.phase(entityid.Derive("release-controllers", ReleaseRolloutID(2))) == rollout.PhaseRolledBack
	})
	if got := h.fleet.stepLog()[steps:]; !slices.Equal(got, []string{"rollback:ctl-b"}) {
		t.Fatalf("steps after the resume = %v, want the canary's rollback only", got)
	}
	if record, _ := h.load(entityid.Derive("release-controllers", ReleaseRolloutID(2))); record.Units["ctl-c"].State != rollout.UnitPending {
		t.Fatalf("ctl-c = %s, want it left pending", record.Units["ctl-c"].State)
	}
}

// An operator who moved a frozen rollout's units by hand to a newer release
// resumes it without stepping them back to the old one, and the next
// generation starts from what they run (ts-gru-2, 2026-10-08).
func TestResumeLeavesTheUnitsAnOperatorMovedOffTheTarget(t *testing.T) {
	h, program := releaseHarness(t)
	h.fleet.wrongBinary["ctl-b"] = true
	h.fleet.refuseRollback = true
	h.publish(fromDigest)
	h.publish(toDigest)
	h.run(10, func() bool {
		return h.phase(entityid.Derive("release-controllers", ReleaseRolloutID(2))) == rollout.PhaseFrozen
	})
	fixed := strings.Repeat("d", 64)
	for _, unit := range []string{"ctl-a", "ctl-b", "ctl-c"} {
		h.fleet.units[unit].digest = fixed
		h.fleet.restart(unit)
	}
	steps := len(h.fleet.stepLog())
	if id, err := Resume(t.Context(), h.store, h.fleet, 7, h.clock.Now()); err != nil || id != entityid.Derive("release-controllers", ReleaseRolloutID(2)) {
		t.Fatalf("resume = %q %v", id, err)
	}
	if phase := h.phase(entityid.Derive("release-controllers", ReleaseRolloutID(2))); !phase.Terminal() {
		t.Fatalf("resumed rollout = %s, want it ended", phase)
	}
	for range 3 {
		if err := h.executor.Tick(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if got := h.fleet.stepLog()[steps:]; len(got) != 0 {
		t.Fatalf("resume stepped units back: %v", got)
	}
	// The next generation names what they run: nothing starts.
	h.publish(fixed)
	if got, err := program.Program(t.Context()); got != nil || err != nil {
		t.Fatalf("program for the release the operator installed = %v %v", got, err)
	}
}

func TestReleaseProgramMovesOnlyTheControllersBehind(t *testing.T) {
	h, _ := releaseHarness(t)
	h.publish(fromDigest)
	// The seed and ctl-c already run the target (a replaced slot, say):
	// only ctl-b moves.
	h.fleet.units["ctl-a"].digest = toDigest
	h.fleet.units["ctl-c"].digest = toDigest
	h.publish(toDigest)
	h.run(50, func() bool {
		return h.phase(entityid.Derive("release-controllers", ReleaseRolloutID(2))) == rollout.PhaseComplete
	})
	if steps := h.fleet.stepLog(); !slices.Equal(steps, []string{"prepare:ctl-b"}) {
		t.Fatalf("steps = %v, want the one controller behind", steps)
	}
	record, _ := h.load(entityid.Derive("release-controllers", ReleaseRolloutID(2)))
	if len(record.Units) != 1 {
		t.Fatalf("rollout units = %v", record.Units)
	}
	// Later ticks keep the stored plan instead of re-planning it.
	for range 3 {
		if err := h.executor.Tick(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if steps := h.fleet.stepLog(); len(steps) != 1 {
		t.Fatalf("a completed generation moved units again: %v", steps)
	}
}

func TestReleaseProgramWaitsForEveryControllerToProveOneRelease(t *testing.T) {
	h, program := releaseHarness(t)
	h.publish(fromDigest)
	h.publish(toDigest)
	h.fleet.units["ctl-c"].down = true
	if _, err := program.Program(t.Context()); err == nil || !strings.Contains(err.Error(), "ctl-c has no fresh health proof") {
		t.Fatalf("program with a silent controller: %v", err)
	}
	if err := h.executor.Tick(t.Context()); err == nil {
		t.Fatal("tick started a program without every controller's proof")
	}
	if last := h.status.statuses[len(h.status.statuses)-1]; !strings.Contains(last.Waiting, "ctl-c") {
		t.Fatalf("status does not say why nothing runs: %+v", last)
	}
	h.fleet.units["ctl-c"].down = false
	h.fleet.units["ctl-c"].digest = otherBad
	if _, err := program.Program(t.Context()); err == nil || !strings.Contains(err.Error(), "different releases") {
		t.Fatalf("program with controllers on different releases: %v", err)
	}
	if steps := h.fleet.stepLog(); len(steps) != 0 {
		t.Fatalf("units moved: %v", steps)
	}
}

// Hosts move after the controllers completed, one seat of a TerraBase
// partition at a time; a silent host holds only the host rollout.
func TestReleaseProgramMovesTheHostsAfterTheControllers(t *testing.T) {
	h, program := releaseHarness(t)
	hosts := HostUnits(map[string][]string{"h1": {"p1"}, "h2": {"p1"}, "h3": nil})
	program.Hosts = func(context.Context) ([]rollout.Unit, error) { return hosts, nil }
	h.executor.Program = program.Program
	h.fleet.units["h3"].down = true
	h.publish(fromDigest)
	h.publish(toDigest)
	h.run(50, func() bool {
		return h.phase(entityid.Derive("release-controllers", ReleaseRolloutID(2))) == rollout.PhaseComplete
	})
	if steps := h.fleet.stepLog(); slices.ContainsFunc(steps, func(step string) bool { return strings.Contains(step, ":h") }) {
		t.Fatalf("a host moved before the controllers completed: %v", steps)
	}
	if _, err := program.Program(t.Context()); err == nil || !strings.Contains(err.Error(), "h3 has no fresh health proof") {
		t.Fatalf("host program with a silent host: %v", err)
	}
	h.fleet.units["h3"].down = false
	h.run(80, func() bool {
		return h.phase(entityid.Derive("release-hosts", ReleaseRolloutID(2))) == rollout.PhaseComplete
	})
	if got := h.digests("h1", "h2", "h3"); !slices.Equal(got, []string{toDigest, toDigest, toDigest}) {
		t.Fatalf("host digests = %v", got)
	}
	record, _ := h.load(entityid.Derive("release-hosts", ReleaseRolloutID(2)))
	for _, wave := range record.Waves {
		if slices.Contains(wave, "h1") && slices.Contains(wave, "h2") {
			t.Fatalf("a wave took both seats of p1: %v", record.Waves)
		}
	}
}
