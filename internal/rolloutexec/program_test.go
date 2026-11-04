package rolloutexec

import (
	"slices"

	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/rollout"
)

// releaseHarness drives the executor from the store's desired release.
func releaseHarness(t *testing.T) (*harness, ReleaseProgram) {
	t.Helper()
	h := emptyHarness(t)
	h.executor = &Executor{Cell: "gru", Store: h.store, Fencer: h.fence, Driver: h.fleet, Proofs: h.fleet, Gate: h.gate, Status: h.status, Now: h.clock.Now}
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
		return h.phase(entityid.Derive("release-controllers", rollout.ReleaseRolloutID(2))) == rollout.PhaseComplete
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
		return h.phase(entityid.Derive("release-controllers", rollout.ReleaseRolloutID(2))) == rollout.PhaseComplete
	})

	back, err := h.store.RollbackRelease(t.Context(), 7, 1, "ops", h.clock.Now())
	if err != nil || back.Generation != 3 || back.Digest != fromDigest {
		t.Fatalf("rollback = %+v %v", back, err)
	}
	h.run(100, func() bool {
		return h.phase(entityid.Derive("release-controllers", rollout.ReleaseRolloutID(3))) == rollout.PhaseComplete
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
