package rolloutexec

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/rollout"
)

func TestExecutorRollbackDeadlineIncludesGateRecovery(t *testing.T) {
	for _, budget := range []int64{20, 60} {
		t.Run(fmt.Sprintf("%ds", budget), func(t *testing.T) {
			h := newHarness(t)
			for i := range h.program {
				h.program[i].Policy.RollbackDeadlineSeconds = budget
			}
			h.fleet.wrongBinary["ctl-b"] = true
			id := h.program[0].RolloutID
			tick := func(delay time.Duration, want rollout.Phase) rollout.Record {
				t.Helper()
				h.clock.Advance(delay)
				if err := h.executor.Tick(t.Context()); err != nil {
					t.Fatal(err)
				}
				record, _ := h.load(id)
				if record.Phase != want {
					t.Fatalf("phase = %s, want %s; reason %q; steps %v", record.Phase, want, record.Reason, h.fleet.stepLog())
				}
				return record
			}

			tick(0, rollout.PhaseCanarySoak)
			// The watchdog has restored the predecessor, but cluster recovery
			// holds the control-plane rollback before it can be acknowledged.
			h.gate.holds["ctl-b"] = 100
			rolling := tick(time.Second, rollout.PhaseRollingBack)
			tick(19*time.Second, rollout.PhaseRollingBack)
			if steps := h.fleet.stepLog(); !slices.Equal(steps, []string{"prepare:ctl-b"}) {
				t.Fatalf("rollback bypassed the gate: %v", steps)
			}
			if !slices.Contains(h.status.heldUnits(), "ctl-b") {
				t.Fatal("rollback gate hold was not reported")
			}

			want := rollout.PhaseRolledBack
			steps := []string{"prepare:ctl-b"}
			if budget == 20 {
				want = rollout.PhaseFrozen
				if record := tick(6*time.Second, want); record.Reason != "rollback deadline exceeded" {
					t.Fatalf("freeze reason = %q", record.Reason)
				}
				h.gate.holds["ctl-b"] = 0
			} else {
				tick(6*time.Second, rollout.PhaseRollingBack)
				h.gate.holds["ctl-b"] = 0
				h.fleet.retryRollbacks = 1
				tick(0, rollout.PhaseRollingBack)
				if steps := h.fleet.stepLog(); !slices.Equal(steps, []string{"prepare:ctl-b", "rollback:ctl-b"}) {
					t.Fatalf("rollback retry was not attempted: %v", steps)
				}
				// The retry was not accepted; a fresh predecessor proof alone
				// must not complete rollback. The next attempt is accepted.
				tick(time.Second, rollout.PhaseRollingBack)
				h.fleet.units["ctl-b"].age = time.Second
				tick(time.Second, rollout.PhaseRollingBack) // cached at the acknowledgement
				h.fleet.units["ctl-b"].age = DefaultProofFreshness + time.Second
				record := tick(DefaultProofFreshness+time.Second, rollout.PhaseRollingBack) // newer, but stale
				if !record.PhaseDeadline.Equal(rolling.PhaseDeadline) {
					t.Fatal("gate recovery or retry extended the rollback deadline")
				}
				h.fleet.units["ctl-b"].age = 0
				tick(time.Second, want)
				steps = append(steps, "rollback:ctl-b", "rollback:ctl-b")
			}

			for range 3 {
				tick(0, want)
			}
			if got := h.fleet.stepLog(); !slices.Equal(got, steps) {
				t.Fatalf("later units moved or rollback was retried after termination: %v", got)
			}
			if _, exists := h.load(h.program[1].RolloutID); exists {
				t.Fatal("host rollout started after the failed controller canary")
			}
			if bad, err := h.store.IsKnownBad(t.Context(), toDigest); err != nil || !bad {
				t.Fatalf("rejected target is not known bad: %v %v", bad, err)
			}
		})
	}
}
