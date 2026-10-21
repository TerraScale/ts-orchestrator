package rollout

import (
	"errors"
	"slices"
	"testing"
	"time"
)

func TestUntouchedObservationExpiryAbortsWithoutBlacklisting(t *testing.T) {
	for _, phase := range []Phase{PhasePending, PhasePreflight} {
		t.Run(string(phase), func(t *testing.T) {
			record := newRecord(t, controllers(), testPolicy())
			record.KnownBad = []string{otherBad}
			completion := EventStart
			if phase == PhasePreflight {
				record = apply(t, record, Event{Kind: EventStart, At: testStart})
				completion = EventPreflightPassed
			}
			for _, event := range []EventKind{EventTick, completion} {
				next := apply(t, record, Event{Kind: event, At: record.StartedAt.Add(ObservationBudget)})
				if next.Phase != PhaseAborted || next.Reason != "release exceeded its fixed 20-minute observation budget" ||
					!slices.Equal(next.KnownBad, record.KnownBad) || len(next.RollbackOrder) != 0 || len(NextActions(next)) != 0 {
					t.Fatalf("untouched expiry = %+v", next)
				}
				for _, progress := range next.Units {
					if progress.State != UnitPending {
						t.Fatalf("untouched unit = %+v", progress)
					}
				}
			}
		})
	}
}

func TestObservationCannotStartInTheFuture(t *testing.T) {
	record, now := startedCanary(t, controllers())
	_, err := New(Spec{StartedAt: now.Add(time.Second), RolloutID: record.RolloutID, Kind: record.Kind,
		Cell: record.Cell, FromDigest: record.FromDigest, ToDigest: record.ToDigest,
		Units: controllers(), Policy: record.Policy, AuthorityEpoch: record.AuthorityEpoch}, now)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("future observation start: %v", err)
	}
}

func TestObservationBudgetCannotRestartBetweenWaves(t *testing.T) {
	record, at := startedCanary(t, controllers())
	deadline := record.StartedAt.Add(ObservationBudget)
	if QualificationBudget+ObservationBudget != 30*time.Minute {
		t.Fatal("qualification and observation must fit one 30-minute window")
	}
	record, at = soakWave(t, record, at)
	if record.Phase != PhaseBatch || !record.StartedAt.Add(ObservationBudget).Equal(deadline) {
		t.Fatalf("new wave restarted observation: %+v", record)
	}
	// A healthy later wave cannot buy another proof/soak deadline.
	record = apply(t, record, Event{Kind: EventPrepared, Unit: "ctrl-c", At: at})
	record = apply(t, record, Event{Kind: EventHealthy, Unit: "ctrl-c", Health: health(at.Add(time.Second), 20), At: at.Add(time.Second)})
	for _, kind := range []EventKind{EventTick, EventHealthy} {
		next := apply(t, record, Event{Kind: kind, Unit: "ctrl-c", Health: health(deadline, 20), At: deadline})
		requireRollingBack(t, next, "fixed 20-minute observation budget")
		if !next.PhaseDeadline.After(deadline) {
			t.Fatal("rollback must have its own recovery budget")
		}
	}
}
