package autoscale

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func cancelledTarget() Target {
	return Target{Region: "gru", Members: 2, RemovalOperationID: "cancelled-operation", RemovalHostID: "host-c", RemovalIncarnation: "boot-c", RemovalResourceID: "oci-c", RemovalSlot: 3, RemovalPhase: "intent", OperationID: "scale-down", ConsecutiveLowSamples: 3}
}

func TestCancelledRemovalRestoresCapacityAtomicallyAcrossRestart(t *testing.T) {
	now := time.Now().UTC()
	targets := &testTargets{value: cancelledTarget(), found: true}
	calls := 0
	construct := func() *Controller {
		c := testController(t, &testSource{}, targets, now)
		c.config.RemovalOutcome = func(_ context.Context, target Target) (RemovalOutcome, error) {
			calls++
			if target.RemovalOperationID != "cancelled-operation" || target.RemovalResourceID != "oci-c" {
				t.Fatalf("wrong cancellation identity: %+v", target)
			}
			return RemovalCancelled, nil
		}
		return c
	}
	plan, changed, err := construct().Evaluate(t.Context(), "gru")
	if err != nil || !changed || plan.DesiredMembers != 3 || plan.PreviousMembers != 2 {
		t.Fatalf("restore plan: %+v %v %v", plan, changed, err)
	}
	if targets.writes != 1 || targets.value.Members != 3 || targets.value.RemovalOperationID != "" || targets.value.RemovalResourceID != "" || targets.value.RemovalHostID != "" || targets.value.RemovalIncarnation != "" || targets.value.RemovalSlot != 0 || targets.value.RemovalPhase != "" || targets.value.OperationID != "" || len(targets.value.CompletedRemovals) != 0 {
		t.Fatalf("cancellation was not one atomic restoration: %+v writes=%d", targets.value, targets.writes)
	}
	retained := targets.value
	if _, changed, err := construct().Evaluate(t.Context(), "gru"); err != nil || changed {
		t.Fatalf("restart repeated restoration: %v %v", changed, err)
	}
	if calls != 1 || targets.writes != 1 || !reflect.DeepEqual(retained, targets.value) {
		t.Fatal("terminal cancellation was applied more than once")
	}
}

type racingCancellationStore struct {
	testTargets
}

func (s *racingCancellationStore) CompareAndSwap(_ context.Context, _ string, expected *Target, next Target) error {
	if !reflect.DeepEqual(*expected, s.value) {
		return ErrConflict
	}
	s.value = next
	s.writes++
	return nil
}

func TestLateRemovalTerminalOutcomeCannotClearReplacementIntent(t *testing.T) {
	for _, outcome := range []RemovalOutcome{RemovalCancelled, RemovalCompleted} {
		t.Run(string(outcome), func(t *testing.T) {
			targets := &racingCancellationStore{testTargets: testTargets{value: cancelledTarget(), found: true}}
			c := testController(t, &testSource{}, targets, time.Now().UTC())
			c.config.RemovalOutcome = func(context.Context, Target) (RemovalOutcome, error) {
				// Another authority-owned reconcile wins while this journal read
				// is in flight. Its newer exact target must survive the late reply.
				targets.value.RemovalOperationID = "replacement-operation"
				targets.value.RemovalResourceID = "oci-replacement"
				return outcome, nil
			}
			if _, changed, err := c.Evaluate(t.Context(), "gru"); err != nil || changed {
				t.Fatalf("late outcome: %v %v", changed, err)
			}
			if targets.value.RemovalOperationID != "replacement-operation" || targets.value.RemovalResourceID != "oci-replacement" || targets.value.Members != 2 || targets.writes != 0 || len(targets.value.CompletedRemovals) != 0 {
				t.Fatalf("late outcome corrupted newer target: %+v", targets.value)
			}
		})
	}
}

func TestCancelledRemovalAllowsFreshQualifiedReselection(t *testing.T) {
	now := time.Now().UTC()
	targets := &testTargets{value: cancelledTarget(), found: true}
	source := &testSource{}
	c := testController(t, source, targets, now)
	c.config.Cooldown = 0
	c.config.LowSamples = 1
	c.config.RemovalOutcome = func(context.Context, Target) (RemovalOutcome, error) {
		return RemovalCancelled, nil
	}
	if _, restored, err := c.Evaluate(t.Context(), "gru"); err != nil || !restored {
		t.Fatalf("restore: %v %v", restored, err)
	}
	for sequence := int64(1); sequence <= 2; sequence++ {
		source.observations = lowObservationsWithProof(now, sequence)
		plan, selected, err := c.Evaluate(t.Context(), "gru")
		if err != nil {
			t.Fatal(err)
		}
		if selected {
			if plan.OperationID == "cancelled-operation" || plan.OperationID == "" || plan.DesiredMembers != 2 || targets.value.RemovalOperationID != plan.OperationID {
				t.Fatalf("invalid fresh intent: %+v", plan)
			}
			return
		}
	}
	t.Fatal("cancelled intent blocked fresh qualified selection")
}

func TestCancelledContextPreservesRemovalIntent(t *testing.T) {
	targets := &testTargets{value: cancelledTarget(), found: true}
	c := testController(t, &testSource{}, targets, time.Now().UTC())
	ctx, cancel := context.WithCancel(t.Context())
	c.config.RemovalOutcome = func(context.Context, Target) (RemovalOutcome, error) {
		cancel()
		return RemovalCancelled, nil
	}
	retained := targets.value
	if _, changed, err := c.Evaluate(ctx, "gru"); !errors.Is(err, context.Canceled) || changed {
		t.Fatalf("canceled terminal outcome: changed=%v err=%v", changed, err)
	}
	if targets.writes != 0 || !reflect.DeepEqual(targets.value, retained) {
		t.Fatalf("canceled evaluation mutated removal intent: writes=%d target=%+v", targets.writes, targets.value)
	}
}

func TestCanceledContextDoesNotReplayPendingRemoval(t *testing.T) {
	targets := &testTargets{value: cancelledTarget(), found: true}
	c := testController(t, &testSource{}, targets, time.Now().UTC())
	c.config.RemovalOutcome = func(context.Context, Target) (RemovalOutcome, error) {
		t.Fatal("canceled evaluation invoked removal progress")
		return RemovalPending, nil
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, changed, err := c.Evaluate(ctx, "gru"); !errors.Is(err, context.Canceled) || changed {
		t.Fatalf("canceled pending outcome: changed=%v err=%v", changed, err)
	}
	if targets.writes != 0 {
		t.Fatalf("canceled evaluation wrote target: %d", targets.writes)
	}
}
