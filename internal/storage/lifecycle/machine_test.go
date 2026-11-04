package lifecycle

import (
	"errors"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func mustApply(t *testing.T, state State, event Event, at time.Time) State {
	t.Helper()
	next, err := Apply(state, event, at, "")
	if err != nil {
		t.Fatalf("Apply(%s, %s): %v", state.Phase, event, err)
	}
	return next
}

func TestHappyPathReachesMountedAndDeleted(t *testing.T) {
	state := New(t0)
	steps := []struct {
		event Event
		want  Phase
	}{
		{EventCreateRequested, Creating},
		{EventCreated, Available},
		{EventAttachRequested, Attaching},
		{EventAttached, Attached},
		{EventFormatStarted, Formatting},
		{EventMounted, Mounted},
		{EventResizeRequested, Resizing},
		{EventResized, Mounted},
		{EventDetachRequested, Detaching},
		{EventDetached, Detached},
		{EventAttachRequested, Attaching},
		{EventDetached, Detached},
		{EventDeleteRequested, Deleting},
		{EventDeleted, Deleted},
	}
	for index, step := range steps {
		state = mustApply(t, state, step.event, t0.Add(time.Duration(index)*time.Second))
		if state.Phase != step.want {
			t.Fatalf("step %d %s: phase %s, want %s", index, step.event, state.Phase, step.want)
		}
		if !state.Since.Equal(t0.Add(time.Duration(index) * time.Second)) {
			t.Fatalf("step %d: Since was not restarted on progress", index)
		}
	}
	if _, err := Apply(state, EventCreateRequested, t0, ""); !errors.Is(err, ErrTerminal) {
		t.Fatalf("Deleted accepted another event: %v", err)
	}
	if _, err := Apply(state, EventHold, t0, "x"); !errors.Is(err, ErrTerminal) {
		t.Fatalf("Deleted accepted a hold: %v", err)
	}
}
