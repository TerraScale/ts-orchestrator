// Package lifecycle is the pure retained-volume state machine. It performs no
// I/O: callers feed observed events and the current time, persist the returned
// State with their own CAS, and act on the returned Remediation. Every phase
// that waits on OCI or the host has a deadline, so a volume can never wait in
// ATTACHING (or any other transitional phase) forever.
package lifecycle

import (
	"errors"
	"fmt"
	"time"
)

// Phase is one durable lifecycle phase of a retained volume.
type Phase string

const (
	Pending    Phase = "pending"
	Creating   Phase = "creating"
	Available  Phase = "available"
	Attaching  Phase = "attaching"
	Attached   Phase = "attached"
	Formatting Phase = "formatting"
	Mounted    Phase = "mounted"
	Resizing   Phase = "resizing"
	Detaching  Phase = "detaching"
	Detached   Phase = "detached"
	Deleting   Phase = "deleting"
	Deleted    Phase = "deleted"
	// Stuck is entered automatically when a transitional phase outlives its
	// deadline. StuckFrom records the phase that stalled.
	Stuck Phase = "stuck"
	// Held is an explicit fail-closed stop (unknown outcome, foreign evidence,
	// or operator decision). Only an explicit Release leaves it.
	Held Phase = "held"
)

// Valid reports whether phase is known.
func (phase Phase) Valid() bool {
	switch phase {
	case Pending, Creating, Available, Attaching, Attached, Formatting, Mounted,
		Resizing, Detaching, Detached, Deleting, Deleted, Stuck, Held:
		return true
	default:
		return false
	}
}

// Transitional reports whether phase waits on an external effect and is
// therefore bounded by a deadline.
func (phase Phase) Transitional() bool {
	switch phase {
	case Creating, Attaching, Formatting, Resizing, Detaching, Deleting:
		return true
	default:
		return false
	}
}

// Event is an observed fact or a requested effect.
type Event string

const (
	EventCreateRequested Event = "create-requested"
	EventCreated         Event = "created"
	EventAttachRequested Event = "attach-requested"
	EventAttached        Event = "attached"
	EventFormatStarted   Event = "format-started"
	EventMounted         Event = "mounted"
	EventResizeRequested Event = "resize-requested"
	EventResized         Event = "resized"
	EventDetachRequested Event = "detach-requested"
	EventDetached        Event = "detached"
	EventDeleteRequested Event = "delete-requested"
	EventDeleted         Event = "deleted"
	// EventHold moves any non-terminal phase to Held with a reason.
	EventHold Event = "hold"
	// EventRelease returns a Held volume to the phase it was held from.
	EventRelease Event = "release"
	// EventRetry returns a Stuck volume to the phase that stalled, restarting
	// its deadline and counting one remediation attempt.
	EventRetry Event = "retry"
)

// State is the durable lifecycle record. Since drives deadlines; callers must
// persist it unchanged while a phase is merely re-observed.
type State struct {
	Phase     Phase     `json:"phase"`
	Since     time.Time `json:"since"`
	StuckFrom Phase     `json:"stuck_from,omitempty"`
	HeldFrom  Phase     `json:"held_from,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	// Attempts counts remediation retries of the current stalled phase.
	Attempts uint32 `json:"attempts,omitzero"`
}

var (
	ErrInvalidTransition = errors.New("invalid retained volume lifecycle transition")
	ErrTerminal          = errors.New("retained volume lifecycle is terminal")
)

// New returns the initial Pending state.
func New(now time.Time) State {
	return State{Phase: Pending, Since: now.UTC()}
}

// Apply returns the state after event at now. It never mutates its input and
// rejects any transition not listed in the transition table.
func Apply(state State, event Event, now time.Time, reason string) (State, error) {
	if !state.Phase.Valid() {
		return state, fmt.Errorf("%w: unknown phase %q", ErrInvalidTransition, state.Phase)
	}
	now = now.UTC()
	if state.Phase == Deleted {
		return state, ErrTerminal
	}
	switch event {
	case EventHold:
		if state.Phase == Held {
			return state, nil
		}
		from := state.Phase
		if from == Stuck {
			from = state.StuckFrom
		}
		return State{Phase: Held, Since: now, HeldFrom: from, Reason: reason, Attempts: state.Attempts}, nil
	case EventRelease:
		if state.Phase != Held || !state.HeldFrom.Valid() || state.HeldFrom == Held || state.HeldFrom == Stuck {
			return state, fmt.Errorf("%w: release requires a held volume with a recorded phase", ErrInvalidTransition)
		}
		// Attempts survive the hold: a release must not reset the bound that
		// escalates repeated same-host attach stalls to host replacement.
		return State{Phase: state.HeldFrom, Since: now, Attempts: state.Attempts}, nil
	case EventRetry:
		if state.Phase != Stuck || !state.StuckFrom.Transitional() {
			return state, fmt.Errorf("%w: retry requires a stuck transitional phase", ErrInvalidTransition)
		}
		return State{Phase: state.StuckFrom, Since: now, Attempts: state.Attempts + 1}, nil
	}
	from := state.Phase
	if from == Stuck {
		// A late positive observation resolves a stall without a retry.
		from = state.StuckFrom
	}
	next, ok := transitions[edge{from, event}]
	if !ok || state.Phase == Held {
		return state, fmt.Errorf("%w: %s on %s", ErrInvalidTransition, event, state.Phase)
	}
	if next == from {
		// Re-observing or re-requesting the current phase keeps the original
		// deadline; a stuck volume stays stuck until it makes progress or an
		// explicit retry restarts its deadline.
		return state, nil
	}
	return State{Phase: next, Since: now}, nil
}

type edge struct {
	from  Phase
	event Event
}

// transitions is the complete allowed graph outside Hold/Release/Retry.
// Re-requesting the current transitional phase is idempotent.
var transitions = map[edge]Phase{
	{Pending, EventCreateRequested}:   Creating,
	{Creating, EventCreateRequested}:  Creating,
	{Creating, EventCreated}:          Available,
	{Creating, EventDeleteRequested}:  Deleting,
	{Available, EventCreated}:         Available,
	{Available, EventAttachRequested}: Attaching,
	{Available, EventDeleteRequested}: Deleting,
	{Attaching, EventAttachRequested}: Attaching,
	{Attaching, EventAttached}:        Attached,
	{Attaching, EventDetachRequested}: Detaching,
	{Attaching, EventDetached}:        Detached,
	{Attached, EventAttached}:         Attached,
	{Attached, EventFormatStarted}:    Formatting,
	{Attached, EventMounted}:          Mounted,
	{Attached, EventDetachRequested}:  Detaching,
	{Attached, EventDetached}:         Detached,
	{Formatting, EventAttached}:       Formatting,
	{Formatting, EventFormatStarted}:  Formatting,
	{Formatting, EventMounted}:        Mounted,
	{Mounted, EventAttached}:          Mounted,
	{Mounted, EventMounted}:           Mounted,
	{Mounted, EventResizeRequested}:   Resizing,
	{Mounted, EventDetachRequested}:   Detaching,
	{Mounted, EventDetached}:          Detached,
	{Resizing, EventAttached}:         Resizing,
	{Resizing, EventMounted}:          Resizing,
	{Resizing, EventResizeRequested}:  Resizing,
	{Resizing, EventResized}:          Mounted,
	{Detaching, EventDetachRequested}: Detaching,
	{Detaching, EventDetached}:        Detached,
	{Detached, EventDetached}:         Detached,
	{Detached, EventAttachRequested}:  Attaching,
	{Detached, EventDeleteRequested}:  Deleting,
	{Deleting, EventDeleteRequested}:  Deleting,
	{Deleting, EventDeleted}:          Deleted,
}

// FromOCIAttachmentState maps an OCI volume-attachment lifecycle state to the
// event it represents. Unknown states return false and must be held.
func FromOCIAttachmentState(state string) (Event, bool) {
	switch state {
	case "ATTACHING":
		return EventAttachRequested, true
	case "ATTACHED":
		return EventAttached, true
	case "DETACHING":
		return EventDetachRequested, true
	case "DETACHED":
		return EventDetached, true
	default:
		return "", false
	}
}
