// Package lifecycle is the pure retained-volume state machine. It performs no
// I/O: callers feed observed events and the current time, persist the returned
// State with their own CAS, and act on the returned Remediation. Every phase
// that waits on OCI or the host has a deadline, so a volume can never wait in
// ATTACHING (or any other transitional phase) forever.
package lifecycle

import (
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

const ()

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

var ()
