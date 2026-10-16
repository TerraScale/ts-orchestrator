// Package lifecycle bounds waits on retained-volume observations. Its
// diagnostics never authorize detach, host replacement, or durable-data effects.
package lifecycle

import "time"

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
	// Held marks a fail-closed observation with an unresolved outcome.
	Held Phase = "held"
)

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

// State describes an observed phase. Since is its recorded start and must
// remain unchanged while the caller re-observes the same phase.
type State struct {
	Phase     Phase     `json:"phase"`
	Since     time.Time `json:"since"`
	StuckFrom Phase     `json:"stuck_from,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	// Attempts counts remediation retries of the current stalled phase.
	Attempts uint32 `json:"attempts,omitzero"`
}
