package membership

import (
	"context"
	"errors"
	"slices"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/naming"
)

// OCI instance lifecycle states the reconciler distinguishes. Every other
// state, including STOPPED, means the instance may still return.
const (
	LifecycleRunning     = "RUNNING"
	LifecycleTerminating = "TERMINATING"
	LifecycleTerminated  = "TERMINATED"
)

var timeZero time.Time

// Topology is the signed, fixed controller slot set of one cell.
type Topology struct {
	Cell     string
	Slots    []string
	SeedSlot string
	SelfSlot string
}

func (t Topology) Validate() error {
	if t.Cell == "" || len(t.Slots) < 1 || len(t.Slots)%2 == 0 || len(t.Slots) > 5 ||
		!slices.Contains(t.Slots, t.SeedSlot) || !slices.Contains(t.Slots, t.SelfSlot) {
		return errors.New("membership topology needs an odd slot set containing the seed and local slot")
	}
	seen := make(map[string]struct{}, len(t.Slots))
	for _, slot := range t.Slots {
		if slot == "" {
			return errors.New("membership topology has an empty slot")
		}
		if _, exists := seen[slot]; exists {
			return errors.New("membership topology repeats a slot")
		}
		seen[slot] = struct{}{}
	}
	return nil
}

// ServerName is the embedded NATS server name of slot. It is stable across
// replacement attempts so a relaunched controller keeps its raft identity.
// It must match natscell.ServerName; a test in app pins the two together.
func (t Topology) ServerName(slot string) string { return naming.NATSServer(t.Cell, slot) }

func (t Topology) quorum() int { return len(t.Slots)/2 + 1 }

// Peer is one JetStream metadata replica as reported by the local server.
type Peer struct {
	Name    string
	Online  bool
	Current bool
	Lag     uint64
	// Active is the time since the peer was last heard from.
	Active time.Duration
}

// Meta is the local server's view of the JetStream metadata group. Peers
// excludes the local server, which is always online while it reports.
type Meta struct {
	Leader string
	Size   int
	Peers  []Peer
}

// LedgerSlot is the historically verified current HEAD of one slot.
type LedgerSlot struct {
	Attempt      uint64
	InstanceOCID string
	Complete     bool
	// Retirement is the digest of the retirement that admitted the current
	// attempt; it is empty for attempt one.
	Retirement string
}

// Evidence is one operator-supplied retirement envelope. Its fields are read
// from the unverified payload only to route it; the ledger verifies the root
// signature and the exact prior attempt before any HEAD change.
type Evidence struct {
	Slot              string
	PreviousAttempt   uint64
	PriorInstanceOCID string
	Digest            string
	Wire              []byte
}

// Observation is one complete snapshot. A reconciler that cannot read every
// source never builds one, so Decide never acts on partial evidence.
type Observation struct {
	At        time.Time
	Meta      Meta
	Ledger    map[string]LedgerSlot
	Lifecycle map[string]string
	Evidence  map[string]Evidence
}

// Phase is the per-slot supervision state.
type Phase string

const (
	PhaseHealthy   Phase = "healthy"
	PhaseSuspect   Phase = "suspect"
	PhaseHeld      Phase = "held"
	PhaseReplacing Phase = "replacing"
)

// SlotStatus is the reportable state of one slot.
type SlotStatus struct {
	Slot         string    `json:"slot"`
	Phase        Phase     `json:"phase"`
	Reason       string    `json:"reason,omitempty"`
	Attempt      uint64    `json:"attempt,omitzero"`
	InstanceOCID string    `json:"instance_ocid,omitempty"`
	Lifecycle    string    `json:"lifecycle,omitempty"`
	Online       bool      `json:"online"`
	OfflineSince time.Time `json:"offline_since,omitzero"`
	// PendingAttempt is the successor attempt a replacement is creating.
	PendingAttempt uint64    `json:"pending_attempt,omitzero"`
	LastFailure    time.Time `json:"last_failure,omitzero"`
	LastError      string    `json:"last_error,omitempty"`
}

// State is the reconciler's memory between ticks. It is local to one leader
// term; a new leader restarts every grace period from its own observations.
type State struct {
	Slots map[string]SlotStatus
}

func (s State) clone() State {
	slots := make(map[string]SlotStatus, len(s.Slots))
	for slot, status := range s.Slots {
		slots[slot] = status
	}
	return State{Slots: slots}
}

// Action is one replacement the leader may execute.
type Action struct {
	Slot              string
	PreviousAttempt   uint64
	PriorInstanceOCID string
	Retirement        Evidence
	Reason            string
	// Epoch is the authority term that decided the action. The reconciler
	// sets it when executing; a seed-routed request carries it.
	Epoch uint64 `json:"-"`
	// Fence is the authority guard of the term that decided the action. A
	// Replacer checks it immediately before every durable or OCI mutation.
	// Decide leaves it nil; the reconciler sets it when executing.
	Fence func(context.Context) error `json:"-"`
}
