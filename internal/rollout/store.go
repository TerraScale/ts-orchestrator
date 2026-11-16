package rollout

import (
	"errors"
	"sync"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/nats-io/nats.go/jetstream"
)

// Bucket is the replicated JetStream KV bucket holding rollout records and
// the per-cell rollout slot.
const Bucket = "TS_ROLLOUTS"

// CellState is the cell-level rollout slot. ActiveRolloutID enforces
// invariant (a): at most one non-terminal rollout per cell. KnownBad and
// Attempts survive every rollout, so a rejected digest never restarts.
type CellState struct {
	SchemaVersion   int            `json:"schema_version"`
	Cell            string         `json:"cell"`
	ActiveRolloutID string         `json:"active_rollout_id,omitempty"`
	KnownBad        []string       `json:"known_bad,omitempty"`
	Attempts        map[string]int `json:"attempts,omitempty"`
}

// Store persists rollout records with CAS on the KV revision. Every write is
// preceded by an authority Guard for the record's epoch (invariant b).
// Records decode tolerantly, so an older controller reads a newer one's
// records during a self-update; schema_version names breaking changes.
type Store struct {
	// Admission and publication share the lifetime of a reservation's generation proof.
	mu     sync.Mutex
	kv     jetstream.KeyValue
	fencer authority.Fencer
	cell   string
}

// ErrAbandonedRollout marks a rollout ID whose cell claim was reclaimed
// before its record existed.
var ErrAbandonedRollout = errors.New("rollout ID was abandoned before its record was created")
