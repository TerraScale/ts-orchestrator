package rolloutexec

import (
	"encoding/json"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
)

// UnitStatus is one unit's state in a status publication.
type UnitStatus struct {
	ID    string            `json:"id"`
	Group string            `json:"group"`
	Seed  bool              `json:"seed,omitzero"`
	Wave  int               `json:"wave"`
	State rollout.UnitState `json:"state"`
	// Digest and ProofAt are the unit's newest verified health proof.
	Digest  string    `json:"digest,omitempty"`
	ProofAt time.Time `json:"proof_at,omitzero"`
}

// Status is the leader's view of the active rollout. It is read-only
// telemetry for operators and the dashboard; nothing reads it back to
// decide anything.
type Status struct {
	Schema        string        `json:"schema"`
	Cell          string        `json:"cell"`
	Epoch         uint64        `json:"epoch"`
	Active        bool          `json:"active"`
	RolloutID     string        `json:"rollout_id,omitempty"`
	Kind          rollout.Kind  `json:"kind,omitempty"`
	Phase         rollout.Phase `json:"phase,omitempty"`
	Wave          int           `json:"wave,omitzero"`
	Waves         int           `json:"waves,omitzero"`
	FromDigest    string        `json:"from_digest,omitempty"`
	ToDigest      string        `json:"to_digest,omitempty"`
	Reason        string        `json:"reason,omitempty"`
	PhaseDeadline time.Time     `json:"phase_deadline,omitzero"`
	// Holds names the steps a gate is holding, by unit ("" is preflight).
	Holds map[string]string `json:"holds,omitempty"`
	// Waiting says why no rollout runs while the slot is free: the program
	// cannot start (no fresh proofs, units on different releases) or a
	// program rollout ended without completing.
	Waiting   string       `json:"waiting,omitempty"`
	Units     []UnitStatus `json:"units,omitempty"`
	UpdatedAt time.Time    `json:"updated_at"`
}

// NATSStatus publishes status on protocol.RolloutStatusSubject.
type NATSStatus struct {
	Conn *nats.Conn
	Cell string
}

// PublishStatus implements StatusSink. Publication is best effort.
func (sink NATSStatus) PublishStatus(status Status) {
	if sink.Conn == nil {
		return
	}
	if data, err := json.Marshal(status); err == nil {
		_ = sink.Conn.Publish(protocol.RolloutStatusSubject(sink.Cell), data)
	}
}
