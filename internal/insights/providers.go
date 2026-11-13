package insights

import (
	"context"
	"time"
)

// The optional providers below are owned by slices that are being built in
// parallel. Each has a small value type with only what a rule needs. A nil
// provider keeps its rules silent; a provider error is reported in
// Evaluation.Unavailable and also keeps them silent.

// RolloutProvider lists rollouts with their deadlines (rollout slice).
type RolloutProvider interface {
	Rollouts(ctx context.Context) ([]Rollout, error)
}

// Rollout is one release rollout as the rollout slice sees it.
type Rollout struct {
	ID      string `json:"id"`
	Release string `json:"release"`
	// Phase is the rollout state machine's phase: pending, preflight,
	// canary, canary-soak, batch, batch-soak, complete, rolling-back,
	// frozen, aborted or rolled-back.
	Phase string `json:"phase"`
	// PhaseStarted is when the current phase began and PhaseDeadline when
	// it should have ended; a zero deadline means none.
	PhaseStarted  time.Time `json:"phase_started"`
	PhaseDeadline time.Time `json:"phase_deadline,omitzero"`
	Done          bool      `json:"done"`
}

// VolumeProvider lists block volumes and their attachment state (storage
// slice).
type VolumeProvider interface {
	Volumes(ctx context.Context) ([]Volume, error)
}

// Volume is one block volume.
type Volume struct {
	ID   string `json:"id"`
	Host string `json:"host,omitempty"`
	// State is attached, available, attaching or detaching.
	State string `json:"state"`
	// Detail optionally names the provider's own finer state, for example
	// the placement stage behind an attached volume.
	Detail string `json:"detail,omitempty"`
	// StateSince is when the volume entered State.
	StateSince time.Time `json:"state_since"`
}
