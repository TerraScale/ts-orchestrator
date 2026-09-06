package bootstrap

import (
	"context"
	"errors"
	"time"
)

// ControlRuntime actuates the admitted hosts and verifies their real control
// stores. OCI tags record these results; they cannot produce runtime evidence.
type ControlRuntime interface {
	Execute(context.Context, ControlActionRequest) (ControlRuntimeEvidence, error)
	Observe(context.Context) (map[string]bool, error)
}

// ControlRuntimeEvidence hashes the actual signed membership records,
// JetStream state and fresh host facts collected after an action.
type ControlRuntimeEvidence struct {
	IdentityDigest string
	StorageDigest  string
	HealthDigest   string
	ObservedAt     time.Time
	// Candidate is present only for VerifyCandidate and records the
	// candidate-specific gates proved by the runtime observation.
	Candidate *CandidateRuntimeEvidence
}

type CandidateRuntimeEvidence struct {
	CaughtUp      bool
	IdentityReady bool
	StorageReady  bool
	HealthReady   bool
}

var ErrControlRuntimeUnavailable = errors.New("bootstrap: verified control runtime is unavailable")

func (e ControlRuntimeEvidence) validate(now time.Time) error {
	if !canonicalControlDigest(e.IdentityDigest) || !canonicalControlDigest(e.StorageDigest) || !canonicalControlDigest(e.HealthDigest) || e.ObservedAt.IsZero() || e.ObservedAt.After(now.Add(time.Second)) || now.Sub(e.ObservedAt) > 30*time.Second {
		return ErrControlRuntimeUnavailable
	}
	return nil
}
