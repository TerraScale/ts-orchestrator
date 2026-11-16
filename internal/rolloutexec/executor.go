package rolloutexec

import (
	"time"
)

const (
	// DefaultInterval is how often the leader drives the active rollout.
	DefaultInterval = 5 * time.Second
	// DefaultProofFreshness is how recent a unit's proof must be for the
	// unit to count as serving in preflight and peer checks.
	DefaultProofFreshness = 4 * DefaultProofInterval
)

// ProofSource returns a unit's newest verified health proof. Collector is
// the production source.
type ProofSource interface {
	Latest(unit string) (HealthProof, bool)
}
