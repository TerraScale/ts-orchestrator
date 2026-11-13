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
	// maxRounds bounds how many derive-act-commit rounds one tick runs, so a
	// tick can move a rollout through several immediate transitions.
	maxRounds = 4
)

// ProofSource returns a unit's newest verified health proof. Collector is
// the production source.
type ProofSource interface {
	Latest(unit string) (HealthProof, bool)
}

func isFresh(proof HealthProof, now time.Time, freshness time.Duration) bool {
	return now.Sub(proof.seen()) <= freshness && now.Sub(proof.ObservedAt) <= freshness+healthClockSkew
}

func short(digest string) string {
	if len(digest) > 12 {
		return digest[:12]
	}
	return digest
}
