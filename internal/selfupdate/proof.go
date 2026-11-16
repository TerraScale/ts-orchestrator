package selfupdate

import (
	"time"
)

const (
	ProofDomain = "terrascale.orchestrator.version-proof"
	ProofSchema = "terrascale.orchestrator.version-proof.v1"
	// ProofLifetime bounds a version proof so only a fresh one confirms.
	ProofLifetime = 10 * time.Minute
	proofClock    = time.Minute
)

// VersionProof is signed by the new process once it is healthy. It names
// the activation, the exact binary digest the process executes and its
// process identity; the watchdog and rollout gates verify it.
type VersionProof struct {
	Schema       string    `json:"schema"`
	ActivationID string    `json:"activation_id"`
	Unit         string    `json:"unit"`
	BinarySHA256 string    `json:"binary_sha256"`
	ProcessID    int64     `json:"process_id"`
	ObservedAt   time.Time `json:"observed_at"`
}
