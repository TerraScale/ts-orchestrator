package bootstrapstart

import (
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
)

// Deadline is the original recipient observation cap, including source age.
func (proof *ControllerHostRecipient) Deadline() time.Time {
	if proof == nil {
		return time.Time{}
	}
	age := proof.started.Add(bootstrap.ManagedPeerObservationMaxAge)
	if age.Before(proof.validUntil) {
		return age
	}
	return proof.validUntil
}
