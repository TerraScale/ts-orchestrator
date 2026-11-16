package bootstrapstart

import (
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
)

// ControllerHostRecipient proves an existing controller's signed slot and live
// OCI identity. The caller must separately fence adoption of its exact spec.
type ControllerHostRecipient struct {
	reader     *CurrentFounderAuthorityReader
	sources    controllerRecipientSources
	issuer     AcceptedIdentity
	spec       []byte
	node       string
	instanceID string
	privateIP  string
	slot       string
	region     string
	started    time.Time
	validUntil time.Time
}

type controllerRecipientSources struct {
	trust    bakedStore
	ledger   *bootstrap.Ledger
	observer *OCIInstanceObserver
}
