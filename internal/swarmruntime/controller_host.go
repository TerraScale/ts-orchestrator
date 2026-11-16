package swarmruntime

import (
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/host"
)

// ControllerHostBinding associates one accepted manager slot with its separately
// enrolled ownhost identity. It cannot authorize WASM or managed DATA execution.
type ControllerHostBinding struct {
	reader   *bootstrapstart.CurrentFounderAuthorityReader
	agent    *host.Agent
	accepted bootstrapstart.AcceptedIdentity
	query    WorkerRegistrationQuery
	identity bootstrapstart.RuntimeIdentity
	hostID   string
}
