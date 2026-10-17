package app

import (
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/region"
)

// mountFoundationObservation uses the existing runtime listener and discovery
// resolver. It never opens a new cloud client or grants provisioning authority.
func mountFoundationObservation(server *observability.Server, foundations region.FoundationResolver) {
	if server == nil {
		return
	}
	server.HandleAuthenticated("GET /v1/regions/{region}/foundation", region.FoundationObservationHandler(foundations))
}
