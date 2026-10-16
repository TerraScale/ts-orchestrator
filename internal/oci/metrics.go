package oci

import (
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

// Metrics holds the shared OCI API metrics and the fleet's inventory gauges.
var Metrics = ociclient.Metrics

// APIView returns per-operation OCI API usage since process start and the
// latest fleet inventory by lifecycle state.
func APIView() observability.OCIView {
	return observability.OCIView{Operations: ociclient.APIOperations(), Fleet: FleetInventory()}
}
