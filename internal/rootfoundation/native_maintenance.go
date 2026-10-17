package rootfoundation

import (
	"context"

	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

// MaintenanceFoundation only observes the current reconciled foundation;
// it grants no journal write, preparation or restart authority.
func (b *Backend) MaintenanceFoundation(ctx context.Context, call rootoci.Call) (TaskTrafficScope, error) {
	return b.operationFoundation(ctx, call, rootoci.OperationReconcileOrchestratorMaintenance)
}
