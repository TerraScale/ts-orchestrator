package app

import (
	"context"
	"fmt"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

func WorkerReleaseJourney(ctx context.Context, state string, node *mesh.Node) error {
	admission, stored, err := swarmruntime.StoredAdmission(state)
	if err != nil || !stored || admission.Role == "manager" {
		return fmt.Errorf("worker admission: %+v, stored %t, %v", admission, stored, err)
	}
	if err := node.ReleaseHealth(ctx); err == nil {
		return fmt.Errorf("the worker unexpectedly has a manager fabric")
	}
	if result := releaseHealth(ctx, state, "ts-dashboard", node, nil); result.Err() != nil {
		return result.Err()
	}
	result := releaseHealth(ctx, state, "ts-dashboard", nil, nil)
	if result.Service != nil || result.Mesh == nil || result.Mesh.Error() != "mesh not started" {
		return fmt.Errorf("worker without a mesh node: %+v", result)
	}
	return nil
}
