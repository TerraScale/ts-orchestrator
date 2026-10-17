package app

import (
	"context"

	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

type nodeMaintenanceRequestKey struct{}

func withNodeMaintenanceRequest(ctx context.Context, op nodeOp) context.Context {
	return context.WithValue(ctx, nodeMaintenanceRequestKey{}, rootoci.NodeMaintenanceRequest{
		OperationID: op.ID, RequestSHA256: op.RequestSHA256, RequestRevision: op.RequestRevision,
	})
}

func nodeMaintenanceRequest(ctx context.Context) (rootoci.NodeMaintenanceRequest, error) {
	request, ok := ctx.Value(nodeMaintenanceRequestKey{}).(rootoci.NodeMaintenanceRequest)
	if !ok || request.OperationID == "" || request.RequestSHA256 == "" || request.RequestRevision == 0 {
		return rootoci.NodeMaintenanceRequest{}, rootoci.ErrUnauthorized
	}
	return request, nil
}
