package rootoci

import (
	"context"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

func validNodeMaintenanceRequest(request NodeMaintenanceRequest) bool {
	return entityid.Valid(request.OperationID) && validDigest(request.RequestSHA256) && request.RequestRevision > 0
}

func validNodeMaintenanceStep(step NodeMaintenanceStep) bool {
	switch step {
	case NodeMaintenanceReboot, NodeMaintenanceResize, NodeMaintenanceRename, NodeMaintenanceBackup, NodeMaintenanceTerminate:
		return true
	default:
		return false
	}
}

func validNodeMaintenanceWire(request wireRequest) bool {
	if request.Operation == OperationObserveNodeMaintenanceNodes {
		return decodePayload(request.Payload, new(struct{})) == nil
	}
	if request.Operation == OperationAdvanceNodeMaintenance {
		var input NodeMaintenanceAdvanceRequest
		return decodePayload(request.Payload, &input) == nil && validNodeMaintenanceRequest(input.NodeMaintenanceRequest) && validNodeMaintenanceStep(input.Step)
	}
	if request.Operation != OperationPrepareNodeMaintenance && request.Operation != OperationObserveNodeMaintenance {
		return false
	}
	var input NodeMaintenanceRequest
	return decodePayload(request.Payload, &input) == nil && validNodeMaintenanceRequest(input)
}

func dispatchNodeMaintenance(ctx context.Context, backend NodeMaintenance, call Call, request wireRequest) (any, error) {
	if !validNodeMaintenanceWire(request) {
		return nil, ErrInvalid
	}
	if request.Operation == OperationObserveNodeMaintenanceNodes {
		return backend.ObserveNodeMaintenanceNodes(ctx, call)
	}
	if request.Operation == OperationAdvanceNodeMaintenance {
		var input NodeMaintenanceAdvanceRequest
		if err := decodePayload(request.Payload, &input); err != nil {
			return nil, err
		}
		return backend.AdvanceNodeMaintenance(ctx, call, input)
	}
	var input NodeMaintenanceRequest
	if err := decodePayload(request.Payload, &input); err != nil {
		return nil, err
	}
	if request.Operation == OperationPrepareNodeMaintenance {
		return backend.PrepareNodeMaintenance(ctx, call, input)
	}
	return backend.ObserveNodeMaintenance(ctx, call, input)
}
