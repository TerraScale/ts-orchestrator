package rootoci

import "context"

const (
	OperationObserveNodeMaintenanceNodes Operation = "observe_node_maintenance_nodes"
	OperationPrepareNodeMaintenance      Operation = "prepare_node_maintenance"
	OperationObserveNodeMaintenance      Operation = "observe_node_maintenance"
	OperationAdvanceNodeMaintenance      Operation = "advance_node_maintenance"
)

func (client *Client) ObserveNodeMaintenanceNodes(ctx context.Context) ([]NodeMaintenanceNode, error) {
	var response []NodeMaintenanceNode
	err := client.invoke(ctx, OperationObserveNodeMaintenanceNodes, struct{}{}, &response)
	return response, err
}

func (client *Client) PrepareNodeMaintenance(ctx context.Context, request NodeMaintenanceRequest) (NodeMaintenanceView, error) {
	var response NodeMaintenanceView
	err := client.invoke(ctx, OperationPrepareNodeMaintenance, request, &response)
	return response, err
}

func (client *Client) ObserveNodeMaintenance(ctx context.Context, request NodeMaintenanceRequest) (NodeMaintenanceView, error) {
	var response NodeMaintenanceView
	err := client.invoke(ctx, OperationObserveNodeMaintenance, request, &response)
	return response, err
}

func (client *Client) AdvanceNodeMaintenance(ctx context.Context, request NodeMaintenanceAdvanceRequest) (NodeMaintenanceView, error) {
	var response NodeMaintenanceView
	err := client.invoke(ctx, OperationAdvanceNodeMaintenance, request, &response)
	return response, err
}
