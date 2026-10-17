package rootoci

import "context"

func (client *Client) ReconcileContainerStatus(ctx context.Context, request ContainerStatusRequest) (ContainerStatusReceipt, error) {
	var result ContainerStatusReceipt
	err := client.invoke(ctx, OperationReconcileContainerStatus, request, &result)
	return result, err
}
