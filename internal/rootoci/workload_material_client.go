//go:build linux

package rootoci

import "context"

func (client *Client) MaterializeContainer(ctx context.Context, request MaterializeContainerRequest) (ContainerMaterialReceipt, error) {
	var result ContainerMaterialReceipt
	err := client.invoke(ctx, OperationMaterializeContainer, request, &result)
	return result, err
}

func (client *Client) ObserveContainerGeneration(ctx context.Context, request ObserveContainerGenerationRequest) (ContainerGenerationReceipt, error) {
	var result ContainerGenerationReceipt
	err := client.invoke(ctx, OperationObserveContainerGeneration, request, &result)
	return result, err
}
