package rootoci

import "context"

func (client *Client) ContainerEvidence(ctx context.Context, request ContainerEvidenceRequest) (ContainerEvidenceChunk, error) {
	var result ContainerEvidenceChunk
	err := client.invoke(ctx, OperationContainerEvidence, request, &result)
	return result, err
}
func (client *Client) ContainerAllocation(ctx context.Context, request ContainerAllocationRequest) (ContainerAllocationObservation, error) {
	var result ContainerAllocationObservation
	err := client.invoke(ctx, OperationContainerAllocation, request, &result)
	return result, err
}
