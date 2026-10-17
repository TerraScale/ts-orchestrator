package rootoci

import "context"

func (client *Client) RetainedContainerEvidence(ctx context.Context, request RetainedContainerEvidenceRequest) (RetainedContainerEvidenceChunk, error) {
	var result RetainedContainerEvidenceChunk
	err := client.invoke(ctx, OperationRetainedContainerEvidence, request, &result)
	return result, err
}
func (client *Client) RetainedContainerAllocation(ctx context.Context, request RetainedContainerAllocationRequest) (RetainedContainerAllocationObservation, error) {
	var result RetainedContainerAllocationObservation
	err := client.invoke(ctx, OperationRetainedContainerAllocation, request, &result)
	return result, err
}
