package rootoci

import "context"

func (client *Client) ReconcileOrchestratorStatus(ctx context.Context, request OrchestratorStatusRequest) (OrchestratorStatusReceipt, error) {
	var result OrchestratorStatusReceipt
	err := client.invoke(ctx, OperationReconcileOrchestratorStatus, request, &result)
	return result, err
}
func (client *Client) NativeRelease(ctx context.Context, request NativeReleaseRequest) (NativeReleaseObservation, error) {
	var result NativeReleaseObservation
	err := client.invoke(ctx, OperationNativeRelease, request, &result)
	return result, err
}
func (client *Client) ReleaseBinaryChunk(ctx context.Context, request ReleaseBinaryChunkRequest) (ReleaseBinaryChunk, error) {
	var result ReleaseBinaryChunk
	err := client.invoke(ctx, OperationReleaseBinaryChunk, request, &result)
	return result, err
}
func (client *Client) NativeReleaseBinaryChunk(ctx context.Context, request NativeReleaseBinaryChunkRequest) (ReleaseBinaryChunk, error) {
	var result ReleaseBinaryChunk
	err := client.invoke(ctx, OperationNativeReleaseBinaryChunk, request, &result)
	return result, err
}
func (client *Client) ReconcileNativeServiceStatus(ctx context.Context, request NativeServiceStatusRequest) (NativeServiceStatusReceipt, error) {
	var result NativeServiceStatusReceipt
	err := client.invoke(ctx, OperationReconcileNativeServiceStatus, request, &result)
	return result, err
}
