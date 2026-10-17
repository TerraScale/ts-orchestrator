package rootoci

import "context"

func (client *Client) ObserveNodeCapacity(ctx context.Context) (NodeCapacityObservation, error) {
	var result NodeCapacityObservation
	err := client.invoke(ctx, OperationObserveNodeCapacity, struct{}{}, &result)
	return result, err
}

func (client *Client) ObserveNodeProbeRegions(ctx context.Context) (NodeProbeRegionObservation, error) {
	var result NodeProbeRegionObservation
	err := client.invoke(ctx, OperationObserveNodeProbeRegions, struct{}{}, &result)
	return result, err
}
