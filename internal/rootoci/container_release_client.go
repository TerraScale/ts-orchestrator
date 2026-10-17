package rootoci

import "context"

func (client *Client) ContainerRelease(ctx context.Context, request ContainerReleaseRequest) (ContainerReleaseObservation, error) {
	var result ContainerReleaseObservation
	err := client.invoke(ctx, OperationContainerRelease, request, &result)
	return result, err
}
