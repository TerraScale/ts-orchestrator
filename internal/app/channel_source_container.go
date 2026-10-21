package app

import (
	"context"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

func (s *channelSource) readContainerRelease(ctx context.Context, role, architecture string) (rootoci.ContainerReleaseObservation, error) {
	request := rootoci.ContainerReleaseRequest{Role: role, Architecture: architecture}
	if s == nil || s.client == nil || !request.Valid() {
		return rootoci.ContainerReleaseObservation{}, rootoci.ErrUnauthorized
	}
	observation, err := s.client.ContainerRelease(ctx, request)
	if err != nil {
		return rootoci.ContainerReleaseObservation{}, err
	}
	if !observation.Valid(request, time.Now()) {
		return rootoci.ContainerReleaseObservation{}, rootoci.ErrUnauthorized
	}
	return observation, nil
}
