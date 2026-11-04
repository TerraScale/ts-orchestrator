package swarmruntime

import (
	"context"

	"github.com/moby/swarmkit/v2/api"

	"google.golang.org/grpc"
)

type metadataServiceClient struct {
	api.ControlClient
	service *api.Service
	updates int
}

func (c *metadataServiceClient) ListServices(context.Context, *api.ListServicesRequest, ...grpc.CallOption) (*api.ListServicesResponse, error) {
	return &api.ListServicesResponse{Services: []*api.Service{c.service.Copy()}}, nil
}

func (c *metadataServiceClient) UpdateService(_ context.Context, request *api.UpdateServiceRequest, _ ...grpc.CallOption) (*api.UpdateServiceResponse, error) {
	c.updates++
	c.service.Spec = *request.Spec.Copy()
	return &api.UpdateServiceResponse{Service: c.service.Copy()}, nil
}
