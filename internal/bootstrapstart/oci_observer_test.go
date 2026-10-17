package bootstrapstart

import (
	"context"

	"github.com/oracle/oci-go-sdk/v65/core"
)

type fakeComputeObservation struct {
	instance    core.GetInstanceResponse
	attachments core.ListVnicAttachmentsResponse
}

func (fake *fakeComputeObservation) GetInstance(context.Context, core.GetInstanceRequest) (core.GetInstanceResponse, error) {
	return fake.instance, nil
}

func (fake *fakeComputeObservation) ListVnicAttachments(context.Context, core.ListVnicAttachmentsRequest) (core.ListVnicAttachmentsResponse, error) {
	return fake.attachments, nil
}

type fakeNetworkObservation struct {
	vnics   map[string]core.GetVnicResponse
	subnets map[string]core.GetSubnetResponse
}

func (fake *fakeNetworkObservation) GetSubnet(_ context.Context, request core.GetSubnetRequest) (core.GetSubnetResponse, error) {
	response, ok := fake.subnets[value(request.SubnetId)]
	if !ok {
		return core.GetSubnetResponse{}, ErrInstanceObservation
	}
	return response, nil
}

func (fake *fakeNetworkObservation) GetVnic(_ context.Context, request core.GetVnicRequest) (core.GetVnicResponse, error) {
	response, ok := fake.vnics[value(request.VnicId)]
	if !ok {
		return core.GetVnicResponse{}, ErrInstanceObservation
	}
	return response, nil
}
