package cli

import (
	"context"

	"github.com/oracle/oci-go-sdk/v65/core"
)

type seedSizingComputeFixture struct {
	instance    core.GetInstanceResponse
	attachments core.ListBootVolumeAttachmentsResponse
}

func (fixture *seedSizingComputeFixture) GetInstance(_ context.Context, request core.GetInstanceRequest) (core.GetInstanceResponse, error) {
	if seedString(request.InstanceId) != seedString(fixture.instance.Instance.Id) {
		return core.GetInstanceResponse{}, ErrSeedCLI
	}
	return fixture.instance, nil
}

func (fixture *seedSizingComputeFixture) ListBootVolumeAttachments(_ context.Context, request core.ListBootVolumeAttachmentsRequest) (core.ListBootVolumeAttachmentsResponse, error) {
	if seedString(request.InstanceId) != seedString(fixture.instance.Instance.Id) ||
		seedString(request.CompartmentId) != seedString(fixture.instance.Instance.CompartmentId) ||
		seedString(request.AvailabilityDomain) != seedString(fixture.instance.Instance.AvailabilityDomain) {
		return core.ListBootVolumeAttachmentsResponse{}, ErrSeedCLI
	}
	return fixture.attachments, nil
}

type seedSizingVolumeFixture struct {
	expectedID string
	response   core.GetBootVolumeResponse
}

func (fixture *seedSizingVolumeFixture) GetBootVolume(_ context.Context, request core.GetBootVolumeRequest) (core.GetBootVolumeResponse, error) {
	if seedString(request.BootVolumeId) != fixture.expectedID {
		return core.GetBootVolumeResponse{}, ErrSeedCLI
	}
	return fixture.response, nil
}
