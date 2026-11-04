package bootstrapstart

import (
	"context"
	"errors"

	"github.com/oracle/oci-go-sdk/v65/core"
)

const (
	founderTestInstanceID = "ocid1.instance.oc1.sa-saopaulo-1.peer"
	founderTestVNICID     = "ocid1.vnic.oc1.sa-saopaulo-1.peer"
	founderTestBootID     = "ocid1.bootvolume.oc1.sa-saopaulo-1.peer"
)

const testOperatorSSHKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl operator@terrascale"

var testLaunchMaterial = LaunchMaterial{Identity: []byte(`{"identity":1}`), Anchor: []byte(`{"anchor":1}`),
	HostEnrollment: []byte(`{"bundle":1}`), OperatorSSHKey: []byte(testOperatorSSHKey),
	ManagedHostImageReceipt: []byte(`{"image":1}`), ManagedHostImageDelegation: []byte(`{"delegation":1}`)}

type lostResponseCompute struct {
	requests []core.LaunchInstanceRequest
}

func (fake *lostResponseCompute) LaunchInstance(_ context.Context, request core.LaunchInstanceRequest) (core.LaunchInstanceResponse, error) {
	fake.requests = append(fake.requests, request)
	if len(fake.requests) == 1 {
		return core.LaunchInstanceResponse{}, errors.New("response lost after OCI accepted request")
	}
	return core.LaunchInstanceResponse{Instance: core.Instance{
		Id: new(founderTestInstanceID), CompartmentId: request.CompartmentId,
		ImageId: new("ocid1.image.oc1.sa-saopaulo-1.image"),
	}}, nil
}
