package bootstrapstart

import (
	"context"
	"errors"
	"testing"

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

func observerFixture() (*OCIInstanceObserver, string) {
	instanceID := "ocid1.instance.oc1.sa-saopaulo-1.example"
	compartmentID := "ocid1.compartment.oc1..example"
	networkCompartmentID := "ocid1.compartment.oc1..network"
	vnicID := "ocid1.vnic.oc1.sa-saopaulo-1.example"
	subnetID := "ocid1.subnet.oc1.sa-saopaulo-1.example"
	vcnID := "ocid1.vcn.oc1.sa-saopaulo-1.example"
	compute := &fakeComputeObservation{
		instance: core.GetInstanceResponse{Instance: core.Instance{
			Id: new(instanceID), CompartmentId: new(compartmentID),
			ImageId:            new("ocid1.image.oc1.sa-saopaulo-1.example"),
			AvailabilityDomain: new("AD-1"), FaultDomain: new("FAULT-DOMAIN-1"),
			Shape: new("VM.Standard.E5.Flex"), LifecycleState: core.InstanceLifecycleStateRunning,
			FreeformTags: map[string]string{"BootstrapCreateKey": "reviewed-seed-create"},
		}},
		attachments: core.ListVnicAttachmentsResponse{Items: []core.VnicAttachment{{
			InstanceId: new(instanceID), CompartmentId: new(compartmentID), VnicId: new(vnicID),
			SubnetId: new(subnetID), LifecycleState: core.VnicAttachmentLifecycleStateAttached,
		}}},
	}
	network := &fakeNetworkObservation{vnics: map[string]core.GetVnicResponse{
		vnicID: {Vnic: core.Vnic{Id: new(vnicID), CompartmentId: new(networkCompartmentID),
			AvailabilityDomain: new("AD-1"), SubnetId: new(subnetID),
			PrivateIp: new("10.0.0.3"), IsPrimary: new(true),
			NsgIds:         []string{"ocid1.networksecuritygroup.oc1.sa-saopaulo-1.example"},
			LifecycleState: core.VnicLifecycleStateAvailable}},
	}, subnets: map[string]core.GetSubnetResponse{
		subnetID: {Subnet: core.Subnet{Id: new(subnetID), CompartmentId: new(networkCompartmentID),
			VcnId: new(vcnID), LifecycleState: core.SubnetLifecycleStateAvailable}},
	}}
	return &OCIInstanceObserver{compute: compute, network: network}, instanceID
}

func TestOCIObserverRejectsNetworkOwnershipAndRegionMismatch(t *testing.T) {
	tests := []struct {
		name   string
		change func(*fakeNetworkObservation, string)
	}{
		{"wrong VNIC compartment", func(network *fakeNetworkObservation, subnetID string) {
			vnicID := "ocid1.vnic.oc1.sa-saopaulo-1.example"
			response := network.vnics[vnicID]
			response.Vnic.CompartmentId = new("ocid1.compartment.oc1..foreign")
			network.vnics[vnicID] = response
		}},
		{"wrong subnet compartment", func(network *fakeNetworkObservation, subnetID string) {
			response := network.subnets[subnetID]
			response.Subnet.CompartmentId = new("ocid1.compartment.oc1..foreign")
			network.subnets[subnetID] = response
		}},
		{"wrong subnet identity", func(network *fakeNetworkObservation, subnetID string) {
			response := network.subnets[subnetID]
			response.Subnet.Id = new("ocid1.subnet.oc1.sa-saopaulo-1.foreign")
			network.subnets[subnetID] = response
		}},
		{"wrong VCN region", func(network *fakeNetworkObservation, subnetID string) {
			response := network.subnets[subnetID]
			response.Subnet.VcnId = new("ocid1.vcn.oc1.us-ashburn-1.foreign")
			network.subnets[subnetID] = response
		}},
		{"missing VCN", func(network *fakeNetworkObservation, subnetID string) {
			response := network.subnets[subnetID]
			response.Subnet.VcnId = nil
			network.subnets[subnetID] = response
		}},
		{"subnet unavailable", func(network *fakeNetworkObservation, subnetID string) {
			response := network.subnets[subnetID]
			response.Subnet.LifecycleState = core.SubnetLifecycleStateTerminated
			network.subnets[subnetID] = response
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observer, instanceID := observerFixture()
			network := observer.network.(*fakeNetworkObservation)
			test.change(network, "ocid1.subnet.oc1.sa-saopaulo-1.example")
			if _, err := observer.ObserveInstance(t.Context(), instanceID); !errors.Is(err, ErrInstanceObservation) {
				t.Fatalf("invalid network ownership accepted: %v", err)
			}
		})
	}
}

func TestOCIObserverRequiresExactAttachedPrimaryVNIC(t *testing.T) {
	observer, instanceID := observerFixture()
	observed, err := observer.ObserveInstance(t.Context(), instanceID)
	if err != nil || observed.InstanceOCID != instanceID || !observed.PrimaryVNIC ||
		observed.PrimaryPrivateIP != "10.0.0.3" || observed.SubnetOCID == "" ||
		observed.BootstrapCreateKey != "reviewed-seed-create" {
		t.Fatalf("exact primary observation = %+v, %v", observed, err)
	}
	compute := observer.compute.(*fakeComputeObservation)
	compute.attachments.Items[0].InstanceId = new("ocid1.instance.oc1.sa-saopaulo-1.foreign")
	if _, err := observer.ObserveInstance(t.Context(), instanceID); !errors.Is(err, ErrInstanceObservation) {
		t.Fatalf("foreign attachment = %v", err)
	}
}

func TestOCIObserverRejectsMissingPrimaryAndCandidateMismatch(t *testing.T) {
	observer, instanceID := observerFixture()
	network := observer.network.(*fakeNetworkObservation)
	for key, response := range network.vnics {
		response.Vnic.IsPrimary = new(false)
		network.vnics[key] = response
	}
	if _, err := observer.ObserveInstance(t.Context(), instanceID); !errors.Is(err, ErrInstanceObservation) {
		t.Fatalf("missing primary VNIC = %v", err)
	}
	if _, err := observer.ObserveInstance(t.Context(), "ocid1.instance.oc1.sa-saopaulo-1.foreign"); !errors.Is(err, ErrInstanceObservation) {
		t.Fatalf("GetInstance candidate mismatch = %v", err)
	}
}
