package oci

import (
	"context"
	"errors"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/oracle/oci-go-sdk/v65/core"
)

func TestLaunchInstanceMapsSignedProfileIntoOCIRequest(t *testing.T) {
	config, _ := testRegionConfig()
	request := LaunchRequest{
		CreateKey: "sdk-shape-config", PrivateIP: "10.251.0.21", Node: hostNode(config, "sdk-shape-config"), RetryToken: "retry-token-sdk-shape-config",
		FaultDomain: "FAULT-DOMAIN-1", Shape: config.Shape, WholeOCPUs: 2, MemoryInGBs: 12,
		PlacementProfileDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		PlacementGeneration:    9,
		BootVolumeGB:           config.BootVolumeGB, BootVolumeVPUsPerGB: config.BootVolumeVPUsPerGB,
		FreeformTags: map[string]string{
			tagManagedBy: managedByValue, tagPlacementProfileDigest: "caller-value-must-not-win",
		},
	}
	bootRequest := testEnsureRequest(request.CreateKey)
	bootRequest.PlacementProfileDigest = request.PlacementProfileDigest
	bootRequest.PlacementGeneration = request.PlacementGeneration
	descriptor, err := (&fleet{config: config}).hostBootDescriptor(bootRequest)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := descriptor.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	request.ImageID, request.BootDescriptor = config.ImageID, string(wire)
	compute := &fakeLaunchSDKClient{response: core.LaunchInstanceResponse{
		Instance: core.Instance{
			Id: new("ocid1.instance.sdk-shape-config"), Shape: new(config.Shape),
			ShapeConfig: &core.InstanceShapeConfig{Ocpus: new(float32(2)), MemoryInGBs: new(float32(12))},
			ImageId:     new(config.ImageID), Metadata: map[string]string{hostboot.MetadataKey: string(wire)},
		},
		Etag: new("sdk-etag"),
	}}
	cloud, err := launchInstance(t.Context(), compute, config, request)
	if err != nil {
		t.Fatalf("launchInstance: %v", err)
	}
	if compute.calls != 1 || compute.request == nil {
		t.Fatalf("OCI SDK client did not receive a launch request: calls=%d request=%+v", compute.calls, compute.request)
	}
	details := compute.request.LaunchInstanceDetails
	if details.Shape == nil || *details.Shape != request.Shape || details.ShapeConfig == nil ||
		details.ShapeConfig.Ocpus == nil || *details.ShapeConfig.Ocpus != 2 ||
		details.ShapeConfig.MemoryInGBs == nil || *details.ShapeConfig.MemoryInGBs != 12 {
		t.Fatalf("signed shape sizing was omitted or changed: %+v", details)
	}
	if compute.request.OpcRetryToken == nil || *compute.request.OpcRetryToken != request.RetryToken ||
		details.FreeformTags[tagPlacementProfileDigest] != request.PlacementProfileDigest ||
		details.FreeformTags[tagPlacementGeneration] != "9" {
		t.Fatalf("retry/profile identity did not reach OCI: retryToken=%v tags=%v", compute.request.OpcRetryToken, details.FreeformTags)
	}
	if details.FreeformTags[tagManagedBy] != managedByValue {
		t.Fatalf("launch lost the caller's non-profile resource tags: %v", details.FreeformTags)
	}
	if details.DisplayName == nil || *details.DisplayName != config.Owner+"-"+request.Node ||
		details.CreateVnicDetails == nil || details.CreateVnicDetails.AssignPublicIp == nil ||
		*details.CreateVnicDetails.AssignPublicIp || details.CreateVnicDetails.PrivateIp == nil ||
		*details.CreateVnicDetails.PrivateIp != request.PrivateIP ||
		details.CreateVnicDetails.SkipSourceDestCheck == nil || *details.CreateVnicDetails.SkipSourceDestCheck {
		t.Fatalf("launch lost the bounded display name or private-only VNIC: %+v", details)
	}
	imageDetails, ok := details.SourceDetails.(core.InstanceSourceViaImageDetails)
	if !ok || imageDetails.ImageId == nil || *imageDetails.ImageId != config.ImageID ||
		imageDetails.BootVolumeSizeInGBs == nil || *imageDetails.BootVolumeSizeInGBs != 50 ||
		imageDetails.BootVolumeVpusPerGB == nil || *imageDetails.BootVolumeVpusPerGB != 10 ||
		details.Metadata[hostboot.MetadataKey] != string(wire) || details.Metadata["terrascale_host_node"] != request.Node {
		t.Fatalf("public image/descriptor binding did not reach OCI: image=%+v metadata=%v", details.SourceDetails, details.Metadata)
	}
	if cloud.Shape != request.Shape || cloud.Ocpus == nil || *cloud.Ocpus != 2 ||
		cloud.MemoryInGBs == nil || *cloud.MemoryInGBs != 12 || cloud.ETag != "sdk-etag" ||
		cloud.ImageID != config.ImageID || cloud.Metadata[hostboot.MetadataKey] != string(wire) {
		t.Fatalf("SDK response dimensions were not normalized: %+v", cloud)
	}
}

func TestLaunchInstanceRejectsSizingThatCannotRoundTripThroughSDK(t *testing.T) {
	config, _ := testRegionConfig()
	request := LaunchRequest{
		RetryToken: "retry-token-unrepresentable", Shape: config.Shape, WholeOCPUs: 1<<24 + 1, MemoryInGBs: 6,
		PlacementProfileDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		PlacementGeneration:    9,
	}
	compute := &fakeLaunchSDKClient{}
	if _, err := launchInstance(t.Context(), compute, config, request); !errors.Is(err, ErrPlacementProfileMismatch) {
		t.Fatalf("non-exact float32 sizing was not rejected: %v", err)
	}
	if compute.calls != 0 {
		t.Fatalf("invalid sizing reached OCI SDK: calls=%d", compute.calls)
	}
}

func TestManagedInstanceReadbackRequiresExactBootAndPrivateVNIC(t *testing.T) {
	config, _ := testRegionConfig()
	instanceID := "ocid1.instance.managed-readback"
	bootID := "ocid1.bootvolume.managed-readback"
	vnicID := "ocid1.vnic.managed-readback"
	instance := CloudInstance{ID: instanceID, CompartmentID: config.CompartmentID,
		AvailabilityDomain: config.AvailabilityDomain, LifecycleState: "RUNNING"}
	reader := &fakeInstanceReadback{
		boots: core.ListBootVolumeAttachmentsResponse{Items: []core.BootVolumeAttachment{{
			BootVolumeId: new(bootID), InstanceId: new(instanceID),
			LifecycleState: core.BootVolumeAttachmentLifecycleStateAttached,
		}}},
		boot: core.GetBootVolumeResponse{BootVolume: core.BootVolume{
			Id: new(bootID), CompartmentId: new(config.CompartmentID), ImageId: new(config.ImageID),
			SizeInGBs: new(int64(50)), VpusPerGB: new(int64(10)),
		}},
		attachments: core.ListVnicAttachmentsResponse{Items: []core.VnicAttachment{{
			VnicId: new(vnicID), InstanceId: new(instanceID),
			LifecycleState: core.VnicAttachmentLifecycleStateAttached,
		}}},
		vnic: core.GetVnicResponse{Vnic: core.Vnic{
			Id: new(vnicID), SubnetId: new(config.SubnetID), PrivateIp: new("10.251.0.21"),
			NsgIds:         append([]string(nil), config.NetworkSecurityGroupIDs...),
			LifecycleState: core.VnicLifecycleStateAvailable,
		}},
	}
	if ip, err := verifyInstanceStorageAndNetwork(t.Context(), config, instance, reader, reader, reader); err != nil || ip != "10.251.0.21" {
		t.Fatalf("exact boot and private VNIC refused: %v", err)
	}
	reader.boot.VpusPerGB = new(int64(20))
	if _, err := verifyInstanceStorageAndNetwork(t.Context(), config, instance, reader, reader, reader); !errors.Is(err, ErrImageNotQualified) {
		t.Fatalf("costed boot tier drift was accepted: %v", err)
	}
	reader.boot.VpusPerGB = new(int64(10))
	reader.vnic.SkipSourceDestCheck = new(true)
	if _, err := verifyInstanceStorageAndNetwork(t.Context(), config, instance, reader, reader, reader); !errors.Is(err, ErrForeignResource) {
		t.Fatalf("VNIC without source/destination checks was accepted: %v", err)
	}
	reader.vnic.SkipSourceDestCheck = new(false)
	reader.vnic.PublicIp = new("203.0.113.5")
	if _, err := verifyInstanceStorageAndNetwork(t.Context(), config, instance, reader, reader, reader); !errors.Is(err, ErrForeignResource) {
		t.Fatalf("public VNIC was accepted: %v", err)
	}
}

type fakeInstanceReadback struct {
	boots       core.ListBootVolumeAttachmentsResponse
	boot        core.GetBootVolumeResponse
	attachments core.ListVnicAttachmentsResponse
	vnic        core.GetVnicResponse
}

func (reader *fakeInstanceReadback) ListBootVolumeAttachments(context.Context, core.ListBootVolumeAttachmentsRequest) (core.ListBootVolumeAttachmentsResponse, error) {
	return reader.boots, nil
}

func (reader *fakeInstanceReadback) GetBootVolume(context.Context, core.GetBootVolumeRequest) (core.GetBootVolumeResponse, error) {
	return reader.boot, nil
}

func (reader *fakeInstanceReadback) ListVnicAttachments(context.Context, core.ListVnicAttachmentsRequest) (core.ListVnicAttachmentsResponse, error) {
	return reader.attachments, nil
}

func (reader *fakeInstanceReadback) GetVnic(context.Context, core.GetVnicRequest) (core.GetVnicResponse, error) {
	return reader.vnic, nil
}

type fakeLaunchSDKClient struct {
	request  *core.LaunchInstanceRequest
	response core.LaunchInstanceResponse
	err      error
	calls    int
}

func (client *fakeLaunchSDKClient) LaunchInstance(_ context.Context, request core.LaunchInstanceRequest) (core.LaunchInstanceResponse, error) {
	client.calls++
	client.request = new(request)
	return client.response, client.err
}
