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
		CreateKey: "sdk-shape-config", Node: hostNode(config, "sdk-shape-config"), RetryToken: "retry-token-sdk-shape-config",
		FaultDomain: "FAULT-DOMAIN-1", Shape: config.Shape, WholeOCPUs: 2, MemoryInGBs: 12,
		PlacementProfileDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		PlacementGeneration:    9,
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
	imageDetails, ok := details.SourceDetails.(core.InstanceSourceViaImageDetails)
	if !ok || imageDetails.ImageId == nil || *imageDetails.ImageId != config.ImageID ||
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
