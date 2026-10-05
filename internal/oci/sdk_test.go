package oci

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

type terminalSDKRecorder struct {
	requests []*http.Request
}

func (recorder *terminalSDKRecorder) Do(request *http.Request) (*http.Response, error) {
	recorder.requests = append(recorder.requests, request)
	return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header),
		Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
}

func TestTerminalSDKDeletesUseExactIfMatchAndPreserveBoot(t *testing.T) {
	config, _ := testRegionConfig()
	recorder := &terminalSDKRecorder{}
	base := common.BaseClient{Host: "https://sdk.test.invalid", BasePath: "20160918",
		UserAgent: "oci-terminal-test", Signer: observeSDKSigner{}, HTTPClient: recorder}
	provider := &sdkProvider{config: config, compute: core.ComputeClient{BaseClient: base},
		storage: core.BlockstorageClient{BaseClient: base}}
	if err := provider.TerminateTerminalInstance(t.Context(), "ocid1.instance.exact", "instance-etag"); err != nil {
		t.Fatal(err)
	}
	if err := provider.DeleteBootVolume(t.Context(), "ocid1.bootvolume.exact", "boot-etag"); err != nil {
		t.Fatal(err)
	}
	if err := provider.DeleteVolume(t.Context(), "ocid1.volume.exact", "data-etag"); err != nil {
		t.Fatal(err)
	}
	if len(recorder.requests) != 3 || recorder.requests[0].Header.Get("If-Match") != "instance-etag" ||
		recorder.requests[1].Header.Get("If-Match") != "boot-etag" ||
		recorder.requests[2].Header.Get("If-Match") != "data-etag" ||
		recorder.requests[0].URL.Query().Get("preserveBootVolume") != "true" {
		t.Fatalf("terminal SDK lost conditional ETags or boot preservation: %+v", recorder.requests)
	}
}

func TestLaunchInstanceMapsSignedProfileIntoOCIRequest(t *testing.T) {
	config, _ := testRegionConfig()
	request := LaunchRequest{
		DisplayName: "gru-1-db-1", CreateKey: "sdk-shape-config", PrivateIP: "10.251.0.21", Node: hostNode(config, "sdk-shape-config"), RetryToken: "retry-token-sdk-shape-config",
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
	enrollment := `{"schema_version":1}`
	cloud, err := launchInstance(t.Context(), compute, config, request,
		map[string]string{hostboot.EnrollmentMetadataKey: enrollment})
	if err != nil {
		t.Fatalf("launchInstance: %v", err)
	}
	if got := compute.request.LaunchInstanceDetails.Metadata; got[hostboot.EnrollmentMetadataKey] != enrollment ||
		got[hostboot.MetadataKey] != string(wire) || got["terrascale_host_node"] != request.Node {
		t.Fatalf("host launch metadata lost its enrollment bundle or boot binding: %v", got)
	}
	if _, err := launchInstance(t.Context(), compute, config, request,
		map[string]string{hostboot.MetadataKey: "{}"}); !errors.Is(err, ErrHostBootBindingMismatch) {
		t.Fatalf("launch material replaced the fleet-bound boot descriptor: %v", err)
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
	if details.DisplayName == nil || *details.DisplayName != request.DisplayName ||
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
	if _, err := launchInstance(t.Context(), compute, config, request, nil); !errors.Is(err, ErrPlacementProfileMismatch) {
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
	for _, state := range []core.BootVolumeAttachmentLifecycleStateEnum{
		core.BootVolumeAttachmentLifecycleStateAttaching, core.BootVolumeAttachmentLifecycleStateDetaching,
	} {
		reader.boots.Items[0].LifecycleState = state
		_, err := verifyInstanceStorageAndNetwork(t.Context(), config, instance, reader, reader, reader)
		if !errors.Is(err, ErrOutcomeUnknown) || errors.Is(err, ErrForeignResource) {
			t.Fatalf("transient boot attachment %s classified as foreign: %v", state, err)
		}
		reader.boots.OpcNextPage = new("extra")
		if _, err := verifyInstanceStorageAndNetwork(t.Context(), config, instance, reader, reader, reader); !errors.Is(err, ErrForeignResource) {
			t.Fatalf("paginated transient boot attachment was not foreign: %v", err)
		}
		reader.boots.OpcNextPage = nil
	}
	reader.boots.Items[0].LifecycleState = core.BootVolumeAttachmentLifecycleStateAttached
	for _, state := range []core.VnicAttachmentLifecycleStateEnum{
		core.VnicAttachmentLifecycleStateAttaching, core.VnicAttachmentLifecycleStateDetaching,
	} {
		reader.attachments.Items[0].LifecycleState = state
		_, err := verifyInstanceStorageAndNetwork(t.Context(), config, instance, reader, reader, reader)
		if !errors.Is(err, ErrOutcomeUnknown) || errors.Is(err, ErrForeignResource) {
			t.Fatalf("transient VNIC attachment %s classified as foreign: %v", state, err)
		}
		reader.attachments.OpcNextPage = new("extra")
		if _, err := verifyInstanceStorageAndNetwork(t.Context(), config, instance, reader, reader, reader); !errors.Is(err, ErrForeignResource) {
			t.Fatalf("paginated transient VNIC attachment was not foreign: %v", err)
		}
		reader.attachments.OpcNextPage = nil
	}
	reader.attachments.Items[0].LifecycleState = core.VnicAttachmentLifecycleStateAttached
	boots := reader.boots.Items
	reader.boots.Items = nil
	if _, err := verifyInstanceStorageAndNetwork(t.Context(), config, instance, reader, reader, reader); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("not-yet-visible boot attachment was not retryable: %v", err)
	}
	reader.boots.Items = boots
	vnics := reader.attachments.Items
	reader.attachments.Items = nil
	if _, err := verifyInstanceStorageAndNetwork(t.Context(), config, instance, reader, reader, reader); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("not-yet-visible VNIC attachment was not retryable: %v", err)
	}
	reader.attachments.Items = vnics
	for _, test := range []struct {
		name    string
		mutate  func()
		restore func()
	}{
		{"image", func() { reader.boot.ImageId = new("ocid1.image.other") },
			func() { reader.boot.ImageId = new(config.ImageID) }},
		{"size", func() { reader.boot.SizeInGBs = new(int64(100)) },
			func() { reader.boot.SizeInGBs = new(int64(50)) }},
		{"tier", func() { reader.boot.VpusPerGB = new(int64(20)) },
			func() { reader.boot.VpusPerGB = new(int64(10)) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.mutate()
			defer test.restore()
			_, err := verifyInstanceStorageAndNetwork(t.Context(), config, instance, reader, reader, reader)
			if !errors.Is(err, ErrImageNotQualified) || !errors.Is(err, ErrForeignResource) {
				t.Fatalf("instance boot drift did not carry both classifications: %v", err)
			}
		})
	}
	bootGets := reader.bootGets
	reader.boots.Items[0].BootVolumeId = nil
	if _, err := verifyInstanceStorageAndNetwork(t.Context(), config, instance, reader, reader, reader); !errors.Is(err, ErrForeignResource) || reader.bootGets != bootGets {
		t.Fatalf("missing boot ID reached GetBootVolume or was not foreign: err=%v calls=%d", err, reader.bootGets)
	}
	reader.boots.Items[0].BootVolumeId = new(bootID)
	vnicGets := reader.vnicGets
	reader.attachments.Items[0].VnicId = nil
	if _, err := verifyInstanceStorageAndNetwork(t.Context(), config, instance, reader, reader, reader); !errors.Is(err, ErrForeignResource) || reader.vnicGets != vnicGets {
		t.Fatalf("missing VNIC ID reached GetVnic or was not foreign: err=%v calls=%d", err, reader.vnicGets)
	}
	reader.attachments.Items[0].VnicId = new(vnicID)
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
	bootGets    int
	vnicGets    int
}

func (reader *fakeInstanceReadback) ListBootVolumeAttachments(context.Context, core.ListBootVolumeAttachmentsRequest) (core.ListBootVolumeAttachmentsResponse, error) {
	return reader.boots, nil
}

func (reader *fakeInstanceReadback) GetBootVolume(context.Context, core.GetBootVolumeRequest) (core.GetBootVolumeResponse, error) {
	reader.bootGets++
	return reader.boot, nil
}

func (reader *fakeInstanceReadback) ListVnicAttachments(context.Context, core.ListVnicAttachmentsRequest) (core.ListVnicAttachmentsResponse, error) {
	return reader.attachments, nil
}

func (reader *fakeInstanceReadback) GetVnic(context.Context, core.GetVnicRequest) (core.GetVnicResponse, error) {
	reader.vnicGets++
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

// A controller host is the running instance of its name whose single
// primary VNIC is available and private; its address comes from that VNIC.
func TestControllerHostObservationRequiresTheNamedRunningPrivateInstance(t *testing.T) {
	instanceID, vnicID := "ocid1.instance.controller", "ocid1.vnic.controller"
	instance := CloudInstance{ID: instanceID, DisplayName: "gru-1-ctl-1", CompartmentID: "ocid1.compartment.control",
		LifecycleState: "RUNNING"}
	reader := &fakeInstanceReadback{
		attachments: core.ListVnicAttachmentsResponse{Items: []core.VnicAttachment{{
			VnicId: new(vnicID), InstanceId: new(instanceID), LifecycleState: core.VnicAttachmentLifecycleStateAttached,
		}}},
		vnic: core.GetVnicResponse{Vnic: core.Vnic{Id: new(vnicID), PrivateIp: new("10.251.0.11"),
			LifecycleState: core.VnicLifecycleStateAvailable}},
	}
	observed, err := observeControllerHost(t.Context(), instance, instanceID, "gru-1-ctl-1", reader, reader)
	if err != nil || observed.PrivateIP != "10.251.0.11" {
		t.Fatalf("controller refused: %+v %v", observed, err)
	}
	stopped := instance
	stopped.LifecycleState = "STOPPED"
	for name, check := range map[string]func() error{
		"another name": func() error {
			_, err := observeControllerHost(t.Context(), instance, instanceID, "gru-1-ctl-2", reader, reader)
			return err
		},
		"another instance": func() error {
			_, err := observeControllerHost(t.Context(), instance, "ocid1.instance.other", "gru-1-ctl-1", reader, reader)
			return err
		},
		"stopped": func() error {
			_, err := observeControllerHost(t.Context(), stopped, instanceID, "gru-1-ctl-1", reader, reader)
			return err
		},
		"public VNIC": func() error {
			reader.vnic.PublicIp = new("203.0.113.5")
			defer func() { reader.vnic.PublicIp = nil }()
			_, err := observeControllerHost(t.Context(), instance, instanceID, "gru-1-ctl-1", reader, reader)
			return err
		},
		"second VNIC": func() error {
			reader.attachments.Items = append(reader.attachments.Items, reader.attachments.Items[0])
			defer func() { reader.attachments.Items = reader.attachments.Items[:1] }()
			_, err := observeControllerHost(t.Context(), instance, instanceID, "gru-1-ctl-1", reader, reader)
			return err
		},
	} {
		if err := check(); !errors.Is(err, ErrForeignResource) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
