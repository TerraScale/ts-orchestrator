package cli

import (
	"context"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/oracle/oci-go-sdk/v65/common"
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

func seedSizingFixture() (*seedSizingReader, bootstrapstart.InstanceObservation, reviewedSeedPlan) {
	created := time.Date(2026, 9, 27, 12, 5, 0, 0, time.UTC)
	instanceID := "ocid1.instance.oc1.sa-saopaulo-1.seed"
	compartmentID := "ocid1.compartment.oc1..control"
	imageID := "ocid1.image.oc1.sa-saopaulo-1.seed"
	ad := "GRU:SA-SAOPAULO-1-AD-1"
	faultDomain := "FAULT-DOMAIN-1"
	shape := "VM.Standard.E5.Flex"
	bootID := "ocid1.bootvolume.oc1.sa-saopaulo-1.seed"
	observed := bootstrapstart.InstanceObservation{InstanceOCID: instanceID, ETag: "seed-etag",
		CompartmentOCID: compartmentID, ImageOCID: imageID, AvailabilityDomain: ad,
		FaultDomain: faultDomain, Shape: shape, LifecycleState: "RUNNING",
		BootstrapCreateKey: "seed-create-1"}
	plan := reviewedSeedPlan{CompartmentID: compartmentID, ImageID: imageID, AvailabilityDomain: ad,
		FaultDomain: faultDomain, Shape: shape, OCPUs: 1, MemoryGB: 6, BootGB: 50,
		BootVPUsPerGB: 10, AdmissionAdmittedAt: created.Add(-time.Minute),
		AdmissionExpiresAt: created.Add(time.Minute)}
	compute := &seedSizingComputeFixture{instance: core.GetInstanceResponse{Etag: new(observed.ETag),
		Instance: core.Instance{Id: new(instanceID), CompartmentId: new(compartmentID),
			ImageId: new(imageID), AvailabilityDomain: new(ad), FaultDomain: new(faultDomain),
			Shape: new(shape), LifecycleState: core.InstanceLifecycleStateRunning,
			FreeformTags: map[string]string{"BootstrapCreateKey": observed.BootstrapCreateKey},
			ShapeConfig: &core.InstanceShapeConfig{Ocpus: new(float32(1)),
				MemoryInGBs: new(float32(6))}, TimeCreated: &common.SDKTime{Time: created}}},
		attachments: core.ListBootVolumeAttachmentsResponse{Items: []core.BootVolumeAttachment{{
			BootVolumeId: new(bootID), InstanceId: new(instanceID), CompartmentId: new(compartmentID),
			AvailabilityDomain: new(ad), LifecycleState: core.BootVolumeAttachmentLifecycleStateAttached,
		}}}}
	volume := &seedSizingVolumeFixture{expectedID: bootID,
		response: core.GetBootVolumeResponse{BootVolume: core.BootVolume{
			Id: new(bootID), CompartmentId: new(compartmentID), AvailabilityDomain: new(ad),
			ImageId: new(imageID), LifecycleState: core.BootVolumeLifecycleStateAvailable,
			SizeInGBs: new(int64(50)), VpusPerGB: new(int64(10)),
		}}}
	return &seedSizingReader{compute: compute, volume: volume}, observed, plan
}

func TestSeedSizingReadbackChecksAdmissionAndExactBootVolume(t *testing.T) {
	reader, observed, plan := seedSizingFixture()
	if err := reader.verifyReadback(context.Background(), observed, plan); err != nil {
		t.Fatalf("reviewed seed rejected: %v", err)
	}
	compute := reader.compute.(*seedSizingComputeFixture)
	volume := reader.volume.(*seedSizingVolumeFixture)
	for _, test := range []struct {
		name    string
		mutate  func()
		restore func()
	}{
		{"oversized OCPUs", func() { compute.instance.Instance.ShapeConfig.Ocpus = new(float32(2)) },
			func() { compute.instance.Instance.ShapeConfig.Ocpus = new(float32(1)) }},
		{"unknown memory", func() { compute.instance.Instance.ShapeConfig.MemoryInGBs = nil },
			func() { compute.instance.Instance.ShapeConfig.MemoryInGBs = new(float32(6)) }},
		{"created after admission", func() {
			compute.instance.Instance.TimeCreated = &common.SDKTime{Time: plan.AdmissionExpiresAt.Add(time.Second)}
		},
			func() {
				compute.instance.Instance.TimeCreated = &common.SDKTime{Time: plan.AdmissionAdmittedAt.Add(time.Minute)}
			}},
		{"different ETag", func() { compute.instance.Etag = new("later-etag") },
			func() { compute.instance.Etag = new(observed.ETag) }},
		{"wrong boot attachment", func() { compute.attachments.Items[0].InstanceId = new("ocid1.instance.oc1.sa-saopaulo-1.other") },
			func() { compute.attachments.Items[0].InstanceId = new(observed.InstanceOCID) }},
		{"multiple boot attachments", func() { compute.attachments.Items = append(compute.attachments.Items, compute.attachments.Items[0]) },
			func() { compute.attachments.Items = compute.attachments.Items[:1] }},
		{"additional attachment page", func() { compute.attachments.OpcNextPage = new("next") },
			func() { compute.attachments.OpcNextPage = nil }},
		{"mismatched boot volume", func() { volume.response.BootVolume.CompartmentId = new("ocid1.compartment.oc1..other") },
			func() { volume.response.BootVolume.CompartmentId = new(plan.CompartmentID) }},
		{"different boot volume ID", func() { volume.response.BootVolume.Id = new("ocid1.bootvolume.oc1.sa-saopaulo-1.other") },
			func() { volume.response.BootVolume.Id = new(seedString(compute.attachments.Items[0].BootVolumeId)) }},
		{"oversized boot volume", func() { volume.response.BootVolume.SizeInGBs = new(int64(100)) },
			func() { volume.response.BootVolume.SizeInGBs = new(int64(50)) }},
		{"unknown volume performance", func() { volume.response.BootVolume.VpusPerGB = nil },
			func() { volume.response.BootVolume.VpusPerGB = new(int64(10)) }},
		{"autotuned boot volume", func() { volume.response.BootVolume.AutoTunedVpusPerGB = new(int64(20)) },
			func() { volume.response.BootVolume.AutoTunedVpusPerGB = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.mutate()
			defer test.restore()
			if err := reader.verifyReadback(context.Background(), observed, plan); err == nil {
				t.Fatal("changed OCI readback accepted")
			}
		})
	}
}
