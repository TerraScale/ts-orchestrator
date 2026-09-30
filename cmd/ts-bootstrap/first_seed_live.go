package main

import (
	"context"
	"fmt"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

type seedComputeSizingAPI interface {
	GetInstance(context.Context, core.GetInstanceRequest) (core.GetInstanceResponse, error)
	ListBootVolumeAttachments(context.Context, core.ListBootVolumeAttachmentsRequest) (core.ListBootVolumeAttachmentsResponse, error)
}

type seedBootVolumeAPI interface {
	GetBootVolume(context.Context, core.GetBootVolumeRequest) (core.GetBootVolumeResponse, error)
}

type seedSizingReader struct {
	compute seedComputeSizingAPI
	volume  seedBootVolumeAPI
}

func seedString(pointer *string) string {
	if pointer == nil {
		return ""
	}
	return *pointer
}

func newSeedSizingReader(region string, provider common.ConfigurationProvider) (*seedSizingReader, error) {
	if provider == nil {
		return nil, ErrSeedCLI
	}
	providerRegion, err := provider.Region()
	if err != nil || providerRegion != region {
		return nil, fmt.Errorf("%w: OCI sizing reader region differs from signed anchor", ErrSeedCLI)
	}
	compute, err := core.NewComputeClientWithConfigurationProvider(provider)
	if err != nil {
		return nil, fmt.Errorf("create seed Compute reader: %w", err)
	}
	volume, err := core.NewBlockstorageClientWithConfigurationProvider(provider)
	if err != nil {
		return nil, fmt.Errorf("create seed Block Storage reader: %w", err)
	}
	compute.SetRegion(region)
	volume.SetRegion(region)
	compute.HTTPClient, err = bootstrap.NewInstancePrincipalSDKHTTPClient()
	if err != nil {
		return nil, err
	}
	volume.HTTPClient, err = bootstrap.NewInstancePrincipalSDKHTTPClient()
	if err != nil {
		return nil, err
	}
	return &seedSizingReader{compute: &compute, volume: &volume}, nil
}

// verifyReadback checks the billable dimensions and creation window omitted
// from the signed observation. It is called only for a fresh OCI observation
// or before a new result write, never for an already committed reconciliation.
func (reader *seedSizingReader) verifyReadback(ctx context.Context, observed bootstrapstart.InstanceObservation,
	plan reviewedSeedPlan,
) error {
	if reader == nil || reader.compute == nil || reader.volume == nil || observed.InstanceOCID == "" ||
		observed.ETag == "" {
		return ErrSeedCLI
	}
	response, err := reader.compute.GetInstance(ctx, core.GetInstanceRequest{InstanceId: new(observed.InstanceOCID)})
	if err != nil {
		return fmt.Errorf("GetInstance exact seed sizing: %w", err)
	}
	instance := response.Instance
	if seedString(instance.Id) != observed.InstanceOCID || seedString(response.Etag) != observed.ETag ||
		seedString(instance.CompartmentId) != observed.CompartmentOCID ||
		seedString(instance.CompartmentId) != plan.CompartmentID ||
		seedString(instance.ImageId) != observed.ImageOCID || seedString(instance.ImageId) != plan.ImageID ||
		seedString(instance.AvailabilityDomain) != observed.AvailabilityDomain ||
		seedString(instance.AvailabilityDomain) != plan.AvailabilityDomain ||
		seedString(instance.FaultDomain) != observed.FaultDomain ||
		seedString(instance.FaultDomain) != plan.FaultDomain ||
		seedString(instance.Shape) != observed.Shape || seedString(instance.Shape) != plan.Shape ||
		string(instance.LifecycleState) != observed.LifecycleState ||
		instance.FreeformTags["BootstrapCreateKey"] != observed.BootstrapCreateKey ||
		instance.ShapeConfig == nil || instance.ShapeConfig.Ocpus == nil ||
		*instance.ShapeConfig.Ocpus != float32(plan.OCPUs) ||
		instance.ShapeConfig.MemoryInGBs == nil ||
		*instance.ShapeConfig.MemoryInGBs != float32(plan.MemoryGB) ||
		instance.TimeCreated == nil || instance.TimeCreated.Time.IsZero() ||
		instance.TimeCreated.Time.Before(plan.AdmissionAdmittedAt) ||
		instance.TimeCreated.Time.After(plan.AdmissionExpiresAt) {
		return fmt.Errorf("%w: seed instance sizing or creation time differs from reviewed admission", ErrSeedCLI)
	}
	attachments, err := reader.compute.ListBootVolumeAttachments(ctx, core.ListBootVolumeAttachmentsRequest{
		AvailabilityDomain: new(plan.AvailabilityDomain), CompartmentId: new(plan.CompartmentID),
		InstanceId: new(observed.InstanceOCID),
	})
	if err != nil {
		return fmt.Errorf("ListBootVolumeAttachments exact seed instance: %w", err)
	}
	if seedString(attachments.OpcNextPage) != "" || len(attachments.Items) != 1 {
		return fmt.Errorf("%w: expected exactly one seed boot volume attachment", ErrSeedCLI)
	}
	attachment := attachments.Items[0]
	bootID := seedString(attachment.BootVolumeId)
	if seedString(attachment.InstanceId) != observed.InstanceOCID ||
		seedString(attachment.CompartmentId) != plan.CompartmentID ||
		seedString(attachment.AvailabilityDomain) != plan.AvailabilityDomain ||
		attachment.LifecycleState != core.BootVolumeAttachmentLifecycleStateAttached ||
		!strings.HasPrefix(bootID, "ocid1.bootvolume.") {
		return fmt.Errorf("%w: seed boot volume attachment differs from exact instance", ErrSeedCLI)
	}
	volumeResponse, err := reader.volume.GetBootVolume(ctx, core.GetBootVolumeRequest{BootVolumeId: new(bootID)})
	if err != nil {
		return fmt.Errorf("GetBootVolume exact seed attachment: %w", err)
	}
	volume := volumeResponse.BootVolume
	if seedString(volume.Id) != bootID || seedString(volume.CompartmentId) != plan.CompartmentID ||
		seedString(volume.AvailabilityDomain) != plan.AvailabilityDomain ||
		seedString(volume.ImageId) != plan.ImageID ||
		volume.LifecycleState != core.BootVolumeLifecycleStateAvailable ||
		volume.SizeInGBs == nil || *volume.SizeInGBs != int64(plan.BootGB) ||
		volume.VpusPerGB == nil || *volume.VpusPerGB != int64(plan.BootVPUsPerGB) ||
		volume.IsAutoTuneEnabled != nil && *volume.IsAutoTuneEnabled ||
		volume.AutoTunedVpusPerGB != nil && *volume.AutoTunedVpusPerGB != int64(plan.BootVPUsPerGB) ||
		len(volume.AutotunePolicies) != 0 {
		return fmt.Errorf("%w: seed boot volume dimensions differ from reviewed admission", ErrSeedCLI)
	}
	return nil
}
