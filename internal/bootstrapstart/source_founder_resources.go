package bootstrapstart

import (
	"context"
	"errors"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/core"
)

// Geometry comes from authenticated provider reads, never instance tags or IMDS.
func (proof VerifiedSourceFounder) verifyResources(ctx context.Context, observed InstanceObservation) error {
	template := proof.template.Template()
	if template.FounderResources == nil {
		return ErrSourceFounder
	}
	var resource bootstrap.StartupSlotResources
	for _, row := range template.FounderResources.Slots {
		if row.Slot == proof.SeedSlot() {
			resource = row
			break
		}
	}
	vpus, supported := resource.BootVolumeTier.VPUsPerGB()
	if resource.WholeOCPUs == 0 || resource.MemoryInGB == 0 || resource.BootVolumeGB == 0 || !supported {
		return ErrSourceFounder
	}
	compute, err := proof.factory.Compute()
	if err != nil {
		return err
	}
	instanceResponse, err := compute.GetInstance(ociclient.RequestContext(ctx), core.GetInstanceRequest{InstanceId: new(observed.InstanceOCID)})
	if err != nil {
		return err
	}
	instance := instanceResponse.Instance
	if value(instance.Id) != observed.InstanceOCID || value(instance.ImageId) != observed.ImageOCID || value(instance.CompartmentId) != observed.CompartmentOCID ||
		value(instance.AvailabilityDomain) != observed.AvailabilityDomain || value(instance.FaultDomain) != observed.FaultDomain ||
		value(instance.Shape) != observed.Shape || instance.LifecycleState != core.InstanceLifecycleStateRunning || instance.ShapeConfig == nil ||
		instance.ShapeConfig.Ocpus == nil || float64(*instance.ShapeConfig.Ocpus) != float64(resource.WholeOCPUs) ||
		instance.ShapeConfig.MemoryInGBs == nil || float64(*instance.ShapeConfig.MemoryInGBs) != float64(resource.MemoryInGB) {
		return ErrSourceFounder
	}
	imageResponse, err := compute.GetImage(ociclient.RequestContext(ctx), core.GetImageRequest{ImageId: new(template.ImageOCID)})
	if err != nil {
		return err
	}
	if value(imageResponse.Image.Id) != template.ImageOCID || value(imageResponse.Image.CompartmentId) != resource.ImageCompartmentOCID || imageResponse.Image.LifecycleState != core.ImageLifecycleStateAvailable {
		return ErrSourceFounder
	}
	attachments, err := compute.ListBootVolumeAttachments(ociclient.RequestContext(ctx), core.ListBootVolumeAttachmentsRequest{
		AvailabilityDomain: new(observed.AvailabilityDomain), CompartmentId: new(observed.CompartmentOCID), InstanceId: new(observed.InstanceOCID), Limit: new(2)})
	if err != nil {
		return err
	}
	if value(attachments.OpcNextPage) != "" || len(attachments.Items) != 1 {
		return ErrSourceFounder
	}
	attachment := attachments.Items[0]
	bootID := value(attachment.BootVolumeId)
	prefix := "ocid1.bootvolume.oc1." + proof.factory.Region() + "."
	if !strings.HasPrefix(bootID, prefix) || len(bootID) <= len(prefix) || value(attachment.InstanceId) != observed.InstanceOCID ||
		value(attachment.CompartmentId) != observed.CompartmentOCID || value(attachment.AvailabilityDomain) != observed.AvailabilityDomain ||
		attachment.LifecycleState != core.BootVolumeAttachmentLifecycleStateAttached {
		return ErrSourceFounder
	}
	volumes, err := proof.factory.Blockstorage()
	if err != nil {
		return err
	}
	volumeResponse, err := volumes.GetBootVolume(ociclient.RequestContext(ctx), core.GetBootVolumeRequest{BootVolumeId: new(bootID)})
	if err != nil {
		return err
	}
	volume := volumeResponse.BootVolume
	if value(volume.Id) != bootID || value(volume.CompartmentId) != observed.CompartmentOCID || value(volume.AvailabilityDomain) != observed.AvailabilityDomain ||
		value(volume.ImageId) != template.ImageOCID || volume.LifecycleState != core.BootVolumeLifecycleStateAvailable ||
		volume.SizeInGBs == nil || *volume.SizeInGBs != int64(resource.BootVolumeGB) || volume.VpusPerGB == nil || *volume.VpusPerGB != int64(vpus) ||
		volume.IsAutoTuneEnabled != nil && *volume.IsAutoTuneEnabled || len(volume.AutotunePolicies) != 0 ||
		volume.AutoTunedVpusPerGB != nil && *volume.AutoTunedVpusPerGB != int64(vpus) {
		return errors.New("authenticated founder boot volume differs from its signed fixed size and performance tier")
	}
	return nil
}
