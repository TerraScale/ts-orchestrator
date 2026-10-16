package imagequalification

import (
	"context"
	"errors"

	"github.com/oracle/oci-go-sdk/v65/core"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

// validateHostBounds uses independent read-only SDK clients so guarding actual
// dispatches cannot recursively call the guarded mutation clients.
func (c *cloud) validateHostBounds(ctx context.Context, j journal) error {
	for _, spec := range c.prepared.approval.Hosts {
		if j.Hosts[spec.Name] == "" || j.Terminated[spec.Name] {
			continue
		}
		instance, err := c.ownedInstance(ctx, j, spec)
		if err != nil {
			return err
		}
		if instance.LifecycleState == core.InstanceLifecycleStateTerminated || instance.LifecycleState == core.InstanceLifecycleStateTerminating {
			continue
		}
		response, err := c.compute.ListBootVolumeAttachments(ociclient.RequestContext(ctx), core.ListBootVolumeAttachmentsRequest{AvailabilityDomain: new(spec.AvailabilityDomain), CompartmentId: new(c.prepared.approval.Compartment), InstanceId: instance.Id})
		if err != nil {
			return err
		}
		if response.OpcNextPage != nil && *response.OpcNextPage != "" || len(response.Items) != 1 {
			return errors.New("disposable host requires exactly one bounded boot-volume attachment")
		}
		attachment := response.Items[0]
		if attachment.InstanceId == nil || *attachment.InstanceId != *instance.Id || attachment.CompartmentId == nil || *attachment.CompartmentId != c.prepared.approval.Compartment || attachment.AvailabilityDomain == nil || *attachment.AvailabilityDomain != spec.AvailabilityDomain || attachment.BootVolumeId == nil || *attachment.BootVolumeId == "" || attachment.LifecycleState != core.BootVolumeAttachmentLifecycleStateAttached {
			return errors.New("boot-volume attachment differs from exact disposable host")
		}
		volume, err := c.block.GetBootVolume(ociclient.RequestContext(ctx), core.GetBootVolumeRequest{BootVolumeId: attachment.BootVolumeId})
		if err != nil {
			return err
		}
		if volume.Id == nil || *volume.Id != *attachment.BootVolumeId || volume.CompartmentId == nil || *volume.CompartmentId != c.prepared.approval.Compartment || volume.AvailabilityDomain == nil || *volume.AvailabilityDomain != spec.AvailabilityDomain || volume.SizeInGBs == nil || *volume.SizeInGBs != spec.BootGB || volume.LifecycleState != core.BootVolumeLifecycleStateAvailable {
			return errors.New("observed boot-volume identity or size differs from signed host bounds")
		}
	}
	return nil
}
