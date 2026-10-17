package hostadmission

import (
	"context"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/qualification"
	"github.com/oracle/oci-go-sdk/v65/core"
)

func (s *readerState) observeGeometry(ctx context.Context, h BoundHost, spec qualification.HostSpec) error {
	if err := s.localGuard(ctx); err != nil {
		return err
	}
	compute, err := s.factory.Compute()
	if err != nil {
		return err
	}
	current, err := compute.GetInstance(ociclient.RequestContext(ctx), core.GetInstanceRequest{InstanceId: new(h.InstanceID)})
	if err != nil {
		return err
	}
	if err := s.localGuard(ctx); err != nil {
		return err
	}
	attachments, err := compute.ListBootVolumeAttachments(ociclient.RequestContext(ctx), core.ListBootVolumeAttachmentsRequest{AvailabilityDomain: new(spec.AvailabilityDomain), CompartmentId: new(s.verified.approval.Compartment), InstanceId: new(h.InstanceID)})
	if err != nil {
		return err
	}
	if attachments.OpcNextPage != nil && *attachments.OpcNextPage != "" || len(attachments.Items) != 1 {
		return ErrAdmission
	}
	a := attachments.Items[0]
	if stringValue(a.InstanceId) != h.InstanceID || stringValue(a.CompartmentId) != s.verified.approval.Compartment || stringValue(a.AvailabilityDomain) != spec.AvailabilityDomain || a.LifecycleState != core.BootVolumeAttachmentLifecycleStateAttached || stringValue(a.BootVolumeId) == "" {
		return ErrAdmission
	}
	if err := s.localGuard(ctx); err != nil {
		return err
	}
	block, err := s.factory.Blockstorage()
	if err != nil {
		return err
	}
	volume, err := block.GetBootVolume(ociclient.RequestContext(ctx), core.GetBootVolumeRequest{BootVolumeId: a.BootVolumeId})
	if err != nil {
		return err
	}
	if !matchesGeometry(current.Instance, volume.BootVolume, h, spec, s.verified.approval.Compartment, stringValue(a.BootVolumeId)) {
		return ErrAdmission
	}
	return s.localGuard(ctx)
}
func matchesGeometry(instance core.Instance, volume core.BootVolume, h BoundHost, spec qualification.HostSpec, compartment, bootID string) bool {
	return stringValue(instance.Id) == h.InstanceID && stringValue(instance.ImageId) == h.ImageID && stringValue(instance.CompartmentId) == compartment &&
		stringValue(instance.Shape) == spec.Shape && stringValue(instance.AvailabilityDomain) == spec.AvailabilityDomain && stringValue(instance.FaultDomain) == spec.FaultDomain && instance.LifecycleState == core.InstanceLifecycleStateRunning && instance.ShapeConfig != nil && instance.ShapeConfig.Ocpus != nil && *instance.ShapeConfig.Ocpus == spec.OCPUs && instance.ShapeConfig.MemoryInGBs != nil && *instance.ShapeConfig.MemoryInGBs == spec.MemoryGB &&
		stringValue(volume.Id) == bootID && stringValue(volume.CompartmentId) == compartment && stringValue(volume.AvailabilityDomain) == spec.AvailabilityDomain && stringValue(volume.ImageId) == h.ImageID &&
		volume.SizeInGBs != nil && *volume.SizeInGBs == spec.BootGB && volume.LifecycleState == core.BootVolumeLifecycleStateAvailable
}
func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
