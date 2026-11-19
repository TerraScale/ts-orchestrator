package compute

import (
	"context"
	"fmt"

	"github.com/TerraScale/ts-orchestrator/internal/nodeinit"
	"github.com/oracle/oci-go-sdk/v65/core"
)

func (p Pass) growExternal(ctx context.Context, slots map[string]core.Volume, attachments []core.VolumeAttachment) error {
	if len(p.External) == 0 {
		return nil
	}
	instances, err := all(func(page *string) ([]core.Instance, *string, error) {
		r, err := p.Compute.ListInstances(ctx, core.ListInstancesRequest{CompartmentId: &p.Compartment, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return fmt.Errorf("list external hosts: %w", err)
	}
	for _, host := range p.External {
		var instance *core.Instance
		for _, candidate := range instances {
			if deref(candidate.DisplayName) != host || candidate.LifecycleState == core.InstanceLifecycleStateTerminated || candidate.LifecycleState == core.InstanceLifecycleStateTerminating {
				continue
			}
			if instance != nil {
				return fmt.Errorf("external host %s names multiple live instances", host)
			}
			instance = &candidate
		}
		if instance == nil {
			return fmt.Errorf("external host %s has no live instance", host)
		}
		name := "external-" + host
		volume := slots[name]
		if instance.Metadata[nodeinit.VolumeKey] != deref(volume.Id) || volume.FreeformTags[boundInstance] != deref(instance.Id) {
			return fmt.Errorf("external host %s data volume lacks its instance binding", host)
		}
		live := 0
		for _, attachment := range attachments {
			if deref(attachment.GetVolumeId()) != deref(volume.Id) {
				continue
			}
			live++
			if deref(attachment.GetInstanceId()) != deref(instance.Id) || attachment.GetLifecycleState() != core.VolumeAttachmentLifecycleStateAttached ||
				deref(attachment.GetDevice()) != dataDevice || deref(attachment.GetIsReadOnly()) || deref(attachment.GetIsShareable()) {
				return fmt.Errorf("external host %s data volume has an unexpected attachment", host)
			}
		}
		if live != 1 {
			return fmt.Errorf("external host %s data volume needs exactly one attached writer; observed %d", host, live)
		}
		grown, err := p.grow(ctx, slot{name, volume})
		if err != nil {
			return err
		}
		slots[name] = grown.volume
	}
	return nil
}
