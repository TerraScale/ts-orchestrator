package compute

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/oracle/oci-go-sdk/v65/core"
)

func (p Pass) growExternal(ctx context.Context, attachments []core.VolumeAttachment) error {
	for _, instance := range slices.Sorted(maps.Keys(p.External)) {
		host := p.External[instance]
		data := slices.DeleteFunc(slices.Clone(attachments), func(a core.VolumeAttachment) bool {
			return deref(a.GetInstanceId()) != instance || deref(a.GetDevice()) != dataDevice
		})
		if len(data) != 1 {
			return fmt.Errorf("external host %s (%s): expected one data volume attached at %s, observed %d", host, instance, dataDevice, len(data))
		}
		attachment := data[0]
		volume := deref(attachment.GetVolumeId())
		if attachment.GetLifecycleState() != core.VolumeAttachmentLifecycleStateAttached || deref(attachment.GetIsReadOnly()) || deref(attachment.GetIsShareable()) || volume == "" {
			return fmt.Errorf("external host %s (%s): data attachment must be one ATTACHED writable, unshared volume", host, instance)
		}
		writers := 0
		for _, other := range attachments {
			if deref(other.GetVolumeId()) == volume {
				writers++
			}
		}
		if writers != 1 {
			return fmt.Errorf("external host %s (%s): data volume %s has %d attachments; growth needs exactly one", host, instance, volume, writers)
		}
		label := fmt.Sprintf("external host %s data volume", host)
		if _, err := p.grow(ctx, label, &volume, func(v core.Volume) bool {
			return deref(v.AvailabilityDomain) == deref(attachment.GetAvailabilityDomain())
		}); err != nil {
			return err
		}
	}
	return nil
}
