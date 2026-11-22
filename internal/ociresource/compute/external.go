package compute

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/oracle/oci-go-sdk/v65/core"
)

type externalVolume struct {
	id     *string
	domain string
	label  string
}

func (v externalVolume) matches(volume core.Volume) bool {
	return deref(volume.AvailabilityDomain) == v.domain
}

func (p Pass) externalVolumes(attachments []core.VolumeAttachment) ([]externalVolume, error) {
	var volumes []externalVolume
	for _, instance := range slices.Sorted(maps.Keys(p.External)) {
		host := p.External[instance]
		var data []core.VolumeAttachment
		for _, attachment := range attachments {
			if deref(attachment.GetInstanceId()) == instance && deref(attachment.GetDevice()) == dataDevice {
				data = append(data, attachment)
			}
		}
		if len(data) != 1 {
			return nil, fmt.Errorf("external host %s (%s): expected one data volume attached at %s, observed %d", host, instance, dataDevice, len(data))
		}
		attachment := data[0]
		id, domain := attachment.GetVolumeId(), deref(attachment.GetAvailabilityDomain())
		if attachment.GetLifecycleState() != core.VolumeAttachmentLifecycleStateAttached || deref(attachment.GetIsReadOnly()) ||
			deref(attachment.GetIsShareable()) || deref(id) == "" || domain == "" {
			return nil, fmt.Errorf("external host %s (%s): data attachment must be one ATTACHED writable, unshared volume with a known availability domain", host, instance)
		}
		count := 0
		for _, other := range attachments {
			if deref(other.GetVolumeId()) == *id {
				count++
			}
		}
		if count != 1 {
			return nil, fmt.Errorf("external host %s (%s): data volume %s has %d attachments; growth needs exactly one", host, instance, *id, count)
		}
		volumes = append(volumes, externalVolume{id: id, domain: domain, label: fmt.Sprintf("external host %s data volume", host)})
	}
	return volumes, nil
}

func (p Pass) preflightExternal(ctx context.Context) error {
	if len(p.External) == 0 {
		return nil
	}
	attachments, err := p.attachments(ctx)
	if err != nil {
		return err
	}
	volumes, err := p.externalVolumes(attachments)
	if err != nil {
		return err
	}
	for _, volume := range volumes {
		if _, err := p.growthVolume(ctx, volume.label, volume.id, volume.matches); err != nil {
			return err
		}
	}
	return nil
}

func (p Pass) growExternal(ctx context.Context, attachments []core.VolumeAttachment) error {
	volumes, err := p.externalVolumes(attachments)
	if err != nil {
		return err
	}
	for _, volume := range volumes {
		if _, err := p.grow(ctx, volume.label, volume.id, volume.matches); err != nil {
			return err
		}
	}
	return nil
}
