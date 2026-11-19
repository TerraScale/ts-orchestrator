package compute

import (
	"context"
	"fmt"
	"maps"
	"net/http"

	"github.com/TerraScale/ts-orchestrator/internal/nodeinit"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

func (p Pass) bindingVolume(ctx context.Context, instance core.Instance, chosen slot) (core.GetVolumeResponse, error) {
	got, err := p.Storage.GetVolume(ctx, core.GetVolumeRequest{VolumeId: chosen.volume.Id})
	if err != nil {
		return got, fmt.Errorf("read %s for binding: %w", p.Key("volume", chosen.name), err)
	}
	if owner := got.FreeformTags[boundInstance]; owner != "" && owner != *instance.Id {
		return got, fmt.Errorf("%s is bound to instance %s; refusing to bind it to %s", p.Key("volume", chosen.name), owner, *instance.Id)
	}
	return got, nil
}

func (p Pass) bind(ctx context.Context, instance core.Instance, chosen slot) error {
	volume, err := p.bindingVolume(ctx, instance, chosen)
	if err != nil {
		return err
	}
	changed := false
	if volume.FreeformTags[boundInstance] == "" {
		tags := maps.Clone(volume.FreeformTags)
		if tags == nil {
			tags = map[string]string{}
		}
		tags[boundInstance] = *instance.Id
		if _, err := p.Storage.UpdateVolume(ctx, core.UpdateVolumeRequest{VolumeId: volume.Id, IfMatch: volume.Etag,
			UpdateVolumeDetails: core.UpdateVolumeDetails{FreeformTags: tags}}); err != nil {
			return fmt.Errorf("record %s on %s: %w", *instance.Id, p.Key("volume", chosen.name), err)
		}
		changed = true
	}
	var conflict error
	err = waitFor(ctx, func() (bool, error) {
		attachments, err := all(func(page *string) ([]core.VolumeAttachment, *string, error) {
			got, err := p.Compute.ListVolumeAttachments(ctx, core.ListVolumeAttachmentsRequest{
				CompartmentId: &p.Compartment, InstanceId: instance.Id, VolumeId: volume.Id, Page: page,
			})
			return got.Items, got.OpcNextPage, err
		})
		if err != nil {
			return false, err
		}
		attached := false
		for _, attachment := range attachments {
			if deref(attachment.GetInstanceId()) == *instance.Id && deref(attachment.GetVolumeId()) == *volume.Id &&
				attachment.GetLifecycleState() == core.VolumeAttachmentLifecycleStateAttached {
				attached = true
			}
		}
		got, err := p.Compute.GetInstance(ctx, core.GetInstanceRequest{InstanceId: instance.Id})
		if err != nil {
			return false, err
		}
		if !attached || got.LifecycleState != core.InstanceLifecycleStateRunning {
			return false, nil
		}
		if got.Metadata[nodeinit.VolumeKey] == *volume.Id {
			return true, nil
		}
		metadata := maps.Clone(got.Metadata)
		if metadata == nil {
			metadata = map[string]string{}
		}
		maps.Copy(metadata, nodeinit.PoolBinding(*volume.Id, volume.FreeformTags[filesystemTag], true))
		policy := common.NoRetryPolicy()
		_, err = p.Compute.UpdateInstance(ctx, core.UpdateInstanceRequest{InstanceId: instance.Id, IfMatch: got.Etag,
			UpdateInstanceDetails: core.UpdateInstanceDetails{Metadata: metadata}, RequestMetadata: common.RequestMetadata{RetryPolicy: &policy}})
		if service, ok := common.IsServiceError(err); ok && service.GetHTTPStatusCode() == http.StatusConflict {
			conflict = err
			return false, nil
		}
		changed = changed || err == nil
		return err == nil, err
	})
	if err != nil {
		if conflict != nil {
			return fmt.Errorf("bind %s to %s: %w (last OCI conflict: %v)", p.Key("volume", chosen.name), *instance.Id, err, conflict)
		}
		return fmt.Errorf("bind %s to %s: %w", p.Key("volume", chosen.name), *instance.Id, err)
	}
	verb := "unchanged"
	if changed {
		verb = "bound"
	}
	p.say(verb, "volume", chosen.name, *volume.Id+" to "+deref(instance.DisplayName))
	return nil
}
