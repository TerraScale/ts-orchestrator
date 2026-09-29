package app

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostboot"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
)

// deployTestProvider is an in-memory OCI region with any number of hosts,
// retained volumes and paravirtualized attachments. consistentNaming and
// inTransit model the image launch options that OCI reports for an instance.
type deployTestProvider struct {
	mu               sync.Mutex
	config           oci.RegionConfig
	consistentNaming bool
	inTransit        bool
	instances        []oci.CloudInstance
	boot             map[string]oci.CloudBootVolume
	launches         []oci.LaunchRequest
	volumes          []oci.CloudVolume
	attachments      []oci.CloudAttachment
	volumeRetries    map[string]string
}

var errDeployTestUnexpected = errors.New("unexpected fake OCI mutation")

func newDeployTestProvider(config oci.RegionConfig, consistentNaming, inTransit bool) *deployTestProvider {
	return &deployTestProvider{config: config, consistentNaming: consistentNaming, inTransit: inTransit,
		boot: make(map[string]oci.CloudBootVolume), volumeRetries: make(map[string]string)}
}

func cloneInstance(instance oci.CloudInstance) oci.CloudInstance {
	instance.Metadata = maps.Clone(instance.Metadata)
	instance.FreeformTags = maps.Clone(instance.FreeformTags)
	return instance
}

func (p *deployTestProvider) ListInstances(_ context.Context, compartmentID string) ([]oci.CloudInstance, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if compartmentID != p.config.CompartmentID {
		return nil, oci.ErrForeignResource
	}
	instances := make([]oci.CloudInstance, 0, len(p.instances))
	for _, instance := range p.instances {
		instances = append(instances, cloneInstance(instance))
	}
	return instances, nil
}

func (p *deployTestProvider) GetInstance(_ context.Context, instanceID string) (oci.CloudInstance, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, instance := range p.instances {
		if instance.ID == instanceID {
			return cloneInstance(instance), nil
		}
	}
	return oci.CloudInstance{}, errors.New("unknown fake OCI instance")
}

func (p *deployTestProvider) LaunchInstance(_ context.Context, request oci.LaunchRequest) (oci.CloudInstance, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for index, launch := range p.launches {
		if launch.RetryToken == request.RetryToken {
			return cloneInstance(p.instances[index]), nil
		}
	}
	region, err := p.config.Region.OCIRegion()
	if err != nil {
		return oci.CloudInstance{}, err
	}
	number := len(p.instances) + 1
	instance := oci.CloudInstance{
		ID: fmt.Sprintf("ocid1.instance.oc1.%s.member%d", region, number), CompartmentID: p.config.CompartmentID,
		PrivateIP: request.PrivateIP, AvailabilityDomain: p.config.AvailabilityDomain, FaultDomain: request.FaultDomain,
		Shape: request.Shape, Ocpus: new(float32(request.WholeOCPUs)), MemoryInGBs: new(float32(request.MemoryInGBs)),
		LifecycleState: "RUNNING", ETag: fmt.Sprintf("instance-etag-%d", number), ImageID: request.ImageID,
		ConsistentVolumeNamingEnabled: new(p.consistentNaming),
		Metadata:                      map[string]string{hostboot.MetadataKey: request.BootDescriptor, "terrascale_host_node": request.Node},
		FreeformTags:                  maps.Clone(request.FreeformTags),
	}
	request.FreeformTags = maps.Clone(request.FreeformTags)
	p.launches = append(p.launches, request)
	p.instances = append(p.instances, instance)
	suffix, _ := strings.CutPrefix(instance.ID, "ocid1.instance.")
	p.boot[instance.ID] = oci.CloudBootVolume{ID: "ocid1.bootvolume." + suffix, CompartmentID: p.config.CompartmentID,
		AvailabilityDomain: p.config.AvailabilityDomain, ImageID: request.ImageID,
		SizeGB: int64(p.config.BootVolumeGB), VPUsPerGB: int64(p.config.BootVolumeVPUsPerGB),
		LifecycleState: "AVAILABLE", ETag: fmt.Sprintf("boot-etag-%d", number)}
	return cloneInstance(instance), nil
}

func (p *deployTestProvider) UpdateInstanceTags(context.Context, string, string, map[string]string) (oci.CloudInstance, error) {
	return oci.CloudInstance{}, errDeployTestUnexpected
}

func (p *deployTestProvider) TerminateInstance(context.Context, string, string) error {
	return errDeployTestUnexpected
}

func (p *deployTestProvider) TerminateTerminalInstance(context.Context, string, string) error {
	return errDeployTestUnexpected
}

func (p *deployTestProvider) ListVolumeAttachments(_ context.Context, compartmentID, instanceID string) ([]oci.CloudAttachment, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if compartmentID != p.config.CompartmentID {
		return nil, oci.ErrForeignResource
	}
	var attachments []oci.CloudAttachment
	for _, attachment := range p.attachments {
		if instanceID == "" || attachment.InstanceID == instanceID {
			attachments = append(attachments, attachment)
		}
	}
	return attachments, nil
}

func (p *deployTestProvider) ListInstanceDevices(_ context.Context, instanceID string) ([]oci.CloudDevice, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var devices []oci.CloudDevice
	for _, letter := range []string{"b", "c", "d"} {
		name := "/dev/oracleoci/oraclevd" + letter
		used := slices.ContainsFunc(p.attachments, func(attachment oci.CloudAttachment) bool {
			return attachment.InstanceID == instanceID && attachment.Device == name
		})
		devices = append(devices, oci.CloudDevice{Name: name, IsAvailable: new(!used)})
	}
	return devices, nil
}

func (p *deployTestProvider) GetVolumeAttachment(_ context.Context, attachmentID string) (oci.CloudAttachment, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, attachment := range p.attachments {
		if attachment.ID == attachmentID {
			return attachment, nil
		}
	}
	return oci.CloudAttachment{}, errors.New("unknown fake OCI attachment")
}

func (p *deployTestProvider) AttachVolume(_ context.Context, request oci.CloudVolumeAttachRequest) (oci.CloudAttachment, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, attachment := range p.attachments {
		if attachment.VolumeID == request.VolumeID {
			return attachment, nil
		}
	}
	number := len(p.attachments) + 1
	attachment := oci.CloudAttachment{ID: fmt.Sprintf("ocid1.volumeattachment.oc1..member%d", number),
		VolumeID: request.VolumeID, InstanceID: request.InstanceID, LifecycleState: "ATTACHED",
		ETag: fmt.Sprintf("attachment-etag-%d", number), Device: request.Device,
		IsReadOnly: new(request.IsReadOnly), IsShareable: new(request.IsShareable),
		IsPvEncryptionInTransitEnabled: new(request.IsPvEncryptionInTransitEnabled && p.inTransit)}
	p.attachments = append(p.attachments, attachment)
	return attachment, nil
}

func (p *deployTestProvider) DetachVolume(context.Context, string, string) error {
	return errDeployTestUnexpected
}

func (p *deployTestProvider) ListVolumes(_ context.Context, compartmentID, availabilityDomain string) ([]oci.CloudVolume, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if compartmentID != p.config.CompartmentID || availabilityDomain != p.config.AvailabilityDomain {
		return nil, oci.ErrForeignResource
	}
	return slices.Clone(p.volumes), nil
}

func (p *deployTestProvider) CreateVolume(_ context.Context, request oci.VolumeCreateRequest, tags map[string]string, retry string) (oci.CloudVolume, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if id, exists := p.volumeRetries[retry]; exists {
		for _, volume := range p.volumes {
			if volume.ID == id {
				return volume, nil
			}
		}
	}
	number := len(p.volumes) + 1
	volume := oci.CloudVolume{ID: fmt.Sprintf("ocid1.volume.oc1..member%d", number), CompartmentID: p.config.CompartmentID,
		AvailabilityDomain: request.AvailabilityDomain, SizeGB: request.SizeGB,
		VPUsPerGB: int64(p.config.DataVolumeVPUsPerGB), LifecycleState: "AVAILABLE",
		ETag: fmt.Sprintf("volume-etag-%d", number), FreeformTags: maps.Clone(tags)}
	p.volumes = append(p.volumes, volume)
	p.volumeRetries[retry] = volume.ID
	return volume, nil
}

func (p *deployTestProvider) GetVolume(_ context.Context, volumeID string) (oci.CloudVolume, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, volume := range p.volumes {
		if volume.ID == volumeID {
			return volume, nil
		}
	}
	return oci.CloudVolume{}, errors.New("unknown fake OCI volume")
}

func (p *deployTestProvider) GetAttachedBootVolume(_ context.Context, instanceID string) (oci.CloudBootVolume, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	boot, exists := p.boot[instanceID]
	if !exists {
		return oci.CloudBootVolume{}, errors.New("unknown fake OCI boot attachment")
	}
	return boot, nil
}

func (p *deployTestProvider) GetBootVolume(_ context.Context, bootVolumeID string) (oci.CloudBootVolume, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, boot := range p.boot {
		if boot.ID == bootVolumeID {
			return boot, nil
		}
	}
	return oci.CloudBootVolume{}, errors.New("unknown fake OCI boot volume")
}

func (p *deployTestProvider) ListBootVolumeAttachments(_ context.Context, bootVolumeID string) ([]oci.CloudBootAttachment, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for instanceID, boot := range p.boot {
		if boot.ID == bootVolumeID {
			return []oci.CloudBootAttachment{{InstanceID: instanceID, BootVolumeID: boot.ID, LifecycleState: "ATTACHED"}}, nil
		}
	}
	return nil, nil
}

func (p *deployTestProvider) DeleteBootVolume(context.Context, string, string) error {
	return errDeployTestUnexpected
}

func (p *deployTestProvider) DeleteVolume(context.Context, string, string) error {
	return errDeployTestUnexpected
}

type acceptingImageVerifier struct{}

func (acceptingImageVerifier) VerifyImageQualified(context.Context, oci.Region, string) error {
	return nil
}

var _ oci.Provider = (*deployTestProvider)(nil)
