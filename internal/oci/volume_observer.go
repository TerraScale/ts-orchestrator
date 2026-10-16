package oci

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/nats-io/nats.go/jetstream"
)

// VolumeMountObserver exposes reads only. The manager keeps its delegated
// workload-effect lease held and guards it before and after each observation.
type VolumeMountObserver struct{ reader *fleet }

func NewVolumeMountObserver(factory *ociclient.Factory, config RegionConfig, intent RegionIntent, journal Journal) (*VolumeMountObserver, error) {
	if err := config.Validate(intent); err != nil {
		return nil, err
	}
	region, err := config.Region.OCIRegion()
	store, ok := journal.(*KVJournal)
	if err != nil || factory == nil || factory.Region() != region || !ok || store == nil {
		return nil, errors.New("volume observation requires the exact regional OCI factory and durable ownership journal")
	}
	config.FaultDomains = slices.Clone(config.FaultDomains)
	config.NetworkSecurityGroupIDs = slices.Clone(config.NetworkSecurityGroupIDs)
	provider, err := sdkProviderFrom(factory, config, nil)
	if err != nil {
		return nil, err
	}
	return &VolumeMountObserver{reader: &fleet{config: config, provider: volumeObservationProvider{Provider: provider}, journal: volumeObservationJournal{store}, now: time.Now}}, nil
}

// VerifiedVolumeObservation is evidence of the exact existing attachment. It
// grants no formatting, mutation, worker authority or workload-effect lease.
type VerifiedVolumeObservation struct {
	pins        VolumeInitializationPins
	descriptor  string
	predecessor string
	observedAt  time.Time
}

func (v VerifiedVolumeObservation) Pins() VolumeInitializationPins { return v.pins }
func (v VerifiedVolumeObservation) BootDescriptorSHA256() string   { return v.descriptor }
func (v VerifiedVolumeObservation) PredecessorID() string          { return v.predecessor }
func (v VerifiedVolumeObservation) ObservedAt() time.Time          { return v.observedAt }
func (v VerifiedVolumeObservation) IsVerified() bool               { return !v.observedAt.IsZero() }

type VerifiedTerminatedInstance struct {
	instance   string
	region     Region
	generation uint64
	owner      string
	observedAt time.Time
}

func (v VerifiedTerminatedInstance) InstanceID() string    { return v.instance }
func (v VerifiedTerminatedInstance) Region() Region        { return v.region }
func (v VerifiedTerminatedInstance) Generation() uint64    { return v.generation }
func (v VerifiedTerminatedInstance) Owner() string         { return v.owner }
func (v VerifiedTerminatedInstance) ObservedAt() time.Time { return v.observedAt }
func (v VerifiedTerminatedInstance) IsVerified() bool      { return !v.observedAt.IsZero() }

func (o *VolumeMountObserver) regionalID(id, kind string) bool {
	if o == nil || o.reader == nil {
		return false
	}
	region, err := o.reader.config.Region.OCIRegion()
	return err == nil && isOCID(id, kind) && strings.HasPrefix(id, "ocid1."+kind+".oc1."+region+".")
}

// ObserveTerminatedInstance never treats absence, STOPPED or TERMINATING as
// fencing. Revoking a launch image does not invalidate a terminal observation.
func (o *VolumeMountObserver) ObserveTerminatedInstance(ctx context.Context, instanceID string) (VerifiedTerminatedInstance, error) {
	if !o.regionalID(instanceID, "instance") {
		return VerifiedTerminatedInstance{}, ErrForeignResource
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	f := o.reader
	cloud, err := f.provider.GetInstance(ctx, instanceID)
	if err != nil {
		return VerifiedTerminatedInstance{}, err
	}
	if cloud.LifecycleState != "TERMINATED" {
		return VerifiedTerminatedInstance{}, ErrWriterStopUnverified
	}
	c, tags := f.config, cloud.FreeformTags
	identity := ResourceIdentity{ID: instanceID, Region: c.Region, Generation: c.Generation, Owner: c.Owner, CreateKey: tags[tagCreateKey]}
	// OCI removes a terminated instance's VNIC and boot attachment. Its exact
	// durable launch ownership remains proof; current network health does not.
	if cloud.ID != instanceID || cloud.CompartmentID != c.CompartmentID || cloud.AvailabilityDomain != c.AvailabilityDomain || cloud.ETag == "" ||
		tags[tagManagedBy] != managedByValue || tags[tagOwner] != c.Owner || tags[tagRegion] != string(c.Region) ||
		tags[tagGeneration] != fmt.Sprint(c.Generation) || tags[tagResource] != resourceMemberHost || !validCreateKey(identity.CreateKey) || tags[tagHostNode] != hostNode(c, identity.CreateKey) {
		return VerifiedTerminatedInstance{}, ErrForeignResource
	}
	owned, err := f.journal.IsOwnedInstance(ctx, identity)
	if err != nil || !owned {
		return VerifiedTerminatedInstance{}, errors.Join(ErrForeignResource, err)
	}
	if err := ctx.Err(); err != nil {
		return VerifiedTerminatedInstance{}, err
	}
	return VerifiedTerminatedInstance{instance: instanceID, region: c.Region, generation: c.Generation, owner: c.Owner, observedAt: time.Now().UTC()}, nil
}

func (o *VolumeMountObserver) InspectVolumeMount(ctx context.Context, pins VolumeInitializationPins, predecessorInstanceID string) (VerifiedVolumeObservation, error) {
	if !o.regionalID(pins.InstanceID, "instance") || !o.regionalID(pins.VolumeID, "volume") || !o.regionalID(pins.AttachmentID, "volumeattachment") ||
		!entityid.Valid(pins.DatabaseID) || !entityid.Valid(pins.PartitionID) || !entityid.Valid(pins.HostCreateKey) ||
		pins.AttachmentETag == "" || !validDevicePath(pins.Device) || pins.FileSystemUUID == "" ||
		pins.FileSystemType != "ext4" && pins.FileSystemType != "xfs" || predecessorInstanceID == pins.InstanceID {
		return VerifiedVolumeObservation{}, errors.New("retained mount observation requires exact regional host, volume and attachment pins")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	f := o.reader
	cloud, identity, err := f.ownedInstance(ctx, pins.InstanceID)
	if err != nil {
		return VerifiedVolumeObservation{}, err
	}
	if cloud.LifecycleState != "RUNNING" || identity.CreateKey != pins.HostCreateKey {
		return VerifiedVolumeObservation{}, ErrForeignResource
	}
	operation, found, err := f.journal.GetOperation(ctx, OperationScope{Action: actionLaunch, Key: identity.CreateKey, Region: identity.Region, Generation: identity.Generation, Owner: identity.Owner})
	if err != nil || !found {
		return VerifiedVolumeObservation{}, errors.Join(ErrHostBootBindingMismatch, err)
	}
	descriptor, err := hostboot.Parse([]byte(cloud.Metadata[hostboot.MetadataKey]))
	if err != nil || descriptor.DatabaseID != pins.DatabaseID || descriptor.PartitionID != pins.PartitionID {
		return VerifiedVolumeObservation{}, ErrHostBootBindingMismatch
	}
	instance, err := f.instanceFromCloud(ctx, cloud, identity, operation)
	if err != nil {
		return VerifiedVolumeObservation{}, err
	}
	matched := false
	for _, attachment := range instance.Attachments {
		if attachment.ID == pins.AttachmentID && attachment.VolumeID == pins.VolumeID && attachment.InstanceID == pins.InstanceID &&
			attachment.ETag == pins.AttachmentETag && attachment.Device == pins.Device {
			matched = true
		}
	}
	if !matched {
		return VerifiedVolumeObservation{}, ErrForeignResource
	}
	volume, err := f.ownedVolume(ctx, pins.VolumeID)
	if err != nil {
		return VerifiedVolumeObservation{}, err
	}
	if volume.LifecycleState != "AVAILABLE" {
		return VerifiedVolumeObservation{}, ErrRetainedVolumeInUse
	}
	attachments, err := f.findVolumeAttachments(ctx, pins.VolumeID)
	if err != nil {
		return VerifiedVolumeObservation{}, err
	}
	current := 0
	terminated := map[string]bool{}
	for _, attachment := range attachments {
		switch {
		case attachment.ID == pins.AttachmentID && attachment.InstanceID == pins.InstanceID && attachment.LifecycleState == "ATTACHED" &&
			attachment.Device == pins.Device && attachment.IsReadOnly != nil && !*attachment.IsReadOnly &&
			attachment.IsShareable != nil && !*attachment.IsShareable && attachment.IsPvEncryptionInTransitEnabled != nil && *attachment.IsPvEncryptionInTransitEnabled:
			current++
		case attachment.InstanceID != pins.InstanceID && attachment.LifecycleState == "DETACHED":
			if !terminated[attachment.InstanceID] {
				if _, err := o.ObserveTerminatedInstance(ctx, attachment.InstanceID); err != nil {
					return VerifiedVolumeObservation{}, fmt.Errorf("observe detached volume history: %w", err)
				}
				terminated[attachment.InstanceID] = true
			}
		default:
			return VerifiedVolumeObservation{}, ErrRetainedVolumeInUse
		}
	}
	if current != 1 {
		return VerifiedVolumeObservation{}, ErrRetainedVolumeInUse
	}
	if predecessorInstanceID != "" && !terminated[predecessorInstanceID] {
		if _, err := o.ObserveTerminatedInstance(ctx, predecessorInstanceID); err != nil {
			return VerifiedVolumeObservation{}, fmt.Errorf("observe retained volume predecessor: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return VerifiedVolumeObservation{}, err
	}
	return VerifiedVolumeObservation{pins: pins, descriptor: instance.BootDescriptorSHA256, predecessor: predecessorInstanceID, observedAt: time.Now().UTC()}, nil
}

// Only provider HTTP reads get the SDK retry context; journal reads retain the
// caller's original cancellation and delegated workload-effect context.
type volumeObservationProvider struct{ Provider }

func (p volumeObservationProvider) GetInstance(ctx context.Context, id string) (CloudInstance, error) {
	return p.Provider.GetInstance(ociclient.RequestContext(ctx), id)
}
func (p volumeObservationProvider) GetVolume(ctx context.Context, id string) (CloudVolume, error) {
	return p.Provider.GetVolume(ociclient.RequestContext(ctx), id)
}
func (p volumeObservationProvider) GetVolumeAttachment(ctx context.Context, id string) (CloudAttachment, error) {
	return p.Provider.GetVolumeAttachment(ociclient.RequestContext(ctx), id)
}
func (p volumeObservationProvider) ListVolumeAttachments(ctx context.Context, compartment, instance string) ([]CloudAttachment, error) {
	return p.Provider.ListVolumeAttachments(ociclient.RequestContext(ctx), compartment, instance)
}
func (p volumeObservationProvider) ListVolumeAttachmentsByVolume(ctx context.Context, compartment, domain, volume string) ([]CloudAttachment, error) {
	if reader, ok := p.Provider.(VolumeAttachmentLister); ok {
		return reader.ListVolumeAttachmentsByVolume(ociclient.RequestContext(ctx), compartment, domain, volume)
	}
	return p.Provider.ListVolumeAttachments(ociclient.RequestContext(ctx), compartment, "")
}

// Normal fleet ownership reads may repair journal projections. This observer
// requires already durable projections and never repairs or advances them.
type volumeObservationJournal struct{ *KVJournal }

func (j volumeObservationJournal) IsOwnedInstance(ctx context.Context, identity ResourceIdentity) (bool, error) {
	return j.readOwnership(ctx, "instance", identity)
}
func (j volumeObservationJournal) IsOwnedVolume(ctx context.Context, identity ResourceIdentity) (bool, error) {
	return j.readOwnership(ctx, "volume", identity)
}
func (j volumeObservationJournal) readOwnership(ctx context.Context, kind string, identity ResourceIdentity) (bool, error) {
	entry, err := j.read(ctx, ownershipKey(kind, identity.ID))
	if errors.Is(err, jetstream.ErrKeyNotFound) || errors.Is(err, jetstream.ErrKeyDeleted) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return entry.Kind == kind && entry.Identity == identity, nil
}
