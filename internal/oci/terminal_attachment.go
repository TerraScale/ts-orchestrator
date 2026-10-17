package oci

import (
	"context"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

// TerminalAttachmentTarget describes original signed terminal selectors. It
// carries no signature verification, protected acceptance or effect authority.
type TerminalAttachmentTarget struct {
	DatabaseID, PartitionID      string
	InstanceID, VolumeID         string
	HostCreateKey, DataCreateKey string
}

// TerminalAttachmentPins retain native attachment identity, not an ETag-based
// incarnation. A future acceptance store must independently retain these pins.
type TerminalAttachmentPins struct {
	Target                     TerminalAttachmentTarget
	AttachmentID, CompartmentID string
	AvailabilityDomain, Type    string
	Device                     string
	CreatedAt                  time.Time
}

// TerminalAttachmentObservation proves only an actual SDK read. It cannot
// authorize first acceptance, stop, detach, retirement or a protected write.
type TerminalAttachmentObservation struct {
	pins       TerminalAttachmentPins
	etag       string
	descriptor string
	observed   time.Time
	deadline   time.Time
	original   context.Context
	observer   *VolumeMountObserver
}

func (v TerminalAttachmentObservation) Pins() TerminalAttachmentPins { return v.pins }
func (v TerminalAttachmentObservation) ETag() string                 { return v.etag }
func (v TerminalAttachmentObservation) BootDescriptorSHA256() string { return v.descriptor }
func (v TerminalAttachmentObservation) ObservedAt() time.Time        { return v.observed }
func (v TerminalAttachmentObservation) ExpiresAt() time.Time         { return v.deadline }

func (v TerminalAttachmentObservation) IsVerified() bool {
	return v.observer != nil && v.original != nil && !v.observed.IsZero() &&
		v.original.Err() == nil && time.Now().Before(v.deadline)
}

// Revalidate retains the first native pin and original caller lifetime. A
// replacement attachment cannot become the old observation's current target.
func (v TerminalAttachmentObservation) Revalidate(ctx context.Context) error {
	if !v.IsVerified() {
		return ErrForeignResource
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	caller := ctx
	deadline := v.deadline
	if current, ok := caller.Deadline(); ok && current.Before(deadline) {
		deadline = current
	}
	ctx, cancel := context.WithDeadline(v.original, deadline)
	stop := context.AfterFunc(caller, cancel)
	defer cancel()
	defer stop()
	pins, _, descriptor, err := v.observer.inspectTerminalAttachment(ctx, v.pins.Target, &v.pins)
	if err != nil {
		return err
	}
	if pins != v.pins || descriptor != v.descriptor || v.original.Err() != nil {
		return ErrForeignResource
	}
	if err := caller.Err(); err != nil {
		return err
	}
	return sealTerminalAttachmentContext(ctx)
}

// ObserveTerminalAttachment derives the unique positive attachment from the
// exact instance and volume. The caller must separately verify signed intent
// and genuine first acceptance; this read never supplies either authority.
func (o *VolumeMountObserver) ObserveTerminalAttachment(ctx context.Context, target TerminalAttachmentTarget) (TerminalAttachmentObservation, error) {
	if !o.regionalID(target.InstanceID, "instance") || !o.regionalID(target.VolumeID, "volume") ||
		!entityid.Valid(target.DatabaseID) || !entityid.Valid(target.PartitionID) ||
		!entityid.Valid(target.HostCreateKey) || !entityid.Valid(target.DataCreateKey) {
		return TerminalAttachmentObservation{}, ErrForeignResource
	}
	original := ctx
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	pins, etag, descriptor, err := o.inspectTerminalAttachment(ctx, target, nil)
	if err != nil {
		return TerminalAttachmentObservation{}, err
	}
	if err := sealTerminalAttachmentContext(ctx); err != nil {
		return TerminalAttachmentObservation{}, err
	}
	return TerminalAttachmentObservation{pins: pins, etag: etag, descriptor: descriptor,
		observed: time.Now().UTC(), deadline: deadline, original: original, observer: o}, nil
}

// Preserve admission values and the original SDK context while forbidding the
// placement sweep's optional cached storage/network verification.
type terminalAttachmentContext struct{ context.Context }

func (ctx terminalAttachmentContext) Value(key any) any {
	if _, cached := key.(observeOnlyKey); cached {
		return nil
	}
	return ctx.Context.Value(key)
}

func sealTerminalAttachmentContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); !ok || !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

func (o *VolumeMountObserver) inspectTerminalAttachment(ctx context.Context, target TerminalAttachmentTarget, original *TerminalAttachmentPins) (TerminalAttachmentPins, string, string, error) {
	var empty TerminalAttachmentPins
	if o == nil || o.reader == nil || o.remote != nil {
		return empty, "", "", ErrForeignResource
	}
	ctx = terminalAttachmentContext{Context: ctx}
	if err := sealTerminalAttachmentContext(ctx); err != nil {
		return empty, "", "", err
	}
	f := o.reader
	cloud, identity, err := f.ownedLaunch(ctx, target.InstanceID, false)
	if err != nil {
		return empty, "", "", err
	}
	if identity.CreateKey != target.HostCreateKey || cloud.LifecycleState != "RUNNING" && cloud.LifecycleState != "STOPPED" {
		return empty, "", "", ErrForeignResource
	}
	launch, result, found, err := f.terminalCreateResult(ctx, actionLaunch, target.HostCreateKey)
	if err != nil || !found || result.ResourceID != target.InstanceID {
		return empty, "", "", errors.Join(ErrForeignResource, err)
	}
	descriptor, err := launchIntentDescriptor(launch)
	if err != nil || descriptor.DatabaseID != target.DatabaseID || descriptor.PartitionID != target.PartitionID {
		return empty, "", "", errors.Join(ErrHostBootBindingMismatch, err)
	}
	volume, err := f.ownedVolume(ctx, target.VolumeID)
	if err != nil {
		return empty, "", "", err
	}
	_, created, found, err := f.terminalCreateResult(ctx, actionVolumeCreate, target.DataCreateKey)
	if err != nil || !found || created.ResourceID != target.VolumeID || volume.FreeformTags[tagCreateKey] != target.DataCreateKey || volume.LifecycleState != "AVAILABLE" {
		return empty, "", "", errors.Join(ErrForeignResource, err)
	}
	lister, ok := f.provider.(VolumeAttachmentLister)
	if !ok {
		return empty, "", "", ErrForeignResource
	}
	attachments, err := lister.ListVolumeAttachmentsByVolume(ctx, f.config.CompartmentID, f.config.AvailabilityDomain, target.VolumeID)
	if err != nil {
		return empty, "", "", err
	}
	var selected *CloudAttachment
	seen := make(map[string]bool, len(attachments))
	for i := range attachments {
		attachment := &attachments[i]
		if !o.regionalID(attachment.ID, "volumeattachment") || attachment.VolumeID != target.VolumeID ||
			attachment.CompartmentID != f.config.CompartmentID || attachment.AvailabilityDomain != f.config.AvailabilityDomain ||
			attachment.AttachmentType != "paravirtualized" || attachment.TimeCreated.IsZero() ||
			attachment.TimeCreated.After(time.Now()) || seen[attachment.ID] {
			return empty, "", "", ErrForeignResource
		}
		seen[attachment.ID] = true
		if attachment.LifecycleState == "DETACHED" && attachment.InstanceID != target.InstanceID {
			if _, err := o.ObserveTerminatedInstance(ctx, attachment.InstanceID); err != nil {
				return empty, "", "", err
			}
			continue
		}
		if selected != nil || attachment.InstanceID != target.InstanceID || !terminalAttachmentReady(*attachment) {
			return empty, "", "", ErrRetainedVolumeInUse
		}
		selected = attachment
	}
	if selected == nil || original != nil && selected.ID != original.AttachmentID {
		return empty, "", "", ErrRetainedVolumeInUse
	}
	actual, err := f.provider.GetVolumeAttachment(ctx, selected.ID)
	if err != nil {
		return empty, "", "", err
	}
	pins := terminalAttachmentPins(target, actual)
	if !terminalAttachmentReady(actual) || actual.ETag == "" || actual.InstanceID != target.InstanceID || actual.VolumeID != target.VolumeID ||
		pins != terminalAttachmentPins(target, *selected) ||
		original != nil && pins != *original {
		return empty, "", "", ErrForeignResource
	}
	if err := sealTerminalAttachmentContext(ctx); err != nil {
		return empty, "", "", err
	}
	return pins, actual.ETag, launch.BootDescriptorSHA256, nil
}

func terminalAttachmentPins(target TerminalAttachmentTarget, actual CloudAttachment) TerminalAttachmentPins {
	return TerminalAttachmentPins{Target: target, AttachmentID: actual.ID, CompartmentID: actual.CompartmentID,
		AvailabilityDomain: actual.AvailabilityDomain, Type: actual.AttachmentType, Device: actual.Device, CreatedAt: actual.TimeCreated}
}

func terminalAttachmentReady(actual CloudAttachment) bool {
	return actual.LifecycleState == "ATTACHED" && validDevicePath(actual.Device) &&
		actual.IsReadOnly != nil && !*actual.IsReadOnly && actual.IsShareable != nil && !*actual.IsShareable &&
		actual.IsPvEncryptionInTransitEnabled != nil && *actual.IsPvEncryptionInTransitEnabled
}
