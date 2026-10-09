package oci

import (
	"context"
	"errors"
	"fmt"
	"maps"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/oracle/oci-go-sdk/v65/core"
)

const actionVolumeResize = "volume-resize"

// ErrVolumeResizeUnsupported reports a provider without the UpdateVolume seam.
var ErrVolumeResizeUnsupported = errors.New("OCI provider cannot resize retained volumes")

// VolumeResizeRequest grows one owned retained volume. Resizes are grow-only:
// a SizeGB at or below the observed size is a no-op.
type VolumeResizeRequest struct {
	DatabaseID  string
	PartitionID string
	VolumeID    string
	SizeGB      int64
}

// VolumeResizer is implemented by the OCI fleet. Callers type-assert it so
// fleets without resize support (and test doubles) keep compiling.
type VolumeResizer interface {
	ResizeRetainedVolume(context.Context, VolumeResizeRequest) (RetainedVolume, error)
}

// VolumeUpdater is the optional Provider seam for OCI UpdateVolume. The size
// and the size tag change in one If-Match request, so an observer never sees
// one without the other.
type VolumeUpdater interface {
	UpdateVolumeSize(ctx context.Context, volumeID, etag string, sizeGB int64, tags map[string]string) (CloudVolume, error)
}

// maxVolumeResizeAttempts bounds the attempts of one resize target. A new
// attempt starts only after the previous one can no longer land, so this
// only stops a volume whose ETag keeps moving under every attempt.
const maxVolumeResizeAttempts = 8

func volumeResizeKey(volumeID string, sizeGB int64) string {
	return volumeResizeAttemptKey(volumeID, sizeGB, 1)
}

// volumeResizeAttemptKey is the journal key of one attempt to resize a volume
// to sizeGB. Every attempt has its own canonical ULID key.
func volumeResizeAttemptKey(volumeID string, sizeGB int64, attempt int) string {
	return entityid.Derive("volume-resize", volumeID, fmt.Sprint(sizeGB), fmt.Sprint(attempt))
}

// validVolumeResizeKey reports whether key is the key of some bounded
// attempt to resize volumeID to sizeGB.
func validVolumeResizeKey(key, volumeID string, sizeGB int64) bool {
	for attempt := 1; attempt <= maxVolumeResizeAttempts; attempt++ {
		if key == volumeResizeAttemptKey(volumeID, sizeGB, attempt) {
			return true
		}
	}
	return false
}

// selectResizeAttempt returns the attempt of a resize to drive: the first
// attempt that is missing or not superseded. An attempt is superseded when
// it never confirmed, the volume is still below its target, and the volume
// ETag no longer matches the attempt's If-Match ETag, so that request can
// never land as journaled (finding 11583 item 2). Attempts are written in
// order, so the first missing key ends the lookup.
func (f *fleet) selectResizeAttempt(ctx context.Context, cloud CloudVolume, sizeGB int64) (OperationScope, OperationIntent, bool, error) {
	for attempt := 1; attempt <= maxVolumeResizeAttempts; attempt++ {
		scope := OperationScope{
			Action: actionVolumeResize, Key: volumeResizeAttemptKey(cloud.ID, sizeGB, attempt),
			Region: f.config.Region, Generation: f.config.Generation, Owner: f.config.Owner,
		}
		intent, found, err := f.journal.GetOperation(ctx, scope)
		if err != nil {
			return OperationScope{}, OperationIntent{}, false, fmt.Errorf("read OCI volume resize intent: %w", err)
		}
		if !found {
			return scope, OperationIntent{}, false, nil
		}
		superseded, err := f.resizeAttemptSuperseded(ctx, intent, cloud)
		if err != nil {
			return OperationScope{}, OperationIntent{}, false, err
		}
		if !superseded {
			return scope, intent, true, nil
		}
	}
	return OperationScope{}, OperationIntent{}, false, fmt.Errorf("%w: resize of %s to %d GiB used all %d attempts",
		ErrStaleETag, cloud.ID, sizeGB, maxVolumeResizeAttempts)
}

func (f *fleet) resizeAttemptSuperseded(ctx context.Context, intent OperationIntent, cloud CloudVolume) (bool, error) {
	if intent.VolumeID != cloud.ID || cloud.SizeGB >= intent.SizeGB || cloud.ETag == "" || cloud.ETag == intent.ExpectedETag {
		return false, nil
	}
	result, recorded, err := f.journal.GetResult(ctx, intent)
	if err != nil {
		return false, fmt.Errorf("read OCI volume resize result: %w", err)
	}
	return !recorded || result.Unknown, nil
}

// ResizeRetainedVolume grows an owned volume through a journaled, epoch-fenced
// OCI UpdateVolume. The immutable intent (keyed by volume, target size and a
// bounded attempt number) records the exact predecessor size and ETag; the confirmed result advances
// the volume ownership record, so the larger volume stays owned instead of
// looking foreign. The host grows its filesystem separately.
func (f *fleet) ResizeRetainedVolume(ctx context.Context, request VolumeResizeRequest) (RetainedVolume, error) {
	if request.VolumeID == "" {
		return RetainedVolume{}, errors.New("retained volume resize requires a volume ID")
	}
	if request.SizeGB < minRetainedVolumeSizeGB || request.SizeGB > f.config.MaxDataVolumeGB {
		return RetainedVolume{}, fmt.Errorf("retained OCI volume size must be between %d GiB and the configured fleet bound %d GiB", minRetainedVolumeSizeGB, f.config.MaxDataVolumeGB)
	}
	updater, ok := f.provider.(VolumeUpdater)
	if !ok {
		return RetainedVolume{}, ErrVolumeResizeUnsupported
	}
	epoch, err := f.currentEpoch()
	if err != nil {
		return RetainedVolume{}, err
	}
	release, err := f.beginActiveWorkloadEffect(ctx, epoch, request.DatabaseID, request.PartitionID)
	if err != nil {
		return RetainedVolume{}, err
	}
	defer release()
	cloud, identity, err := f.reobserveVolume(ctx, request.VolumeID)
	if err != nil {
		return RetainedVolume{}, err
	}
	scope, intent, hasIntent, err := f.selectResizeAttempt(ctx, cloud, request.SizeGB)
	if err != nil {
		return RetainedVolume{}, err
	}
	if hasIntent && (intent.VolumeID != request.VolumeID || intent.CreateKey != identity.CreateKey) {
		return RetainedVolume{}, fmt.Errorf("%w: resize operation is bound to a different volume", ErrForeignResource)
	}
	// Ownership is proven at the predecessor size before the effect, or at the
	// target size once a recorded resize has landed.
	predecessor := identity
	if hasIntent && cloud.SizeGB == intent.SizeGB {
		predecessor.SizeGB = intent.PreviousSizeGB
	}
	owned, err := f.journal.IsOwnedVolume(ctx, identity)
	if err == nil && !owned && predecessor != identity {
		owned, err = f.journal.IsOwnedVolume(ctx, predecessor)
	}
	if err != nil {
		return RetainedVolume{}, fmt.Errorf("read OCI retained volume ownership journal: %w", err)
	}
	if !owned {
		return RetainedVolume{}, fmt.Errorf("%w: %s", ErrRetainedVolumeUnknown, request.VolumeID)
	}
	if !hasIntent && cloud.SizeGB >= request.SizeGB || hasIntent && cloud.SizeGB > intent.SizeGB {
		return retainedVolumeFromCloud(cloud, identity), nil
	}
	if hasIntent {
		prior, confirmed, err := f.journal.GetResult(ctx, intent)
		if err != nil {
			return RetainedVolume{}, fmt.Errorf("read OCI volume resize result: %w", err)
		}
		if confirmed && !prior.Unknown {
			if cloud.SizeGB != intent.SizeGB {
				return RetainedVolume{}, fmt.Errorf("%w: confirmed resize of %s is no longer observed", ErrAttachmentRecoveryHold, request.VolumeID)
			}
			// Re-recording the immutable receipt repairs an interrupted
			// ownership advance without changing the confirmed result.
			if err := f.recordResult(ctx, epoch, OperationResult{Intent: intent, ResourceID: prior.ResourceID, ETag: prior.ETag}); err != nil {
				return RetainedVolume{}, err
			}
			return retainedVolumeFromCloud(cloud, identity), nil
		}
	}
	if cloud.LifecycleState != "AVAILABLE" {
		return RetainedVolume{}, fmt.Errorf("%w: retained volume %s is %s", ErrAttachmentRecoveryHold, request.VolumeID, cloud.LifecycleState)
	}
	if !hasIntent {
		intent = f.intent(actionVolumeResize, scope.Key, request.VolumeID, identity.CreateKey, cloud.ETag, "", request.VolumeID)
		intent.AvailabilityDomain = cloud.AvailabilityDomain
		intent.SizeGB = request.SizeGB
		intent.PreviousSizeGB = cloud.SizeGB
		if err := f.recordIntent(ctx, epoch, intent); err != nil {
			return RetainedVolume{}, err
		}
		stored, found, err := f.journal.GetOperation(ctx, scope)
		if err != nil {
			return RetainedVolume{}, fmt.Errorf("confirm OCI volume resize intent: %w", err)
		}
		if !found || !sameIntent(stored, intent) {
			return RetainedVolume{}, fmt.Errorf("%w: persisted resize intent changed during creation", ErrAttachmentRecoveryHold)
		}
		intent = stored
	}
	if cloud.SizeGB == intent.SizeGB {
		// The update landed before its result was recorded.
		if err := f.recordResult(ctx, epoch, OperationResult{Intent: intent, ResourceID: request.VolumeID, ETag: cloud.ETag}); err != nil {
			return RetainedVolume{}, err
		}
		return retainedVolumeFromCloud(cloud, identity), nil
	}
	if cloud.SizeGB != intent.PreviousSizeGB || cloud.ETag != intent.ExpectedETag {
		return RetainedVolume{}, fmt.Errorf("%w: retained volume changed since its resize intent", ErrStaleETag)
	}
	tags := maps.Clone(cloud.FreeformTags)
	tags[tagVolumeSize] = fmt.Sprint(intent.SizeGB)
	if err := f.guard(ctx, epoch); err != nil {
		return RetainedVolume{}, err
	}
	_, updateErr := updater.UpdateVolumeSize(ctx, request.VolumeID, intent.ExpectedETag, intent.SizeGB, tags)
	observed, observedIdentity, observeErr := f.reobserveVolume(ctx, request.VolumeID)
	if observeErr != nil || observed.SizeGB != intent.SizeGB {
		return RetainedVolume{}, errors.Join(ErrOutcomeUnknown, updateErr, observeErr,
			f.recordResult(ctx, epoch, OperationResult{Intent: intent, Unknown: true}))
	}
	if observedIdentity.CreateKey != identity.CreateKey || observed.AvailabilityDomain != intent.AvailabilityDomain {
		return RetainedVolume{}, fmt.Errorf("%w: resized volume scope changed", ErrForeignResource)
	}
	if err := f.recordResult(ctx, epoch, OperationResult{Intent: intent, ResourceID: request.VolumeID, ETag: observed.ETag}); err != nil {
		return RetainedVolume{}, err
	}
	return retainedVolumeFromCloud(observed, observedIdentity), nil
}

// UpdateVolumeSize grows one volume and replaces its freeform tags in a
// single If-Match request. The performance tier is not changed.
func (provider *sdkProvider) UpdateVolumeSize(ctx context.Context, volumeID, etag string, sizeGB int64, tags map[string]string) (CloudVolume, error) {
	response, err := provider.storage.UpdateVolume(ctx, core.UpdateVolumeRequest{
		VolumeId: new(volumeID),
		IfMatch:  new(etag),
		UpdateVolumeDetails: core.UpdateVolumeDetails{
			SizeInGBs:    new(sizeGB),
			FreeformTags: cloneStringMap(tags),
		},
	})
	if err != nil {
		return CloudVolume{}, fmt.Errorf("resize retained OCI volume: %w", err)
	}
	return cloudVolume(response.Volume), nil
}
