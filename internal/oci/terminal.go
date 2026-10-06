package oci

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
)

const (
	actionTerminalTerminate  = "terminal-terminate"
	actionTerminalBootDelete = "terminal-boot-delete"
	actionTerminalDataDelete = "terminal-data-delete"
)

// DiscoverTerminalTargets resolves only positively journaled resources. A
// missing create result is never inferred from an empty OCI list when a create
// attempt was recorded; a late provider response could still appear.
func (f *fleet) DiscoverTerminalTargets(ctx context.Context, intent authority.TerminalIntent) ([]authority.TerminalTarget, error) {
	if err := f.validateTerminalScope(intent); err != nil {
		return nil, err
	}
	instances, err := f.provider.ListInstances(ctx, f.config.CompartmentID)
	if err != nil {
		return nil, fmt.Errorf("list terminal instance inventory: %w", err)
	}
	volumes, err := f.provider.ListVolumes(ctx, f.config.CompartmentID, f.config.AvailabilityDomain)
	if err != nil {
		return nil, fmt.Errorf("list terminal data inventory: %w", err)
	}
	if len(instances) > maxProviderItems || len(volumes) > maxProviderItems {
		return nil, errors.New("terminal OCI inventory exceeds safety bound")
	}
	operations, err := f.journal.ListOperations(ctx)
	if err != nil {
		return nil, err
	}
	targets := make([]authority.TerminalTarget, len(intent.Targets))
	allowedHosts := make(map[string]bool, len(intent.Targets))
	allowedData := make(map[string]bool, len(intent.Targets))
	for i, target := range intent.Targets {
		if !terminalDataKeyMatches(intent, target) {
			return nil, fmt.Errorf("%w: seat %s has a data create key outside its workload", ErrForeignResource, target.SeatID)
		}
		allowedHosts[target.HostCreateKey] = true
		allowedData[target.DataCreateKey] = true
		resolved := target
		resolved.InstanceID, resolved.BootVolumeID, resolved.DataVolumeID = "", "", ""
		launch, launchResult, launchFound, err := f.terminalCreateResult(ctx, actionLaunch, target.HostCreateKey)
		if err != nil {
			return nil, err
		}
		if launchFound {
			descriptor, err := launchIntentDescriptor(launch)
			if err != nil || descriptor.DatabaseID != intent.DatabaseID || descriptor.PartitionID != intent.PartitionID ||
				descriptor.SeatID != target.SeatID || descriptor.IntentGeneration != intent.PlacementGeneration ||
				descriptor.IntentPayloadDigest != intent.PlacementPayloadDigest {
				return nil, fmt.Errorf("%w: host launch differs from signed terminal placement", ErrHostBootBindingMismatch)
			}
			resolved.InstanceID = launchResult.ResourceID
			binding, found, err := f.journal.GetBootBinding(ctx, resolved.InstanceID)
			if err != nil {
				return nil, err
			}
			if !found || !f.terminalBootBindingMatches(binding, resolved.InstanceID, launch) {
				return nil, fmt.Errorf("%w: host %s lacks its active-instance boot binding", ErrForeignResource, resolved.InstanceID)
			}
			resolved.BootVolumeID = binding.BootVolumeID
		}
		volumeIntent, volumeResult, volumeFound, err := f.terminalCreateResult(ctx, actionVolumeCreate, target.DataCreateKey)
		if err != nil {
			return nil, err
		}
		if volumeFound {
			if volumeIntent.AvailabilityDomain != f.config.AvailabilityDomain || volumeIntent.SizeGB < minRetainedVolumeSizeGB ||
				volumeIntent.SizeGB > f.config.MaxDataVolumeGB {
				return nil, fmt.Errorf("%w: terminal data create profile differs from fleet", ErrForeignResource)
			}
			resolved.DataVolumeID = volumeResult.ResourceID
		}
		if target.InstanceID != "" && target.InstanceID != resolved.InstanceID ||
			target.BootVolumeID != "" && target.BootVolumeID != resolved.BootVolumeID ||
			target.DataVolumeID != "" && target.DataVolumeID != resolved.DataVolumeID {
			return nil, fmt.Errorf("%w: seat %s differs from durable terminal inventory", ErrForeignResource, target.SeatID)
		}
		if err := checkTerminalListed(instances, target.HostCreateKey, resolved.InstanceID); err != nil {
			return nil, err
		}
		if err := checkTerminalListed(volumes, target.DataCreateKey, resolved.DataVolumeID); err != nil {
			return nil, err
		}
		targets[i] = resolved
	}
	for _, record := range operations {
		op := record.Intent
		if op.Region != f.config.Region || op.Generation != f.config.Generation || op.Owner != f.config.Owner {
			continue
		}
		if op.Action == actionLaunch {
			descriptor, err := launchIntentDescriptor(op)
			if err != nil {
				return nil, err
			}
			if descriptor.DatabaseID == intent.DatabaseID && descriptor.PartitionID == intent.PartitionID && !allowedHosts[op.CreateKey] {
				return nil, fmt.Errorf("%w: workload has an unlisted host create attempt", ErrForeignResource)
			}
		}
		if (allowedHosts[op.CreateKey] || allowedData[op.CreateKey] || terminalOperationTouches(op, targets)) &&
			op.Action != actionTerminalTerminate && op.Action != actionTerminalBootDelete && op.Action != actionTerminalDataDelete &&
			(record.Result.RecordedAt.IsZero() || record.Result.Unknown) && !f.resizeSettled(ctx, op, volumes) &&
			!f.detachSettled(ctx, op) {
			return nil, fmt.Errorf("%w: prior OCI operation %s remains unsettled", ErrOutcomeUnknown, op.Action)
		}
	}
	return targets, nil
}

// resizeSettledByObservation reports a grow-only resize whose outcome no
// longer matters: the listed volume is already at or past its target (the
// resize landed or a larger one superseded it), or the volume is gone and no
// resize can land on it any more. Any other unsettled resize stays unknown.
func resizeSettledByObservation(op OperationIntent, volumes []CloudVolume) bool {
	if op.Action != actionVolumeResize || op.VolumeID == "" {
		return false
	}
	for _, volume := range volumes {
		if volume.ID == op.VolumeID {
			return volume.SizeGB >= op.SizeGB || volume.LifecycleState == "TERMINATED"
		}
	}
	return true
}

// resizeSettled extends resizeSettledByObservation with an exact read: a
// resize below its target whose If-Match ETag no longer matches the volume
// can never land, so its outcome is settled too. A read failure keeps the
// resize unsettled.
func (f *fleet) resizeSettled(ctx context.Context, op OperationIntent, volumes []CloudVolume) bool {
	if resizeSettledByObservation(op, volumes) {
		return true
	}
	if op.Action != actionVolumeResize || op.ExpectedETag == "" {
		return false
	}
	current, err := f.provider.GetVolume(ctx, op.VolumeID)
	if err != nil {
		return isNotFound(err)
	}
	return current.SizeGB >= op.SizeGB || current.ETag != "" && current.ETag != op.ExpectedETag
}

func (f *fleet) VerifyTerminalInventorySettled(ctx context.Context, intent authority.TerminalIntent) error {
	resolved, err := f.DiscoverTerminalTargets(ctx, intent)
	if err != nil {
		return err
	}
	for i, target := range resolved {
		if target != intent.Targets[i] {
			return fmt.Errorf("%w: seat %s has an omitted or changed resource ID", ErrForeignResource, target.SeatID)
		}
		if target.InstanceID != "" {
			cloud, err := f.provider.GetInstance(ctx, target.InstanceID)
			if err != nil && !isNotFound(err) {
				return err
			}
			if err == nil {
				if cloud.ID != target.InstanceID || cloud.CompartmentID != f.config.CompartmentID {
					return ErrForeignResource
				}
				if cloud.LifecycleState != "TERMINATED" {
					if _, _, err := f.reobserveLaunch(ctx, target.InstanceID, false); err != nil {
						return fmt.Errorf("%w: terminal instance has no positive ownership: %v", ErrForeignResource, err)
					}
				}
			}
			image, err := f.terminalBootImage(ctx, target)
			if err != nil {
				return err
			}
			boot, err := f.provider.GetBootVolume(ctx, target.BootVolumeID)
			if err != nil && !isNotFound(err) {
				return err
			}
			if err == nil && !f.terminalBootMatches(boot, target.BootVolumeID, image) {
				return fmt.Errorf("%w: terminal boot volume differs from fleet pins", ErrForeignResource)
			}
		}
		if target.DataVolumeID != "" {
			if _, _, err := f.reobserveVolume(ctx, target.DataVolumeID); err != nil && !isNotFound(err) {
				return err
			}
		}
	}
	return nil
}

func (f *fleet) ReconcileTerminal(ctx context.Context, intent authority.TerminalIntent, markerSeq uint64) (TerminalStatus, error) {
	status := TerminalStatus{Phase: "pending"}
	if err := f.requireTerminalMarker(ctx, intent, markerSeq); err != nil {
		return status, err
	}
	if err := f.VerifyTerminalInventorySettled(ctx, intent); err != nil {
		return status, err
	}
	for _, target := range intent.Targets {
		if target.InstanceID != "" {
			settled, err := f.reconcileTerminalInstance(ctx, intent, markerSeq, target)
			if err != nil {
				return status, err
			}
			if !settled {
				status.Pending = append(status.Pending, target.InstanceID)
				continue
			}
			settled, err = f.reconcileTerminalBoot(ctx, intent, markerSeq, target)
			if err != nil {
				return status, err
			}
			if !settled {
				status.Pending = append(status.Pending, target.BootVolumeID)
			}
		}
		if target.DataVolumeID != "" {
			settled, err := f.reconcileTerminalData(ctx, intent, markerSeq, target)
			if err != nil {
				return status, err
			}
			if !settled {
				status.Pending = append(status.Pending, target.DataVolumeID)
			}
		}
	}
	if len(status.Pending) == 0 {
		status.Phase = "complete"
	}
	return status, nil
}

func (f *fleet) validateTerminalScope(intent authority.TerminalIntent) error {
	if err := intent.Validate(); err != nil {
		return err
	}
	if intent.Region != string(f.config.Region) || intent.Cell != strings.ToLower(string(f.config.Region)) ||
		intent.Owner != f.config.Owner || intent.CompartmentID != f.config.CompartmentID ||
		intent.FleetGeneration != f.config.Generation {
		return fmt.Errorf("%w: terminal intent differs from pinned OCI fleet", ErrForeignResource)
	}
	permanentSeat := map[Region]string{RegionGRU: "permanent-a", RegionSFO: "permanent-b", RegionFRA: "permanent-c"}[f.config.Region]
	elasticSeat := "elastic-" + strings.ToLower(string(f.config.Region))
	if len(intent.Targets) != 2 || intent.Targets[0].SeatID != permanentSeat || intent.Targets[1].SeatID != elasticSeat {
		return fmt.Errorf("%w: terminal intent must pin the two ordered workload seats", ErrForeignResource)
	}
	return nil
}

func (f *fleet) terminalCreateResult(ctx context.Context, action, key string) (OperationIntent, OperationResult, bool, error) {
	op, exists, err := f.journal.GetOperation(ctx, OperationScope{Action: action, Key: key, Region: f.config.Region,
		Generation: f.config.Generation, Owner: f.config.Owner})
	if err != nil || !exists {
		return op, OperationResult{}, false, err
	}
	result, found, err := f.journal.GetResult(ctx, op)
	if err != nil {
		return op, result, false, err
	}
	if !found || result.Unknown || result.ResourceID == "" {
		return op, result, false, fmt.Errorf("%w: %s %s has no confirmed create result", ErrOutcomeUnknown, action, key)
	}
	return op, result, true, nil
}

func terminalDataKeyMatches(intent authority.TerminalIntent, target authority.TerminalTarget) bool {
	return target.DataCreateKey == terminalDigestToken("tv", intent.DatabaseID, intent.PartitionID, intent.Region, target.SeatID)
}

func terminalOperationTouches(op OperationIntent, targets []authority.TerminalTarget) bool {
	for _, target := range targets {
		if op.ResourceID != "" && (op.ResourceID == target.InstanceID || op.ResourceID == target.DataVolumeID) ||
			op.VolumeID != "" && op.VolumeID == target.DataVolumeID {
			return true
		}
	}
	return false
}

func checkTerminalListed[T CloudInstance | CloudVolume](items []T, key, expected string) error {
	count := 0
	for _, item := range items {
		var id string
		var tags map[string]string
		switch value := any(item).(type) {
		case CloudInstance:
			id, tags = value.ID, value.FreeformTags
		case CloudVolume:
			id, tags = value.ID, value.FreeformTags
		}
		if tags[tagCreateKey] != key {
			continue
		}
		count++
		if id != expected {
			return fmt.Errorf("%w: create key %s resolves to an unpinned resource", ErrForeignResource, key)
		}
	}
	if count > 1 {
		return ErrDuplicateCreateKey
	}
	return nil
}

// terminalBootBindingMatches binds a boot binding to the host's launch,
// image included. Teardown trusts these journaled records, not the current
// allow-list, so a revoked image never strands its hosts' cleanup.
func (f *fleet) terminalBootBindingMatches(binding BootBinding, instanceID string, launch OperationIntent) bool {
	return binding.InstanceID == instanceID && binding.Region == f.config.Region && binding.Generation == f.config.Generation &&
		binding.Owner == f.config.Owner && binding.CreateKey == launch.CreateKey &&
		binding.CompartmentID == f.config.CompartmentID && binding.AvailabilityDomain == f.config.AvailabilityDomain &&
		binding.ImageID == launch.ImageID && binding.SizeGB == int64(f.config.BootVolumeGB) &&
		binding.VPUsPerGB == int64(f.config.BootVolumeVPUsPerGB)
}

// terminalBootImage is the image of target's journaled boot binding.
func (f *fleet) terminalBootImage(ctx context.Context, target authority.TerminalTarget) (string, error) {
	binding, found, err := f.journal.GetBootBinding(ctx, target.InstanceID)
	if err != nil {
		return "", fmt.Errorf("read OCI host boot binding: %w", err)
	}
	if !found || binding.BootVolumeID != target.BootVolumeID || binding.ImageID == "" {
		return "", fmt.Errorf("%w: boot volume %s lacks its journaled boot binding", ErrForeignResource, target.BootVolumeID)
	}
	return binding.ImageID, nil
}

func (f *fleet) terminalBootMatches(boot CloudBootVolume, id, imageID string) bool {
	return boot.ID == id && boot.CompartmentID == f.config.CompartmentID &&
		boot.AvailabilityDomain == f.config.AvailabilityDomain && boot.ImageID == imageID &&
		boot.SizeGB == int64(f.config.BootVolumeGB) && boot.VPUsPerGB == int64(f.config.BootVolumeVPUsPerGB) &&
		boot.ETag != ""
}

func (f *fleet) requireTerminalMarker(ctx context.Context, intent authority.TerminalIntent, sequence uint64) error {
	if sequence == 0 {
		return errors.New("terminal reconciliation requires an accepted marker sequence")
	}
	if err := f.validateTerminalScope(intent); err != nil {
		return err
	}
	reader, ok := f.fencer.(authority.TerminalIntentReader)
	if !ok {
		return errors.New("OCI authority cannot verify the terminal marker")
	}
	entry, err := reader.ReadTerminalIntent(ctx, intent.DatabaseID, intent.PartitionID)
	if err != nil {
		return err
	}
	wire, err := json.Marshal(intent, json.Deterministic(true))
	if err != nil || entry.Kind != authority.MutationTerminalIntent || entry.Sequence != sequence ||
		entry.SubjectKey != intent.DatabaseID+"."+intent.PartitionID ||
		entry.OperationID != intent.OperationID || !bytes.Equal(entry.Payload, wire) {
		return errors.New("current terminal marker differs from accepted exact intent")
	}
	epoch, err := f.currentEpoch()
	if err != nil {
		return err
	}
	return f.guard(ctx, epoch)
}

func (f *fleet) terminalMutation(ctx context.Context, intent authority.TerminalIntent, markerSeq uint64,
	action, resourceID, createKey, etag string, mutate func() error, observe func() (bool, error),
) (bool, error) {
	key := digest(intent.OperationID, action, resourceID)
	op := f.intent(action, key, resourceID, createKey, etag, "", "")
	prior, found, err := f.journal.GetOperation(ctx, OperationScope{Action: action, Key: key, Region: f.config.Region,
		Generation: f.config.Generation, Owner: f.config.Owner})
	if err != nil {
		return false, err
	}
	if found {
		if prior.ResourceID != resourceID || prior.CreateKey != createKey || prior.ExpectedETag != etag {
			return false, ErrStaleETag
		}
		op = prior
		result, hasResult, err := f.journal.GetResult(ctx, op)
		if err != nil {
			return false, err
		}
		if hasResult && !result.Unknown {
			return observe()
		}
		// A prior request may have succeeded despite loss of its response. Only
		// readback may settle it; issuing a second destructive call is unsafe.
		settled, err := observe()
		if err != nil || !settled {
			return false, errors.Join(ErrOutcomeUnknown, err)
		}
		return true, f.terminalRecordResult(ctx, intent, markerSeq, op)
	}
	if err := f.requireTerminalMarker(ctx, intent, markerSeq); err != nil {
		return false, err
	}
	epoch, err := f.currentEpoch()
	if err != nil {
		return false, err
	}
	if err := f.recordIntent(ctx, epoch, op); err != nil {
		return false, err
	}
	if err := f.requireTerminalMarker(ctx, intent, markerSeq); err != nil {
		return false, err
	}
	callErr := mutate()
	settled, readErr := observe()
	if readErr != nil {
		return false, errors.Join(ErrOutcomeUnknown, callErr, readErr)
	}
	if !settled {
		if callErr != nil {
			return false, errors.Join(ErrOutcomeUnknown, callErr)
		}
		return false, nil
	}
	return true, f.terminalRecordResult(ctx, intent, markerSeq, op)
}

func (f *fleet) terminalRecordResult(ctx context.Context, intent authority.TerminalIntent, seq uint64, op OperationIntent) error {
	if err := f.requireTerminalMarker(ctx, intent, seq); err != nil {
		return err
	}
	epoch, err := f.currentEpoch()
	if err != nil {
		return err
	}
	return f.recordResult(ctx, epoch, OperationResult{Intent: op, ResourceID: op.ResourceID, ETag: op.ExpectedETag})
}

func terminalDigestToken(prefix string, values ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(values, "\x00")))
	return prefix + "-" + hex.EncodeToString(sum[:24])
}

// InspectTerminalStatus reports provider readbacks without advancing teardown.
func (f *fleet) InspectTerminalStatus(ctx context.Context, intent authority.TerminalIntent) (TerminalStatus, error) {
	status := TerminalStatus{Phase: TerminalPhasePending}
	if err := f.VerifyTerminalInventorySettled(ctx, intent); err != nil {
		status.Phase = TerminalPhaseHeld
		return status, err
	}
	for _, target := range intent.Targets {
		if target.InstanceID != "" {
			settled, err := f.terminalInstanceSettled(ctx, target.InstanceID)
			if err != nil {
				status.Phase = TerminalPhaseHeld
				return status, err
			}
			if !settled {
				status.Pending = append(status.Pending, target.InstanceID)
			} else if err := f.requireTerminalResultSettled(ctx, intent, actionTerminalTerminate, target.InstanceID); err != nil {
				status.Phase = TerminalPhaseHeld
				return status, err
			}
			settled, err = f.terminalBootSettled(ctx, target)
			if err != nil {
				status.Phase = TerminalPhaseHeld
				return status, err
			}
			if !settled {
				status.Pending = append(status.Pending, target.BootVolumeID)
			} else if err := f.requireTerminalResultSettled(ctx, intent, actionTerminalBootDelete, target.BootVolumeID); err != nil {
				status.Phase = TerminalPhaseHeld
				return status, err
			}
		}
		if target.DataVolumeID != "" {
			settled, err := f.terminalDataSettled(ctx, target.DataVolumeID)
			if err != nil {
				status.Phase = TerminalPhaseHeld
				return status, err
			}
			if !settled {
				status.Pending = append(status.Pending, target.DataVolumeID)
			} else if err := f.requireTerminalResultSettled(ctx, intent, actionTerminalDataDelete, target.DataVolumeID); err != nil {
				status.Phase = TerminalPhaseHeld
				return status, err
			}
		}
	}
	if len(status.Pending) == 0 {
		status.Phase = TerminalPhaseComplete
	}
	return status, nil
}

func (f *fleet) reconcileTerminalInstance(ctx context.Context, intent authority.TerminalIntent, seq uint64,
	target authority.TerminalTarget,
) (bool, error) {
	settled, err := f.terminalInstanceSettled(ctx, target.InstanceID)
	if err != nil || settled {
		if err != nil {
			return false, err
		}
		return true, f.settleTerminalRecorded(ctx, intent, seq, actionTerminalTerminate, target.InstanceID)
	}
	cloud, _, err := f.ownedLaunch(ctx, target.InstanceID, false)
	if err != nil {
		return false, err
	}
	if cloud.LifecycleState == "TERMINATING" || cloud.ETag == "" {
		return false, nil
	}
	return f.terminalMutation(ctx, intent, seq, actionTerminalTerminate, target.InstanceID,
		target.HostCreateKey, cloud.ETag,
		func() error { return f.provider.TerminateTerminalInstance(ctx, target.InstanceID, cloud.ETag) },
		func() (bool, error) { return f.terminalInstanceSettled(ctx, target.InstanceID) })
}

func (f *fleet) reconcileTerminalBoot(ctx context.Context, intent authority.TerminalIntent, seq uint64,
	target authority.TerminalTarget,
) (bool, error) {
	settled, err := f.terminalBootSettled(ctx, target)
	if err != nil || settled {
		if err != nil {
			return false, err
		}
		return true, f.settleTerminalRecorded(ctx, intent, seq, actionTerminalBootDelete, target.BootVolumeID)
	}
	attachments, err := f.provider.ListBootVolumeAttachments(ctx, target.BootVolumeID)
	if err != nil {
		return false, err
	}
	if activeBootAttachments(attachments, target.BootVolumeID) {
		return false, nil
	}
	image, err := f.terminalBootImage(ctx, target)
	if err != nil {
		return false, err
	}
	boot, err := f.provider.GetBootVolume(ctx, target.BootVolumeID)
	if err != nil {
		return false, err
	}
	if !f.terminalBootMatches(boot, target.BootVolumeID, image) {
		return false, ErrForeignResource
	}
	if boot.LifecycleState == "TERMINATING" {
		return false, nil
	}
	return f.terminalMutation(ctx, intent, seq, actionTerminalBootDelete, target.BootVolumeID,
		target.HostCreateKey, boot.ETag,
		func() error { return f.provider.DeleteBootVolume(ctx, target.BootVolumeID, boot.ETag) },
		func() (bool, error) { return f.terminalBootSettled(ctx, target) })
}

func (f *fleet) reconcileTerminalData(ctx context.Context, intent authority.TerminalIntent, seq uint64,
	target authority.TerminalTarget,
) (bool, error) {
	settled, err := f.terminalDataSettled(ctx, target.DataVolumeID)
	if err != nil || settled {
		if err != nil {
			return false, err
		}
		return true, f.settleTerminalRecorded(ctx, intent, seq, actionTerminalDataDelete, target.DataVolumeID)
	}
	attachments, err := f.findVolumeAttachments(ctx, target.DataVolumeID)
	if err != nil {
		return false, err
	}
	if activeDataAttachments(attachments) {
		return false, nil
	}
	volume, err := f.ownedVolume(ctx, target.DataVolumeID)
	if err != nil {
		return false, err
	}
	if volume.ETag == "" {
		return false, ErrStaleETag
	}
	if volume.LifecycleState == "TERMINATING" {
		return false, nil
	}
	return f.terminalMutation(ctx, intent, seq, actionTerminalDataDelete, target.DataVolumeID,
		target.DataCreateKey, volume.ETag,
		func() error { return f.provider.DeleteVolume(ctx, target.DataVolumeID, volume.ETag) },
		func() (bool, error) { return f.terminalDataSettled(ctx, target.DataVolumeID) })
}

func (f *fleet) terminalInstanceSettled(ctx context.Context, id string) (bool, error) {
	cloud, err := f.provider.GetInstance(ctx, id)
	if err != nil && !isNotFound(err) {
		return false, err
	}
	if err == nil {
		if cloud.ID != id || cloud.CompartmentID != f.config.CompartmentID {
			return false, ErrForeignResource
		}
		if cloud.LifecycleState != "TERMINATED" {
			return false, nil
		}
	}
	attachments, err := f.provider.ListVolumeAttachments(ctx, f.config.CompartmentID, id)
	if err != nil {
		return false, err
	}
	for _, attachment := range attachments {
		if attachment.InstanceID == id && attachment.LifecycleState != "DETACHED" && attachment.LifecycleState != "TERMINATED" {
			return false, nil
		}
	}
	return true, nil
}

func (f *fleet) terminalBootSettled(ctx context.Context, target authority.TerminalTarget) (bool, error) {
	id := target.BootVolumeID
	image, err := f.terminalBootImage(ctx, target)
	if err != nil {
		return false, err
	}
	boot, err := f.provider.GetBootVolume(ctx, id)
	if err != nil && !isNotFound(err) {
		return false, err
	}
	if err == nil {
		if !f.terminalBootMatches(boot, id, image) {
			return false, ErrForeignResource
		}
		if boot.LifecycleState != "TERMINATED" {
			return false, nil
		}
	}
	attachments, err := f.provider.ListBootVolumeAttachments(ctx, id)
	if err != nil {
		return false, err
	}
	return !activeBootAttachments(attachments, id), nil
}

func (f *fleet) terminalDataSettled(ctx context.Context, id string) (bool, error) {
	volume, err := f.provider.GetVolume(ctx, id)
	if err != nil && !isNotFound(err) {
		return false, err
	}
	if err == nil {
		if volume.ID != id || volume.CompartmentID != f.config.CompartmentID ||
			volume.AvailabilityDomain != f.config.AvailabilityDomain {
			return false, ErrForeignResource
		}
		if volume.LifecycleState != "TERMINATED" {
			return false, nil
		}
	}
	attachments, err := f.findVolumeAttachments(ctx, id)
	if err != nil {
		return false, err
	}
	return !activeDataAttachments(attachments), nil
}

func activeBootAttachments(attachments []CloudBootAttachment, id string) bool {
	for _, attachment := range attachments {
		if attachment.BootVolumeID == id && attachment.LifecycleState != "DETACHED" && attachment.LifecycleState != "TERMINATED" {
			return true
		}
	}
	return false
}

func activeDataAttachments(attachments []CloudAttachment) bool {
	for _, attachment := range attachments {
		if attachment.LifecycleState != "DETACHED" && attachment.LifecycleState != "TERMINATED" {
			return true
		}
	}
	return false
}

func (f *fleet) settleTerminalRecorded(ctx context.Context, intent authority.TerminalIntent, seq uint64,
	action, id string,
) error {
	op, found, err := f.journal.GetOperation(ctx, OperationScope{Action: action,
		Key: digest(intent.OperationID, action, id), Region: f.config.Region,
		Generation: f.config.Generation, Owner: f.config.Owner})
	if err != nil || !found {
		return err
	}
	if op.ResourceID != id {
		return ErrForeignResource
	}
	result, hasResult, err := f.journal.GetResult(ctx, op)
	if err != nil {
		return err
	}
	if hasResult && !result.Unknown {
		return nil
	}
	return f.terminalRecordResult(ctx, intent, seq, op)
}

func (f *fleet) requireTerminalResultSettled(ctx context.Context, intent authority.TerminalIntent,
	action, id string,
) error {
	op, found, err := f.journal.GetOperation(ctx, OperationScope{Action: action,
		Key: digest(intent.OperationID, action, id), Region: f.config.Region,
		Generation: f.config.Generation, Owner: f.config.Owner})
	if err != nil || !found {
		return err
	}
	if op.ResourceID != id {
		return ErrForeignResource
	}
	result, hasResult, err := f.journal.GetResult(ctx, op)
	if err != nil {
		return err
	}
	if !hasResult || result.Unknown || result.ResourceID != id {
		return fmt.Errorf("%w: terminal %s %s has no durable readback result", ErrOutcomeUnknown, action, id)
	}
	return nil
}
