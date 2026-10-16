package placement

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

type managedUpdateAuthority interface {
	authority.ManagedUpdateStore
	ReadPlacementIntent(context.Context, string, string) (authority.LogEntry, error)
}

// PrepareManagedUpdate verifies both currently serving members, the admitted
// candidate, retained volume profile, and exact placement before recording the
// signed request in R3. The final authority callback repeats those checks while
// the workload gate and stream-sequence CAS fence are held.
func (controller *Controller) PrepareManagedUpdate(ctx context.Context,
	record authority.ManagedUpdateRecord,
) (uint64, error) {
	if controller == nil || ctx == nil || ctx.Err() != nil {
		return 0, errors.New("managed update requires a live placement controller")
	}
	if err := record.Validate(); err != nil || record.Phase != authority.ManagedUpdatePrepared {
		return 0, errors.New("managed update admission requires a valid signed Prepare record")
	}
	reader, ok := controller.fencer.(managedUpdateAuthority)
	if !ok {
		return 0, errors.New("placement authority lacks managed update and exact placement history")
	}
	entries, err := reader.ReadManagedUpdateOperation(ctx, record.DatabaseID, record.PartitionID, record.OperationID)
	if err == nil {
		for _, entry := range entries {
			if entry.SubjectKey != record.DatabaseID+"."+record.PartitionID+"."+record.OperationID+"."+string(record.Phase) {
				continue
			}
			payload, marshalErr := json.Marshal(record, json.Deterministic(true))
			if marshalErr != nil {
				return 0, marshalErr
			}
			if bytes.Equal(entry.Payload, payload) {
				return entry.Sequence, nil
			}
			return 0, authority.ErrOperationConflict
		}
	} else if !errors.Is(err, authority.ErrNotFound) {
		return 0, err
	}
	intent, err := managedUpdateIntentForRecord(record, controller.config.Cell)
	if err != nil {
		return 0, err
	}
	epoch := intent.AuthorityEpoch
	if err := controller.verifyManagedUpdateBaseline(ctx, intent, record, epoch); err != nil {
		return 0, err
	}
	// A new operation follows the partition's latest terminal outcome; the
	// authority rejects it while an earlier operation is still prepared.
	var previous uint64
	if latest, err := reader.ReadManagedUpdate(ctx, record.DatabaseID, record.PartitionID); err == nil {
		previous = latest.Sequence
	} else if !errors.Is(err, authority.ErrNotFound) {
		return 0, err
	}
	return reader.CommitManagedUpdate(ctx, epoch, record, previous, func(verifyCtx context.Context) error {
		return controller.verifyManagedUpdateBaselineAtAuthorityCommit(verifyCtx, intent, record, epoch)
	})
}

func managedUpdateIntentForRecord(record authority.ManagedUpdateRecord, cell string) (ManagedUpdateIntent, error) {
	if record.Phase != authority.ManagedUpdatePrepared {
		return ManagedUpdateIntent{}, errors.New("managed update record is not a Prepare phase")
	}
	key := record.DatabaseID + "." + record.PartitionID + "." + record.OperationID + "." + string(record.Phase)
	payload, err := json.Marshal(record, json.Deterministic(true))
	if err != nil {
		return ManagedUpdateIntent{}, err
	}
	var envelope protocol.Envelope
	if err := protocol.DecodeStrict(record.SignedRequest, &envelope, protocol.MaxPayloadBytes+4096); err != nil {
		return ManagedUpdateIntent{}, err
	}
	entry := authority.LogEntry{Kind: authority.MutationManagedUpdate, SubjectKey: key,
		OperationID: record.OperationID, Epoch: envelope.Epoch, Payload: payload}
	_, intent, _, err := decodeManagedUpdateRequest(entry, cell)
	return intent, err
}

func (controller *Controller) verifyManagedUpdateBaseline(ctx context.Context,
	update ManagedUpdateIntent, record authority.ManagedUpdateRecord, epoch uint64,
) error {
	return controller.verifyManagedUpdateBaselineChecked(ctx, update, record, epoch, true)
}

func (controller *Controller) verifyManagedUpdateBaselineAtAuthorityCommit(ctx context.Context,
	update ManagedUpdateIntent, record authority.ManagedUpdateRecord, epoch uint64,
) error {
	// CommitManagedUpdate owns the final lease and sequence fence while this
	// verifier runs, so it must not reenter Runtime.Guard.
	return controller.verifyManagedUpdateBaselineChecked(ctx, update, record, epoch, false)
}

func (controller *Controller) verifyManagedUpdateBaselineChecked(ctx context.Context,
	update ManagedUpdateIntent, record authority.ManagedUpdateRecord, epoch uint64, guardAuthority bool,
) error {
	if guardAuthority {
		if err := controller.guard(ctx, epoch); err != nil {
			return err
		}
	}
	if update.Validate() != nil || update.Cell != controller.config.Cell || update.Role != controller.config.MemberRole ||
		update.Environment != controller.config.Environment || record.Cell != update.Cell ||
		record.DatabaseID != update.DatabaseID || record.PartitionID != update.PartitionID ||
		record.OperationID != update.OperationID || record.PlacementGeneration != update.PlacementGeneration ||
		record.PlacementPayloadDigest != update.PlacementPayloadDigest || record.PlacementSequence != update.PlacementSequence ||
		record.CanarySeatID != update.CanarySeatID || record.CanaryDesiredGeneration != update.CanaryDesiredGeneration ||
		record.OldArtifactDigest != update.OldArtifactDigest || record.CandidateArtifactDigest != update.CandidateArtifactDigest ||
		record.CandidateManifestDigest != update.CandidateManifestDigest || record.CandidateSourceDigest != update.CandidateSourceDigest {
		return errors.New("managed update request and authority record differ from placement policy")
	}
	profileDigest, err := update.DurabilityProfile.Digest()
	if err != nil || record.DurabilityProfileSHA256 != profileDigest {
		return errors.New("managed update authority record has a different durability profile digest")
	}
	if _, err := controller.store.ReadTerminalIntent(ctx, update.DatabaseID, update.PartitionID); err == nil {
		return authority.ErrFenced
	} else if !errors.Is(err, authority.ErrNotFound) {
		return err
	}
	reader, ok := controller.fencer.(managedUpdateAuthority)
	if !ok {
		return errors.New("managed update verifier lacks exact authority history")
	}
	placementEntry, err := reader.ReadPlacementIntent(ctx, update.DatabaseID, update.PartitionID)
	if err != nil {
		return err
	}
	intent, err := DecodeCommittedIntent(placementEntry.Payload)
	if err != nil || placementEntry.Kind != authority.MutationPlacementIntent ||
		placementEntry.SubjectKey != update.DatabaseID+"."+update.PartitionID ||
		placementEntry.Sequence != update.PlacementSequence || placementEntry.OperationID != intent.OperationID() ||
		intent.Generation != update.PlacementGeneration || intent.PayloadDigest() != update.PlacementPayloadDigest ||
		intent.DatabaseID != update.DatabaseID || intent.PartitionID != update.PartitionID ||
		intent.SchemaVersion != IntentSchemaVersion || len(intent.ActiveRegions) != 1 ||
		intent.ActiveRegions[0] != controller.config.Region {
		return errors.New("managed update does not match the exact immutable placement record")
	}
	candidate, err := controller.resolveArtifact(ctx, update.CandidateArtifactDigest, update.Role, update.Environment)
	if err != nil || candidate.Digest != update.CandidateArtifactDigest ||
		candidate.ManifestDigest != update.CandidateManifestDigest || candidate.SourceDigest != update.CandidateSourceDigest {
		return errors.New("managed update candidate bytes, manifest, or source admission changed")
	}
	if err := controller.refuseKnownBad(ctx, update.CandidateArtifactDigest); err != nil {
		return err
	}
	seats, err := controller.localSeats(intent)
	if err != nil {
		return err
	}
	members, err := controller.store.ListMembers(ctx, update.DatabaseID, update.PartitionID)
	if err != nil {
		return err
	}
	if len(seats) != 2 || len(members) != len(seats) || len(update.Seats) != len(seats) {
		return errors.New("managed update requires exactly two durable local placement seats")
	}
	memberByID := make(map[string]VersionedMemberState, len(members))
	for _, member := range members {
		state := member.State
		if member.Revision == 0 || state.Validate() != nil || state.DatabaseID != update.DatabaseID ||
			state.PartitionID != update.PartitionID || state.ManagedRuntimeTarget.Phase == ManagedUpdateSeatPrepared {
			return errors.New("managed update found invalid seat state or an unfinished update")
		}
		if _, exists := memberByID[state.MemberID]; exists {
			return errors.New("managed update found duplicate placement member state")
		}
		memberByID[state.MemberID] = member
	}
	instances, err := controller.fleet.Observe(ctx)
	if err != nil {
		return fmt.Errorf("observe current managed OCI hosts: %w", err)
	}
	statuses, err := controller.hosts.ListHosts(ctx)
	if err != nil {
		return fmt.Errorf("read current host registrations and sessions: %w", err)
	}
	statusByNode := make(map[string]host.HostStatus, len(statuses))
	for _, status := range statuses {
		if _, exists := statusByNode[status.Registration.Node]; exists {
			return errors.New("managed update found duplicate host registrations")
		}
		statusByNode[status.Registration.Node] = status
	}
	desiredRows, err := controller.hosts.ListDesired(ctx, controller.config.MemberRole)
	if err != nil {
		return err
	}
	desiredByNode := make(map[string]host.Desired, len(desiredRows))
	for _, desired := range desiredRows {
		if _, exists := desiredByNode[desired.Node]; exists {
			return errors.New("managed update found duplicate desired state for a host")
		}
		desiredByNode[desired.Node] = desired
	}
	seatPins := make(map[string]ManagedUpdateSeat, len(update.Seats))
	for _, seat := range update.Seats {
		seatPins[seat.SeatID] = seat
	}
	seenSeats := make(map[string]struct{}, len(seats))
	for _, seat := range seats {
		versioned, exists := memberByID[seat.MemberID]
		if !exists {
			return fmt.Errorf("managed update seat %s has no durable member state", seat.MemberID)
		}
		state := versioned.State
		provided, exists := seatPins[seat.MemberID]
		canary := seat.MemberID == update.CanarySeatID
		rollback := canary && managedUpdateRollsBackHeld(update, state)
		effective := state.EffectiveRuntimeManifest().ArtifactDigest
		if !exists || !managedUpdateSeatMatches(provided, state) ||
			state.Stage != StageServing && !rollback ||
			state.ManagedRuntimeTarget.Phase == ManagedUpdateSeatHeld && !rollback ||
			state.SchemaVersion != managedUpdateMemberStateSchemaVersion ||
			provided.OCIOwner != controller.config.ManagedOwner ||
			provided.OCIFleetGeneration != controller.config.FleetGeneration ||
			canary && effective != update.OldArtifactDigest ||
			effective != update.OldArtifactDigest && effective != update.CandidateArtifactDigest ||
			state.DesiredGeneration != provided.DesiredGeneration {
			return fmt.Errorf("managed update seat %s no longer matches its signed serving predecessor", seat.MemberID)
		}
		if err := managedUpdateDurabilityMatches(update.DurabilityProfile, state); err != nil {
			return err
		}
		instanceCount := 0
		var instance oci.Instance
		for _, observed := range instances {
			if observed.ID != state.InstanceID && observed.Node != state.HostNode {
				continue
			}
			instance = observed
			instanceCount++
		}
		if instanceCount != 1 || controller.validateObservedInstance(instance, state, seat) != nil {
			return fmt.Errorf("managed update seat %s lacks its exact current OCI host", seat.MemberID)
		}
		attachment, attached := observedAttachment(instance, state)
		if !attached || !validObservedAttachment(attachment) || attachment.Device != state.AttachmentDevice ||
			attachment.ETag != state.AttachmentETag || attachment.ID != provided.AttachmentID {
			return fmt.Errorf("managed update seat %s lacks its exact attached retained volume", seat.MemberID)
		}
		status, admitted := controller.admittedHost(intent, state, instance, statusByNode)
		if !admitted || status.Registration.Generation != state.HostGeneration ||
			!rollback && !controller.hasServingReport(intent, state, instance, status) {
			return fmt.Errorf("managed update seat %s lacks a fresh current-session serving proof", seat.MemberID)
		}
		want, err := controller.memberDesired(epoch, intent, state, seat)
		if err != nil {
			return err
		}
		current, exists := desiredByNode[state.HostNode]
		if !exists || !sameManagedDesired(current, want) || current.Generation != state.DesiredGeneration ||
			current.Digest != effective {
			return fmt.Errorf("managed update seat %s desired state differs from its exact predecessor", seat.MemberID)
		}
		seenSeats[seat.MemberID] = struct{}{}
	}
	if len(seenSeats) != len(seats) || len(seatPins) != len(seats) || seatPins[update.CanarySeatID].DesiredGeneration+1 != update.CanaryDesiredGeneration {
		return errors.New("managed update signed seat set does not match the two continuing members")
	}
	return nil
}

// ManagedUpdateSeatFor returns the signed predecessor pins an update must
// carry for one durable seat: what the seat runs now and where.
func ManagedUpdateSeatFor(state MemberState, owner string, fleetGeneration uint64) ManagedUpdateSeat {
	return ManagedUpdateSeat{
		SeatID: state.MemberID, Region: state.Region, MemberID: state.CanonicalRosterRow.MemberID,
		Incarnation: state.CanonicalRosterRow.Incarnation, TLSLeafSHA256: state.CanonicalRosterRow.TLSLeafSHA256,
		RuntimeManifestDigest: state.RuntimeManifestDigest, HostNode: state.HostNode,
		HostGeneration: state.HostGeneration, HostAttempt: state.HostAttempt,
		OCIInstanceID: state.InstanceID, OCIOwner: owner, OCIFleetGeneration: fleetGeneration,
		CreateKey: state.CreateKey, VolumeID: state.VolumeID, AttachmentID: state.AttachmentID,
		AttachmentETag: state.AttachmentETag, AttachmentDevice: state.AttachmentDevice,
		DesiredGeneration: state.DesiredGeneration, ArtifactDigest: state.EffectiveRuntimeManifest().ArtifactDigest,
	}
}

// managedUpdateRollsBackHeld reports whether update returns a seat whose
// candidate was held back to the exact artifact and source it replaced. A
// held rollback is excluded: its predecessor is the candidate that failed
// first, and returning to it would re-deploy a known-bad release.
func managedUpdateRollsBackHeld(update ManagedUpdateIntent, state MemberState) bool {
	target := state.ManagedRuntimeTarget
	predecessor := state.PredecessorState().RuntimeManifest
	return target.Phase == ManagedUpdateSeatHeld && !target.RollbackOfHeld && update.CanarySeatID == state.MemberID &&
		update.OldArtifactDigest == target.ArtifactDigest &&
		update.CandidateArtifactDigest == predecessor.ArtifactDigest &&
		update.CandidateSourceDigest == predecessor.SourceDigest &&
		(state.Stage == StagePreparedDesired || state.Stage == StageAwaitingHealthy)
}

// refuseKnownBad enforces the cell's durable known-bad list in admission, so
// a candidate a rollout rolled back is refused here even when the caller's
// own list does not name it. A read failure refuses the update: admission
// fails closed.
func (controller *Controller) refuseKnownBad(ctx context.Context, digest string) error {
	if controller.config.KnownBad == nil {
		return nil
	}
	bad, err := controller.config.KnownBad.IsKnownBad(ctx, digest)
	if err != nil {
		return fmt.Errorf("read the cell known-bad release list: %w", err)
	}
	if bad {
		return fmt.Errorf("%w: %s", ErrKnownBadCandidate, digest)
	}
	return nil
}

func managedUpdateSeatMatches(seat ManagedUpdateSeat, state MemberState) bool {
	return seat.SeatID == state.MemberID && seat.Region == state.Region &&
		seat.MemberID == state.CanonicalRosterRow.MemberID && seat.Incarnation == state.CanonicalRosterRow.Incarnation &&
		seat.TLSLeafSHA256 == state.CanonicalRosterRow.TLSLeafSHA256 &&
		seat.RuntimeManifestDigest == state.RuntimeManifestDigest && seat.HostNode == state.HostNode &&
		seat.HostGeneration == state.HostGeneration && seat.HostAttempt == state.HostAttempt &&
		seat.OCIInstanceID == state.InstanceID && seat.CreateKey == state.CreateKey &&
		seat.VolumeID == state.VolumeID && seat.AttachmentID == state.AttachmentID &&
		seat.AttachmentETag == state.AttachmentETag && seat.AttachmentDevice == state.AttachmentDevice &&
		seat.DesiredGeneration == state.DesiredGeneration &&
		seat.ArtifactDigest == state.EffectiveRuntimeManifest().ArtifactDigest
}

func managedUpdateDurabilityMatches(profile ManagedUpdateDurabilityProfile, state MemberState) error {
	if profile.Region != state.Region || profile.SQLSchemaBundleSHA256 != state.RuntimeManifest.SQLSchemaBundleSHA256 ||
		profile.LiveS3ConfigSHA256 != state.RuntimeManifest.LiveS3ConfigSHA256 ||
		profile.LiveS3TargetSHA256 != state.RuntimeManifest.LiveS3TargetSHA256 ||
		profile.LiveS3Credential != state.RuntimeManifest.LiveS3Credential {
		return errors.New("managed update durability profile differs from immutable runtime data pins")
	}
	for _, volume := range profile.Volumes {
		if volume.SeatID == state.MemberID && volume.VolumeID == state.VolumeID &&
			volume.FileSystemUUID == state.RuntimeManifest.FileSystemUUID &&
			volume.FileSystemType == state.RuntimeManifest.FileSystemType {
			return nil
		}
	}
	return fmt.Errorf("managed update durability profile omits retained volume for seat %s", state.MemberID)
}
