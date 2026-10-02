package placement

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

const managedUpdateCanaryProofTimeout = 15 * time.Minute

type managedUpdatePlacementReader interface {
	ReadPlacementIntent(context.Context, string, string) (authority.LogEntry, error)
}

func (controller *Controller) managedUpdatePrepareIsCurrent(ctx context.Context, state MemberState) (bool, error) {
	target := state.ManagedRuntimeTarget
	reader, ok := controller.fencer.(authority.ManagedUpdateReader)
	if !ok {
		return false, errors.New("placement authority lacks managed update history")
	}
	entries, err := reader.ReadManagedUpdateOperation(ctx, state.DatabaseID, state.PartitionID, target.OperationID)
	if err != nil {
		if errors.Is(err, authority.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	if len(entries) == 0 {
		return false, nil
	}
	var preparedEntry authority.LogEntry
	for _, entry := range entries {
		if managedUpdatePhaseFromSubject(entry.SubjectKey) == authority.ManagedUpdatePrepared {
			preparedEntry = entry
			break
		}
	}
	if preparedEntry.Kind != authority.MutationManagedUpdate || preparedEntry.Sequence != target.AuthoritySequence ||
		preparedEntry.OperationID != target.OperationID {
		return false, nil
	}
	record, intent, envelope, err := decodeManagedUpdateRequest(preparedEntry, controller.config.Cell)
	if err != nil {
		return false, err
	}
	if record.PlacementGeneration != target.PlacementGeneration ||
		record.PlacementPayloadDigest != target.PlacementPayloadDigest ||
		record.CanarySeatID != target.CanarySeatID ||
		record.CanaryDesiredGeneration != target.DesiredGeneration ||
		record.CandidateArtifactDigest != target.ArtifactDigest ||
		record.CandidateManifestDigest != target.ManifestDigest ||
		record.CandidateSourceDigest != target.SourceDigest ||
		record.SignedRequestSHA256 != target.RequestSHA256 ||
		intent.DatabaseID != state.DatabaseID || intent.PartitionID != state.PartitionID ||
		intent.CanarySeatID != state.MemberID || envelope.Epoch != preparedEntry.Epoch {
		return false, nil
	}
	latest, err := reader.ReadManagedUpdate(ctx, state.DatabaseID, state.PartitionID)
	if err != nil {
		return false, err
	}
	if latest.Kind != authority.MutationManagedUpdate {
		return false, nil
	}
	if latest.OperationID != preparedEntry.OperationID || latest.Sequence != preparedEntry.Sequence {
		// The operation is no longer the latest prepared request, so it stays
		// current only through its own retained canary-serving outcome. Once a
		// later operation follows, the seat must already record that outcome.
		served := false
		for _, entry := range entries {
			if managedUpdatePhaseFromSubject(entry.SubjectKey) != authority.ManagedUpdateCanaryServing {
				continue
			}
			terminal, err := decodeManagedUpdatePhaseRecord(entry, record, authority.ManagedUpdateCanaryServing)
			served = err == nil && terminal.Phase == authority.ManagedUpdateCanaryServing
		}
		if !served || target.Phase != ManagedUpdateSeatPrepared && target.Phase != ManagedUpdateSeatCanaryServing ||
			latest.OperationID != preparedEntry.OperationID && target.Phase != ManagedUpdateSeatCanaryServing {
			return false, nil
		}
	}
	placementReader, ok := controller.fencer.(managedUpdatePlacementReader)
	if !ok {
		return false, errors.New("placement authority lacks exact placement history")
	}
	placementEntry, err := placementReader.ReadPlacementIntent(ctx, state.DatabaseID, state.PartitionID)
	if err != nil {
		return false, err
	}
	if placementEntry.Sequence != record.PlacementSequence {
		return false, nil
	}
	currentIntent, err := DecodeCommittedIntent(placementEntry.Payload)
	if err != nil {
		return false, err
	}
	return currentIntent.Generation == record.PlacementGeneration &&
		currentIntent.PayloadDigest() == record.PlacementPayloadDigest &&
		currentIntent.Generation == intent.PlacementGeneration &&
		currentIntent.PayloadDigest() == intent.PlacementPayloadDigest, nil
}

func (controller *Controller) reconcileManagedUpdate(ctx context.Context, epoch uint64,
	intent Intent, seats []Seat, memberByID map[string]VersionedMemberState,
) (bool, error) {
	reader, ok := controller.fencer.(authority.ManagedUpdateReader)
	if !ok {
		return false, errors.New("placement authority lacks managed update history")
	}
	latest, err := reader.ReadManagedUpdate(ctx, intent.DatabaseID, intent.PartitionID)
	if errors.Is(err, authority.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if latest.Kind != authority.MutationManagedUpdate || latest.Sequence == 0 || latest.OperationID == "" {
		return false, errors.New("managed update authority history is malformed")
	}
	var record authority.ManagedUpdateRecord
	if err := json.Unmarshal(latest.Payload, &record, json.RejectUnknownMembers(true)); err != nil ||
		record.Validate() != nil || record.OperationID != latest.OperationID ||
		record.DatabaseID != intent.DatabaseID || record.PartitionID != intent.PartitionID ||
		managedUpdatePhaseFromSubject(latest.SubjectKey) != record.Phase {
		return false, errors.New("managed update authority phase is corrupt")
	}
	if record.Phase == authority.ManagedUpdateHeld || record.Phase == authority.ManagedUpdateCanaryServing {
		return controller.reconcileManagedUpdateTerminal(ctx, epoch, intent, latest, record, memberByID)
	}
	if record.Phase != authority.ManagedUpdatePrepared {
		return false, errors.New("managed update authority phase is unsupported")
	}
	_, update, _, err := decodeManagedUpdateRequest(latest, controller.config.Cell)
	if err != nil || update.DatabaseID != intent.DatabaseID || update.PartitionID != intent.PartitionID ||
		update.PlacementGeneration != intent.Generation || update.PlacementPayloadDigest != intent.PayloadDigest() {
		return false, errors.New("prepared managed update no longer matches the active placement")
	}
	canary, exists := memberByID[record.CanarySeatID]
	if !exists {
		controller.hold(fmt.Sprintf("managed update %s has no durable canary seat", record.OperationID))
		return false, nil
	}
	state := canary.State
	current := state.ManagedRuntimeTarget
	if current.OperationID == record.OperationID {
		if current.AuthoritySequence != latest.Sequence || current.RequestSHA256 != record.SignedRequestSHA256 ||
			current.ArtifactDigest != record.CandidateArtifactDigest {
			controller.hold(fmt.Sprintf("member %s has a different durable managed canary target", state.MemberID))
		}
		return false, nil
	}
	if current.Phase == ManagedUpdateSeatPrepared {
		controller.hold(fmt.Sprintf("member %s has an unfinished managed canary target", state.MemberID))
		return false, nil
	}
	if err := controller.verifyManagedUpdateBaseline(ctx, update, record, epoch); err != nil {
		controller.hold(fmt.Sprintf("managed update %s baseline changed before its canary write: %v", record.OperationID, err))
		return false, nil
	}
	rollsBackHeld := managedUpdateRollsBackHeld(update, state)
	if state.Stage != StageServing && !rollsBackHeld || state.DesiredGeneration == 0 ||
		state.DesiredGeneration == ^uint64(0) || record.CanaryDesiredGeneration != state.DesiredGeneration+1 {
		controller.hold(fmt.Sprintf("member %s is not at the exact signed canary predecessor", state.MemberID))
		return false, nil
	}
	previousSource := ""
	if current.OperationID != "" {
		previousSource = current.SourceDigest
	}
	state.SchemaVersion = managedUpdateMemberStateSchemaVersion
	state.ManagedRuntimeTarget = ManagedRuntimeTarget{
		OperationID: record.OperationID, AuthoritySequence: latest.Sequence,
		RequestSHA256: record.SignedRequestSHA256, PreparedAt: controller.currentTime().UTC(),
		PlacementGeneration:    record.PlacementGeneration,
		PlacementPayloadDigest: record.PlacementPayloadDigest, CanarySeatID: record.CanarySeatID,
		PreviousDesiredGeneration: state.DesiredGeneration,
		PreviousArtifactDigest:    state.EffectiveRuntimeManifest().ArtifactDigest, PreviousSourceDigest: previousSource,
		DesiredGeneration: record.CanaryDesiredGeneration, ArtifactDigest: record.CandidateArtifactDigest,
		ManifestDigest: record.CandidateManifestDigest, SourceDigest: record.CandidateSourceDigest,
		Phase: ManagedUpdateSeatPrepared, RollbackOfHeld: rollsBackHeld,
	}
	state.DesiredGeneration = record.CanaryDesiredGeneration
	state.Stage = StagePreparedDesired
	state.OperationID = digestToken("u", state.DatabaseID, state.PartitionID, record.OperationID, state.MemberID, "prepared")
	if _, err := controller.persist(ctx, epoch, canary.Revision, state); err != nil {
		return false, err
	}
	return true, nil
}

func (controller *Controller) reconcileManagedUpdateTerminal(ctx context.Context, epoch uint64,
	active Intent, latest authority.LogEntry, terminal authority.ManagedUpdateRecord,
	memberByID map[string]VersionedMemberState,
) (bool, error) {
	reader, ok := controller.fencer.(authority.ManagedUpdateReader)
	if !ok {
		return false, errors.New("placement authority lacks exact managed update history")
	}
	history, err := reader.ReadManagedUpdateOperation(ctx, terminal.DatabaseID, terminal.PartitionID,
		terminal.OperationID)
	if err != nil {
		return false, err
	}
	if len(history) != 2 || history[1].Sequence != latest.Sequence ||
		managedUpdatePhaseFromSubject(history[0].SubjectKey) != authority.ManagedUpdatePrepared ||
		managedUpdatePhaseFromSubject(history[1].SubjectKey) != terminal.Phase {
		controller.hold(fmt.Sprintf("managed update %s terminal history cannot be reconciled safely", terminal.OperationID))
		return true, nil
	}
	prepared, update, _, err := decodeManagedUpdateRequest(history[0], controller.config.Cell)
	if err != nil {
		return false, err
	}
	verifiedTerminal, err := decodeManagedUpdatePhaseRecord(latest, prepared, terminal.Phase)
	if err != nil || verifiedTerminal.Outcome != terminal.Outcome ||
		terminal.Phase == authority.ManagedUpdateCanaryServing && terminal.Outcome != string(authority.ManagedUpdateCanaryServing) ||
		terminal.Phase == authority.ManagedUpdateHeld && terminal.Outcome != "candidate-reported-failure" &&
			terminal.Outcome != "candidate-proof-timeout" ||
		update.DatabaseID != active.DatabaseID || update.PartitionID != active.PartitionID ||
		update.PlacementGeneration != active.Generation || update.PlacementPayloadDigest != active.PayloadDigest() {
		controller.hold(fmt.Sprintf("managed update %s terminal record differs from its exact signed Prepare", terminal.OperationID))
		return true, nil
	}
	placementReader, ok := controller.fencer.(managedUpdatePlacementReader)
	if !ok {
		return false, errors.New("placement authority lacks immutable placement history")
	}
	placementEntry, err := placementReader.ReadPlacementIntent(ctx, update.DatabaseID, update.PartitionID)
	if err != nil {
		return false, err
	}
	currentIntent, err := DecodeCommittedIntent(placementEntry.Payload)
	if err != nil || placementEntry.Sequence != update.PlacementSequence ||
		currentIntent.Generation != update.PlacementGeneration ||
		currentIntent.PayloadDigest() != update.PlacementPayloadDigest ||
		currentIntent.DatabaseID != active.DatabaseID || currentIntent.PartitionID != active.PartitionID {
		controller.hold(fmt.Sprintf("managed update %s terminal outcome is not for the current immutable placement", terminal.OperationID))
		return true, nil
	}
	canary, exists := memberByID[update.CanarySeatID]
	if !exists || !managedUpdateSeatTargetMatches(update, history[0].Sequence, prepared, canary.State) {
		controller.hold(fmt.Sprintf("managed update %s terminal outcome has no exact prepared canary seat", terminal.OperationID))
		return true, nil
	}
	return controller.persistManagedUpdateSeatOutcome(ctx, epoch, currentIntent, update, history[0].Sequence,
		prepared, terminal, canary)
}

func (controller *Controller) persistManagedUpdateSeatOutcome(ctx context.Context, epoch uint64,
	active Intent, update ManagedUpdateIntent, preparedSequence uint64,
	prepared, terminal authority.ManagedUpdateRecord,
	canary VersionedMemberState,
) (bool, error) {
	if terminal.Phase != authority.ManagedUpdateHeld && terminal.Phase != authority.ManagedUpdateCanaryServing {
		return false, errors.New("managed update seat outcome is not terminal")
	}
	state := canary.State
	if !managedUpdateSeatTargetMatches(update, preparedSequence, prepared, state) {
		controller.hold(fmt.Sprintf("managed update %s terminal outcome has no exact prepared canary seat", terminal.OperationID))
		return true, nil
	}
	wantPhase := ManagedUpdateSeatHeld
	if terminal.Phase == authority.ManagedUpdateCanaryServing {
		wantPhase = ManagedUpdateSeatCanaryServing
	}
	target := state.ManagedRuntimeTarget
	if target.Phase == wantPhase && target.Outcome == terminal.Outcome {
		if terminal.Phase == authority.ManagedUpdateHeld &&
			(state.Stage == StagePreparedDesired || state.Stage == StageAwaitingHealthy) {
			controller.hold(fmt.Sprintf("managed update %s is durably held: %s", terminal.OperationID, terminal.Outcome))
			return true, nil
		}
		if terminal.Phase == authority.ManagedUpdateCanaryServing && state.Stage == StageServing {
			return false, nil
		}
		controller.hold(fmt.Sprintf("managed update %s terminal seat stage is inconsistent", terminal.OperationID))
		return true, nil
	}
	if target.Phase != ManagedUpdateSeatPrepared || target.Outcome != "" ||
		terminal.Phase == authority.ManagedUpdateCanaryServing && state.Stage != StageAwaitingHealthy ||
		terminal.Phase == authority.ManagedUpdateHeld && state.Stage != StagePreparedDesired &&
			state.Stage != StageAwaitingHealthy {
		controller.hold(fmt.Sprintf("managed update %s terminal outcome cannot replace the current canary seat phase", terminal.OperationID))
		return true, nil
	}
	target.Phase = wantPhase
	target.Outcome = terminal.Outcome
	state.ManagedRuntimeTarget = target
	if terminal.Phase == authority.ManagedUpdateCanaryServing {
		state.Stage = StageServing
		state.OperationID = memberOperationID(active, state.MemberID, state.HostAttempt, "serving")
	} else {
		state.OperationID = digestToken("u", state.DatabaseID, state.PartitionID,
			terminal.OperationID, state.MemberID, "held")
	}
	if _, err := controller.persist(ctx, epoch, canary.Revision, state); err != nil {
		return false, err
	}
	if terminal.Phase == authority.ManagedUpdateHeld {
		controller.hold(fmt.Sprintf("managed update %s is durably held: %s", terminal.OperationID, terminal.Outcome))
	}
	return true, nil
}

func managedUpdateSeatTargetMatches(update ManagedUpdateIntent, preparedSequence uint64,
	prepared authority.ManagedUpdateRecord, state MemberState,
) bool {
	target := state.ManagedRuntimeTarget
	if state.SchemaVersion != managedUpdateMemberStateSchemaVersion || target.OperationID != prepared.OperationID ||
		target.AuthoritySequence != preparedSequence || target.RequestSHA256 != prepared.SignedRequestSHA256 ||
		target.PreparedAt.IsZero() || target.PreparedAt.Location() != time.UTC ||
		target.PlacementGeneration != update.PlacementGeneration ||
		target.PlacementPayloadDigest != update.PlacementPayloadDigest ||
		target.CanarySeatID != update.CanarySeatID ||
		target.PreviousArtifactDigest != update.OldArtifactDigest ||
		target.DesiredGeneration != update.CanaryDesiredGeneration ||
		target.ArtifactDigest != update.CandidateArtifactDigest ||
		target.ManifestDigest != update.CandidateManifestDigest || target.SourceDigest != update.CandidateSourceDigest {
		return false
	}
	seatIndex := slices.IndexFunc(update.Seats, func(seat ManagedUpdateSeat) bool {
		return seat.SeatID == update.CanarySeatID
	})
	if seatIndex < 0 {
		return false
	}
	if update.Seats[seatIndex].DesiredGeneration != target.PreviousDesiredGeneration {
		return false
	}
	return managedUpdateSeatMatches(update.Seats[seatIndex], state.PredecessorState())
}

func decodeManagedUpdatePhaseRecord(entry authority.LogEntry, prepared authority.ManagedUpdateRecord,
	want authority.ManagedUpdatePhase,
) (authority.ManagedUpdateRecord, error) {
	var record authority.ManagedUpdateRecord
	if entry.Kind != authority.MutationManagedUpdate || entry.OperationID != prepared.OperationID ||
		managedUpdatePhaseFromSubject(entry.SubjectKey) != want {
		return record, errors.New("managed update terminal phase has a mismatched authority identity")
	}
	if err := json.Unmarshal(entry.Payload, &record, json.RejectUnknownMembers(true)); err != nil {
		return record, err
	}
	canonical, err := json.Marshal(record, json.Deterministic(true))
	if err != nil || !bytes.Equal(canonical, entry.Payload) || record.Validate() != nil ||
		record.Phase != want || !prepared.SameIdentity(record) {
		return record, errors.New("managed update terminal phase differs from its signed Prepare identity")
	}
	return record, nil
}

func (controller *Controller) commitManagedUpdateOutcome(ctx context.Context, epoch uint64,
	state MemberState, phase authority.ManagedUpdatePhase, outcome string,
	verify func(context.Context, ManagedUpdateIntent, authority.ManagedUpdateRecord) error,
) (uint64, error) {
	if err := controller.guard(ctx, epoch); err != nil {
		return 0, err
	}
	reader, ok := controller.fencer.(authority.ManagedUpdateStore)
	if !ok {
		return 0, errors.New("placement authority cannot commit a managed update outcome")
	}
	entries, err := reader.ReadManagedUpdateOperation(ctx, state.DatabaseID, state.PartitionID,
		state.ManagedRuntimeTarget.OperationID)
	if err != nil {
		return 0, err
	}
	var preparedEntry authority.LogEntry
	for _, entry := range entries {
		if managedUpdatePhaseFromSubject(entry.SubjectKey) == authority.ManagedUpdatePrepared {
			preparedEntry = entry
			break
		}
	}
	if preparedEntry.Sequence != state.ManagedRuntimeTarget.AuthoritySequence {
		return 0, authority.ErrInvalidTransition
	}
	prepared, update, _, err := decodeManagedUpdateRequest(preparedEntry, controller.config.Cell)
	if err != nil || prepared.OperationID != state.ManagedRuntimeTarget.OperationID ||
		prepared.SignedRequestSHA256 != state.ManagedRuntimeTarget.RequestSHA256 ||
		update.CanarySeatID != state.MemberID ||
		state.ManagedRuntimeTarget.AuthoritySequence != preparedEntry.Sequence {
		return 0, authority.ErrInvalidTransition
	}
	record := prepared
	record.Phase = phase
	record.Outcome = outcome
	return reader.CommitManagedUpdate(ctx, epoch, record, preparedEntry.Sequence,
		func(verifyCtx context.Context) error {
			if _, err := controller.store.ReadTerminalIntent(verifyCtx, state.DatabaseID, state.PartitionID); err == nil {
				return authority.ErrFenced
			} else if !errors.Is(err, authority.ErrNotFound) {
				return err
			}
			if verify == nil {
				return nil
			}
			return verify(verifyCtx, update, prepared)
		})
}

func managedUpdateCanaryTiming(target ManagedRuntimeTarget, now time.Time) (timedOut, clockValid bool) {
	if target.PreparedAt.IsZero() || target.PreparedAt.Location() != time.UTC {
		return false, false
	}
	now = now.UTC()
	if now.Before(target.PreparedAt) {
		return false, false
	}
	deadline := target.PreparedAt.Add(managedUpdateCanaryProofTimeout)
	if !deadline.After(target.PreparedAt) {
		return false, false
	}
	return !now.Before(deadline), true
}

func (controller *Controller) holdTimedOutManagedCanary(ctx context.Context, epoch uint64,
	intent Intent, versioned VersionedMemberState,
) (bool, error) {
	state := versioned.State
	target := state.ManagedRuntimeTarget
	if target.OperationID == "" {
		return false, nil
	}
	if target.Phase != ManagedUpdateSeatPrepared {
		controller.hold(fmt.Sprintf("managed update %s has an unreconciled canary phase", target.OperationID))
		return true, nil
	}
	if target.PlacementGeneration != intent.Generation || target.PlacementPayloadDigest != intent.PayloadDigest() {
		controller.hold(fmt.Sprintf("managed update %s no longer matches its immutable placement", target.OperationID))
		return true, nil
	}
	timedOut, clockValid := managedUpdateCanaryTiming(target, controller.currentTime())
	if !clockValid {
		controller.hold(fmt.Sprintf("managed update %s has a future or invalid canary preparation clock", target.OperationID))
		return true, nil
	}
	if !timedOut {
		return false, nil
	}
	const outcome = "candidate-proof-timeout"
	if _, err := controller.commitManagedUpdateOutcome(ctx, epoch, state, authority.ManagedUpdateHeld, outcome,
		func(verifyCtx context.Context, update ManagedUpdateIntent, prepared authority.ManagedUpdateRecord) error {
			return controller.verifyManagedCanaryTimeoutAtAuthorityCommit(verifyCtx, epoch, update, prepared, versioned)
		}); err != nil {
		return false, err
	}
	target.Phase = ManagedUpdateSeatHeld
	target.Outcome = outcome
	state.ManagedRuntimeTarget = target
	state.OperationID = digestToken("u", state.DatabaseID, state.PartitionID,
		target.OperationID, state.MemberID, "held")
	if _, err := controller.persist(ctx, epoch, versioned.Revision, state); err != nil {
		return false, err
	}
	controller.hold(fmt.Sprintf("managed update %s is durably held after its canary proof deadline", target.OperationID))
	return true, nil
}

func (controller *Controller) verifyManagedCanaryServing(ctx context.Context, epoch uint64,
	update ManagedUpdateIntent, prepared authority.ManagedUpdateRecord, expected VersionedMemberState,
) error {
	return controller.verifyManagedCanaryServingChecked(ctx, epoch, update, prepared, expected, true)
}

func (controller *Controller) verifyManagedCanaryServingAtAuthorityCommit(ctx context.Context, epoch uint64,
	update ManagedUpdateIntent, prepared authority.ManagedUpdateRecord, expected VersionedMemberState,
) error {
	// The authority callback holds the lease and final sequence fence; Runtime.Guard
	// would reacquire its mutex while this callback is running.
	return controller.verifyManagedCanaryServingChecked(ctx, epoch, update, prepared, expected, false)
}

func (controller *Controller) verifyManagedCanaryServingChecked(ctx context.Context, epoch uint64,
	update ManagedUpdateIntent, prepared authority.ManagedUpdateRecord, expected VersionedMemberState,
	guardAuthority bool,
) error {
	if guardAuthority {
		if err := controller.guard(ctx, epoch); err != nil {
			return err
		}
	}
	if _, err := controller.store.ReadTerminalIntent(ctx, update.DatabaseID, update.PartitionID); err == nil {
		return authority.ErrFenced
	} else if !errors.Is(err, authority.ErrNotFound) {
		return err
	}
	if timedOut, clockValid := managedUpdateCanaryTiming(expected.State.ManagedRuntimeTarget, controller.currentTime()); !clockValid || timedOut {
		return errors.New("managed canary serving proof is outside its durable deadline")
	}
	reader, ok := controller.fencer.(managedUpdatePlacementReader)
	if !ok {
		return errors.New("managed canary proof verifier lacks placement history")
	}
	placementEntry, err := reader.ReadPlacementIntent(ctx, update.DatabaseID, update.PartitionID)
	if err != nil {
		return err
	}
	currentIntent, err := DecodeCommittedIntent(placementEntry.Payload)
	if err != nil || placementEntry.Sequence != update.PlacementSequence ||
		currentIntent.Generation != update.PlacementGeneration ||
		currentIntent.PayloadDigest() != update.PlacementPayloadDigest {
		return errors.New("managed canary proof is not for the current immutable placement")
	}
	seats, err := controller.localSeats(currentIntent)
	if err != nil {
		return err
	}
	members, err := controller.store.ListMembers(ctx, update.DatabaseID, update.PartitionID)
	if err != nil {
		return err
	}
	if len(seats) != 2 || len(members) != 2 || len(update.Seats) != 2 {
		return errors.New("managed canary proof requires both retained members")
	}
	memberByID := make(map[string]VersionedMemberState, len(members))
	for _, member := range members {
		if _, exists := memberByID[member.State.MemberID]; exists {
			return errors.New("managed canary proof found duplicate member state")
		}
		memberByID[member.State.MemberID] = member
	}
	canary, exists := memberByID[update.CanarySeatID]
	if !exists || canary.Revision != expected.Revision || !reflect.DeepEqual(canary.State, expected.State) {
		return errors.New("managed canary state changed before the serving outcome commit")
	}
	target := canary.State.ManagedRuntimeTarget
	if canary.State.Stage != StageAwaitingHealthy || target.Phase != ManagedUpdateSeatPrepared ||
		target.OperationID != prepared.OperationID || target.AuthoritySequence == 0 ||
		target.RequestSHA256 != prepared.SignedRequestSHA256 ||
		target.PlacementGeneration != update.PlacementGeneration ||
		target.PlacementPayloadDigest != update.PlacementPayloadDigest ||
		target.CanarySeatID != update.CanarySeatID ||
		target.ArtifactDigest != update.CandidateArtifactDigest ||
		target.ManifestDigest != update.CandidateManifestDigest || target.SourceDigest != update.CandidateSourceDigest ||
		canary.State.EffectiveRuntimeManifest().ArtifactDigest != update.CandidateArtifactDigest ||
		canary.State.DesiredGeneration != update.CanaryDesiredGeneration {
		return errors.New("managed canary does not have its exact prepared candidate target")
	}
	instances, err := controller.fleet.Observe(ctx)
	if err != nil {
		return err
	}
	statuses, err := controller.hosts.ListHosts(ctx)
	if err != nil {
		return err
	}
	statusByNode := make(map[string]host.HostStatus, len(statuses))
	for _, status := range statuses {
		if _, exists := statusByNode[status.Registration.Node]; exists {
			return errors.New("managed canary proof found duplicate host status")
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
			return errors.New("managed canary proof found duplicate host desired state")
		}
		desiredByNode[desired.Node] = desired
	}
	stateBySeat := make(map[string]MemberState, len(members))
	pinBySeat := make(map[string]ManagedUpdateSeat, len(update.Seats))
	for _, seat := range update.Seats {
		versioned, exists := memberByID[seat.SeatID]
		if !exists {
			return errors.New("managed canary proof lost a signed member seat")
		}
		state := versioned.State
		if seat.SeatID == update.CanarySeatID {
			if !managedUpdateSeatMatches(seat, state.PredecessorState()) ||
				state.ManagedRuntimeTarget.Phase != ManagedUpdateSeatPrepared {
				return errors.New("canary member identity differs from its exact signed predecessor")
			}
		} else if !managedUpdatePeerUnchanged(seat, state, update) {
			return errors.New("peer member changed from its exact serving predecessor during canary")
		}
		stateBySeat[seat.SeatID], pinBySeat[seat.SeatID] = state, seat
	}
	for _, seat := range seats {
		state, exists := stateBySeat[seat.MemberID]
		if !exists {
			return errors.New("managed canary proof lacks a current placement seat")
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
			return errors.New("managed canary proof lacks an exact current OCI host")
		}
		attachment, attached := observedAttachment(instance, state)
		if !attached || !validObservedAttachment(attachment) || attachment.Device != state.AttachmentDevice ||
			attachment.ETag != state.AttachmentETag {
			return errors.New("managed canary proof lacks its exact attached retained volume")
		}
		status, admitted := controller.admittedHost(currentIntent, state, instance, statusByNode)
		if !admitted || status.Registration.Generation != state.HostGeneration ||
			!controller.hasServingReport(currentIntent, state, instance, status) {
			return errors.New("managed canary proof is not fresh for both exact host sessions")
		}
		if seat.MemberID == update.CanarySeatID {
			artifact, err := controller.admittedRuntimeArtifact(ctx, state)
			if err != nil || artifact.Digest != update.CandidateArtifactDigest ||
				artifact.ManifestDigest != update.CandidateManifestDigest || artifact.SourceDigest != update.CandidateSourceDigest {
				return errors.New("managed canary serving report does not match admitted candidate bytes")
			}
		} else if !managedUpdatePeerUnchanged(pinBySeat[seat.MemberID], state, update) {
			return errors.New("managed canary peer no longer runs its signed artifact")
		}
		want, err := controller.memberDesired(epoch, currentIntent, state, seat)
		if err != nil {
			return err
		}
		current, exists := desiredByNode[state.HostNode]
		if !exists || !sameManagedDesired(current, want) {
			return errors.New("managed canary host desired differs from its exact durable target")
		}
	}
	currentCanary, err := controller.store.ReadMember(ctx, update.DatabaseID, update.PartitionID,
		update.CanarySeatID)
	if err != nil || currentCanary.Revision != canary.Revision ||
		!reflect.DeepEqual(currentCanary.State, canary.State) {
		return errors.New("managed canary seat changed during the final serving verification")
	}
	if timedOut, clockValid := managedUpdateCanaryTiming(currentCanary.State.ManagedRuntimeTarget, controller.currentTime()); !clockValid || timedOut {
		return errors.New("managed canary serving proof expired before the final authority commit")
	}
	return nil
}

// managedUpdatePeerUnchanged requires the non-canary seat to still serve the
// exact signed predecessor: no unfinished or held target of its own, and the
// prior or already promoted candidate artifact.
func managedUpdatePeerUnchanged(seat ManagedUpdateSeat, state MemberState, update ManagedUpdateIntent) bool {
	effective := state.EffectiveRuntimeManifest().ArtifactDigest
	return managedUpdateSeatMatches(seat, state) && state.Stage == StageServing &&
		(state.ManagedRuntimeTarget.OperationID == "" || state.ManagedRuntimeTarget.Phase == ManagedUpdateSeatCanaryServing) &&
		(effective == update.OldArtifactDigest || effective == update.CandidateArtifactDigest)
}

func hasCurrentFailedCanaryReport(status host.HostStatus, state MemberState, environment, role string) bool {
	now := time.Now()
	if !status.Verified || !now.Before(status.SessionExpiresAt) {
		return false
	}
	for _, report := range status.Reports {
		if strings.EqualFold(report.Cell, string(state.Region)) && report.Node == state.HostNode &&
			report.Environment == environment && report.Role == role &&
			report.Generation == state.DesiredGeneration &&
			report.Digest == state.ManagedRuntimeTarget.ArtifactDigest &&
			report.State == "failed" && report.Error != "" && !report.ObservedAt.IsZero() &&
			!report.ObservedAt.After(now.Add(2*time.Second)) && now.Sub(report.ObservedAt) < host.ReportMaxAge {
			return true
		}
	}
	return false
}

func (controller *Controller) verifyManagedCanaryTimeoutAtAuthorityCommit(ctx context.Context, epoch uint64,
	update ManagedUpdateIntent, prepared authority.ManagedUpdateRecord, expected VersionedMemberState,
) error {
	// CommitManagedUpdate holds the final authority fence throughout this check.
	if _, err := controller.store.ReadTerminalIntent(ctx, update.DatabaseID, update.PartitionID); err == nil {
		return authority.ErrFenced
	} else if !errors.Is(err, authority.ErrNotFound) {
		return err
	}
	placementReader, ok := controller.fencer.(managedUpdatePlacementReader)
	if !ok {
		return errors.New("managed canary timeout verifier lacks placement history")
	}
	placementEntry, err := placementReader.ReadPlacementIntent(ctx, update.DatabaseID, update.PartitionID)
	if err != nil {
		return err
	}
	currentIntent, err := DecodeCommittedIntent(placementEntry.Payload)
	if err != nil || placementEntry.Sequence != update.PlacementSequence ||
		currentIntent.Generation != update.PlacementGeneration ||
		currentIntent.PayloadDigest() != update.PlacementPayloadDigest {
		return errors.New("managed canary timeout is not for the current immutable placement")
	}
	current, err := controller.store.ReadMember(ctx, update.DatabaseID, update.PartitionID,
		expected.State.MemberID)
	if err != nil || current.Revision != expected.Revision || !reflect.DeepEqual(current.State, expected.State) ||
		current.State.Stage != StagePreparedDesired && current.State.Stage != StageAwaitingHealthy ||
		current.State.ManagedRuntimeTarget.Phase != ManagedUpdateSeatPrepared ||
		!managedUpdateSeatTargetMatches(update, expected.State.ManagedRuntimeTarget.AuthoritySequence,
			prepared, current.State) {
		return errors.New("managed canary seat changed before its timeout outcome commit")
	}
	timedOut, clockValid := managedUpdateCanaryTiming(current.State.ManagedRuntimeTarget, controller.currentTime())
	if !clockValid || !timedOut {
		return errors.New("managed canary timeout has not reached its durable deadline")
	}
	return nil
}

func (controller *Controller) verifyManagedCanaryFailure(ctx context.Context, epoch uint64,
	update ManagedUpdateIntent, expected VersionedMemberState, environment, role string,
) error {
	return controller.verifyManagedCanaryFailureChecked(ctx, epoch, update, expected, environment, role, true)
}

func (controller *Controller) verifyManagedCanaryFailureAtAuthorityCommit(ctx context.Context, epoch uint64,
	update ManagedUpdateIntent, expected VersionedMemberState, environment, role string,
) error {
	// CommitManagedUpdate holds the final authority fence throughout this check.
	return controller.verifyManagedCanaryFailureChecked(ctx, epoch, update, expected, environment, role, false)
}

func (controller *Controller) verifyManagedCanaryFailureChecked(ctx context.Context, epoch uint64,
	update ManagedUpdateIntent, expected VersionedMemberState, environment, role string, guardAuthority bool,
) error {
	if guardAuthority {
		if err := controller.guard(ctx, epoch); err != nil {
			return err
		}
	}
	if _, err := controller.store.ReadTerminalIntent(ctx, update.DatabaseID, update.PartitionID); err == nil {
		return authority.ErrFenced
	} else if !errors.Is(err, authority.ErrNotFound) {
		return err
	}
	placementReader, ok := controller.fencer.(managedUpdatePlacementReader)
	if !ok {
		return errors.New("managed canary failure verifier lacks placement history")
	}
	placementEntry, err := placementReader.ReadPlacementIntent(ctx, update.DatabaseID, update.PartitionID)
	if err != nil {
		return err
	}
	currentIntent, err := DecodeCommittedIntent(placementEntry.Payload)
	if err != nil || placementEntry.Sequence != update.PlacementSequence ||
		currentIntent.Generation != update.PlacementGeneration ||
		currentIntent.PayloadDigest() != update.PlacementPayloadDigest {
		return errors.New("managed canary failure is not for the current placement")
	}
	current, err := controller.store.ReadMember(ctx, update.DatabaseID, update.PartitionID, expected.State.MemberID)
	if err != nil || current.Revision != expected.Revision || !reflect.DeepEqual(current.State, expected.State) ||
		current.State.Stage != StageAwaitingHealthy ||
		current.State.ManagedRuntimeTarget.Phase != ManagedUpdateSeatPrepared {
		return errors.New("managed canary changed before its held outcome commit")
	}
	if timedOut, clockValid := managedUpdateCanaryTiming(current.State.ManagedRuntimeTarget, controller.currentTime()); !clockValid || timedOut {
		return errors.New("managed canary failure report arrived outside its durable proof deadline")
	}
	instances, err := controller.fleet.Observe(ctx)
	if err != nil {
		return err
	}
	var instance oci.Instance
	count := 0
	for _, observed := range instances {
		if observed.ID != current.State.InstanceID && observed.Node != current.State.HostNode {
			continue
		}
		instance = observed
		count++
	}
	seat, ok := controller.seatForMember(currentIntent, current.State.Region, current.State.MemberID)
	if !ok || count != 1 || controller.validateObservedInstance(instance, current.State, seat) != nil {
		return errors.New("managed failed canary lost its exact OCI host before held outcome")
	}
	statuses, err := controller.hosts.ListHosts(ctx)
	if err != nil {
		return err
	}
	byNode := make(map[string]host.HostStatus, len(statuses))
	for _, status := range statuses {
		byNode[status.Registration.Node] = status
	}
	status, admitted := controller.admittedHost(currentIntent, current.State, instance, byNode)
	if !admitted || status.Registration.Generation != current.State.HostGeneration ||
		!hasCurrentFailedCanaryReport(status, current.State, environment, role) {
		return errors.New("managed canary failure report is no longer current")
	}
	if timedOut, clockValid := managedUpdateCanaryTiming(current.State.ManagedRuntimeTarget, controller.currentTime()); !clockValid || timedOut {
		return errors.New("managed canary failure report expired before the final authority commit")
	}
	return nil
}

// VerifyManagedDesired is installed directly on host.ApplyDesired. The host
// controller runs it inside every final authority-stream CAS retry.
func (controller *Controller) VerifyManagedDesired(
	ctx context.Context,
	desired host.Desired,
	registration host.Registration,
	current host.Desired,
	currentExists bool,
) error {
	if desired.ManagedMember == nil || desired.Withdrawn || registration.ManagedPlacement == nil ||
		registration.ManagedMember == nil || registration.ManagedOCI == nil {
		return errors.New("managed desired is missing its registered placement identity")
	}
	databaseID, partitionID := registration.ManagedPlacement.DatabaseID, registration.ManagedPlacement.PartitionID
	if _, err := controller.store.ReadTerminalIntent(ctx, databaseID, partitionID); err == nil {
		return authority.ErrFenced
	} else if !errors.Is(err, authority.ErrNotFound) {
		return err
	}
	placementReader, ok := controller.fencer.(managedUpdatePlacementReader)
	if !ok {
		return errors.New("managed desired verifier lacks exact placement history")
	}
	placementEntry, err := placementReader.ReadPlacementIntent(ctx, databaseID, partitionID)
	if err != nil {
		return err
	}
	intent, err := DecodeCommittedIntent(placementEntry.Payload)
	if err != nil || intent.Generation != registration.ManagedPlacement.IntentGeneration ||
		intent.PayloadDigest() != registration.ManagedPlacement.IntentPayloadDigest {
		return errors.New("managed desired placement differs from its current authority record")
	}
	// Member states are keyed by placement seat; the TerraBase member UUID is
	// the signed roster identity bound to that seat.
	seatID := registration.ManagedPlacement.SeatID
	versioned, err := controller.store.ReadMember(ctx, intent.DatabaseID, intent.PartitionID, seatID)
	if err != nil {
		return err
	}
	state := versioned.State
	if versioned.Revision == 0 || state.Validate() != nil ||
		state.DatabaseID != intent.DatabaseID || state.PartitionID != intent.PartitionID ||
		state.MemberID != seatID || state.CanonicalRosterRow.MemberID != desired.ManagedMember.Member.Scope.MemberID ||
		state.Region != oci.Region(desired.ManagedMember.OCI.Region) ||
		state.HostNode != desired.Node || state.HostGeneration != registration.Generation ||
		state.IntentGeneration != intent.Generation || state.IntentPayloadDigest != intent.PayloadDigest() ||
		state.HostAttempt != registration.ManagedMember.HostAttempt ||
		registration.ManagedPlacement.CanonicalRosterDigest != state.CanonicalRosterDigest ||
		registration.ManagedPlacement.ManagedHostProfileDigest != state.ManagedHostProfileDigest ||
		registration.ManagedOCI.InstanceID != state.InstanceID || registration.ManagedOCI.CreateKey != state.CreateKey ||
		registration.ManagedOCI.Owner != controller.config.ManagedOwner ||
		registration.ManagedOCI.FleetGeneration != controller.config.FleetGeneration {
		return errors.New("managed desired registration differs from its durable placement seat")
	}
	seat, ok := controller.seatForMember(intent, state.Region, state.MemberID)
	if !ok || state.Stage != StagePreparedDesired && state.Stage != StageAwaitingHealthy && state.Stage != StageServing {
		return errors.New("managed desired seat is not in an authorized launch stage")
	}
	if desired.Environment != controller.config.Environment || desired.Role != controller.config.MemberRole {
		return errors.New("managed desired role or environment differs from placement policy")
	}
	member := controller.memberBinding(intent, state)
	ociBinding := host.ManagedOCIBinding{
		Region: string(state.Region), InstanceID: state.InstanceID, Owner: controller.config.ManagedOwner,
		FleetGeneration: controller.config.FleetGeneration, CreateKey: state.CreateKey,
	}
	pins := host.ManagedRegistrationPins{
		Placement: host.ManagedPlacementBinding{
			DatabaseID: state.DatabaseID, PartitionID: state.PartitionID, SeatID: state.MemberID,
			IntentGeneration: state.IntentGeneration, IntentPayloadDigest: state.IntentPayloadDigest,
			CanonicalRosterDigest:    state.CanonicalRosterDigest,
			ManagedHostProfileDigest: state.ManagedHostProfileDigest,
		},
		Member: member, OCI: ociBinding, FailureDomain: state.FailureDomain,
		AllocatableMemoryBytes: state.ManagedHostProfile.AllocatableMemoryBytes,
		SystemReserveBytes:     state.ManagedHostProfile.SystemReserveBytes,
	}
	if host.ValidateManagedRegistrationPins(registration, pins) != nil {
		return errors.New("managed desired does not match the current host registration")
	}
	artifact, err := controller.admittedRuntimeArtifact(ctx, state)
	if err != nil {
		return fmt.Errorf("verify managed desired artifact admission: %w", err)
	}
	target := state.ManagedRuntimeTarget
	if target.OperationID != "" && (artifact.Digest != target.ArtifactDigest ||
		artifact.ManifestDigest != target.ManifestDigest || artifact.SourceDigest != target.SourceDigest) {
		return errors.New("managed canary artifact bytes, manifest, or source differs from its signed update")
	}
	want, err := controller.memberDesired(controller.fencer.Current().Epoch, intent, state, seat)
	if err != nil {
		return err
	}
	if !sameManagedDesired(desired, want) {
		return errors.New("managed desired differs from its exact durable runtime target")
	}
	if target.OperationID == "" {
		if state.Stage != StagePreparedDesired {
			return errors.New("initial managed desired is no longer prepared")
		}
		if currentExists && !sameManagedDesired(current, want) {
			return errors.New("initial managed desired cannot replace an existing target")
		}
		return nil
	}
	if state.SchemaVersion != managedUpdateMemberStateSchemaVersion || target.Phase == ManagedUpdateSeatHeld {
		return errors.New("managed canary target is not durably prepared")
	}
	currentUpdate, err := controller.managedUpdatePrepareIsCurrent(ctx, state)
	if err != nil {
		return err
	}
	if !currentUpdate {
		return errors.New("managed canary authorization is unavailable")
	}
	previous, err := controller.memberDesired(controller.fencer.Current().Epoch, intent, state.PredecessorState(), seat)
	if err != nil {
		return err
	}
	if state.Stage == StagePreparedDesired && currentExists &&
		(sameManagedDesired(current, previous) || sameManagedDesired(current, want)) {
		return nil
	}
	if (state.Stage == StageAwaitingHealthy || state.Stage == StageServing) && currentExists &&
		sameManagedDesired(current, want) {
		return nil
	}
	return errors.New("managed canary desired is neither the exact predecessor nor the committed target")
}

// VerifyManagedRuntimeTarget rechecks durable canary authorization before
// material delivery or volume initialization. Initial placement launches keep
// their existing verifier and return false here.
func (controller *Controller) VerifyManagedRuntimeTarget(ctx context.Context, desired host.Desired,
	registration host.Registration,
) (bool, error) {
	if desired.ManagedMember == nil || desired.Withdrawn || registration.ManagedPlacement == nil ||
		registration.ManagedMember == nil || registration.ManagedOCI == nil {
		return false, errors.New("managed runtime target is missing its host registration")
	}
	placementBinding := *registration.ManagedPlacement
	if _, err := controller.store.ReadTerminalIntent(ctx, placementBinding.DatabaseID, placementBinding.PartitionID); err == nil {
		return false, authority.ErrFenced
	} else if !errors.Is(err, authority.ErrNotFound) {
		return false, err
	}
	reader, ok := controller.fencer.(managedUpdatePlacementReader)
	if !ok {
		return false, errors.New("managed runtime verifier lacks exact placement history")
	}
	entry, err := reader.ReadPlacementIntent(ctx, placementBinding.DatabaseID, placementBinding.PartitionID)
	if err != nil {
		return false, err
	}
	intent, err := DecodeCommittedIntent(entry.Payload)
	if err != nil || intent.Generation != placementBinding.IntentGeneration ||
		intent.PayloadDigest() != placementBinding.IntentPayloadDigest ||
		intent.DatabaseID != placementBinding.DatabaseID || intent.PartitionID != placementBinding.PartitionID {
		return false, errors.New("managed runtime placement differs from its exact authority record")
	}
	stateVersion, err := controller.store.ReadMember(ctx, intent.DatabaseID, intent.PartitionID, placementBinding.SeatID)
	if err != nil {
		return false, err
	}
	state := stateVersion.State
	if state.CanonicalRosterRow.MemberID != desired.ManagedMember.Member.Scope.MemberID {
		return false, errors.New("managed runtime target member differs from its durable placement seat")
	}
	target := state.ManagedRuntimeTarget
	if target.OperationID == "" {
		return false, nil
	}
	if stateVersion.Revision == 0 || state.Validate() != nil || state.SchemaVersion != managedUpdateMemberStateSchemaVersion ||
		state.HostNode != desired.Node || state.HostGeneration != registration.Generation ||
		state.MemberID != placementBinding.SeatID || target.Phase == ManagedUpdateSeatHeld ||
		state.Stage != StagePreparedDesired && state.Stage != StageAwaitingHealthy && state.Stage != StageServing ||
		registration.ManagedOCI.InstanceID != state.InstanceID || registration.ManagedOCI.CreateKey != state.CreateKey ||
		registration.ManagedOCI.Owner != controller.config.ManagedOwner ||
		registration.ManagedOCI.FleetGeneration != controller.config.FleetGeneration {
		return false, errors.New("managed runtime target differs from the exact durable canary seat")
	}
	current, err := controller.managedUpdatePrepareIsCurrent(ctx, state)
	if err != nil {
		return false, err
	}
	if !current {
		return false, errors.New("managed runtime update authority is no longer current")
	}
	artifact, err := controller.admittedRuntimeArtifact(ctx, state)
	if err != nil || artifact.Digest != target.ArtifactDigest || artifact.ManifestDigest != target.ManifestDigest ||
		artifact.SourceDigest != target.SourceDigest || desired.Digest != target.ArtifactDigest ||
		desired.Generation != target.DesiredGeneration || desired.ManagedMember.SourceDigest != target.SourceDigest {
		return false, errors.New("managed runtime target artifact or source is not the exact admitted canary")
	}
	seat, ok := controller.seatForMember(intent, state.Region, state.MemberID)
	if !ok {
		return false, errors.New("managed runtime target seat is not in the immutable placement")
	}
	want, err := controller.memberDesired(controller.fencer.Current().Epoch, intent, state, seat)
	if err != nil || !sameManagedDesired(desired, want) {
		return false, errors.New("managed runtime target desired differs from its durable canary pins")
	}
	return true, nil
}

func (controller *Controller) seatForMember(intent Intent, region oci.Region, memberID string) (Seat, bool) {
	seats, err := controller.localSeats(intent)
	if err != nil {
		return Seat{}, false
	}
	for _, seat := range seats {
		if seat.Region == region && seat.MemberID == memberID {
			return seat, true
		}
	}
	return Seat{}, false
}

func sameManagedDesired(left, right host.Desired) bool {
	left.AuthorityEpoch, right.AuthorityEpoch = 0, 0
	return reflect.DeepEqual(left, right)
}

func decodeManagedUpdateRequest(
	entry authority.LogEntry,
	cell string,
) (authority.ManagedUpdateRecord, ManagedUpdateIntent, protocol.Envelope, error) {
	var record authority.ManagedUpdateRecord
	if err := json.Unmarshal(entry.Payload, &record, json.RejectUnknownMembers(true)); err != nil {
		return record, ManagedUpdateIntent{}, protocol.Envelope{}, err
	}
	wantSubject := strings.Join([]string{record.DatabaseID, record.PartitionID,
		record.OperationID, string(record.Phase)}, ".")
	if record.Validate() != nil || record.Cell != cell || wantSubject != entry.SubjectKey ||
		record.OperationID != entry.OperationID || record.Phase != authority.ManagedUpdatePrepared {
		return record, ManagedUpdateIntent{}, protocol.Envelope{}, errors.New("managed update Prepare record is malformed")
	}
	canonicalRecord, err := json.Marshal(record, json.Deterministic(true))
	if err != nil || !bytes.Equal(canonicalRecord, entry.Payload) {
		return record, ManagedUpdateIntent{}, protocol.Envelope{}, errors.New("managed update Prepare record is not canonical")
	}
	var envelope protocol.Envelope
	if err := protocol.DecodeStrict(record.SignedRequest, &envelope, protocol.MaxPayloadBytes+4096); err != nil {
		return record, ManagedUpdateIntent{}, protocol.Envelope{}, err
	}
	var intent ManagedUpdateIntent
	if err := protocol.DecodeStrict(envelope.Payload, &intent, protocol.MaxPayloadBytes); err != nil {
		return record, intent, envelope, err
	}
	canonical, err := protocol.EncodeJSON(intent)
	if err != nil || !bytes.Equal(canonical, envelope.Payload) || intent.Validate() != nil ||
		envelope.Kind != ManagedUpdateEnvelopeKind || !managedUpdateEnvelopeRegionMatches(envelope, cell) ||
		envelope.OperationID != record.OperationID || envelope.Generation != intent.CanaryDesiredGeneration ||
		envelope.Epoch != intent.AuthorityEpoch || entry.Epoch != envelope.Epoch ||
		intent.Cell != record.Cell || intent.DatabaseID != record.DatabaseID ||
		intent.PartitionID != record.PartitionID || intent.OperationID != record.OperationID ||
		intent.PlacementGeneration != record.PlacementGeneration ||
		intent.PlacementPayloadDigest != record.PlacementPayloadDigest ||
		intent.PlacementSequence != record.PlacementSequence || intent.CanarySeatID != record.CanarySeatID ||
		intent.CanaryDesiredGeneration != record.CanaryDesiredGeneration ||
		intent.OldArtifactDigest != record.OldArtifactDigest ||
		intent.CandidateArtifactDigest != record.CandidateArtifactDigest ||
		intent.CandidateManifestDigest != record.CandidateManifestDigest ||
		intent.CandidateSourceDigest != record.CandidateSourceDigest {
		return record, intent, envelope, errors.New("managed update signed request differs from its immutable authority record")
	}
	return record, intent, envelope, nil
}

func managedUpdateEnvelopeRegionMatches(envelope protocol.Envelope, cell string) bool {
	canonicalCell, err := protocol.CanonicalRegion(cell)
	return err == nil && envelope.Region == canonicalCell
}

func managedUpdatePhaseFromSubject(subjectKey string) authority.ManagedUpdatePhase {
	_, phase, ok := strings.CutLast(subjectKey, ".")
	if !ok {
		return ""
	}
	return authority.ManagedUpdatePhase(phase)
}
