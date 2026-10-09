package authority

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/nats-io/nats.go/jetstream"
)

const maxManagedUpdateRecords = 4096
const maxManagedUpdateRequestBytes = 700 << 10

// CommitManagedUpdate appends one immutable operation phase under the
// database's terminal workload gate. Each phase has its own subject, so later
// phases and operations never replace the exact original signed Prepare
// receipt. expectedSequence is the current workload update sequence for
// Prepare, and the exact Prepare receipt sequence for a terminal canary phase.
// verify runs under the authority log's final stream-sequence CAS boundary.
func (r *Runtime) CommitManagedUpdate(
	ctx context.Context,
	epoch uint64,
	record ManagedUpdateRecord,
	expectedSequence uint64,
	verify func(context.Context) error,
) (uint64, error) {
	if r == nil || ctx == nil || ctx.Err() != nil {
		return 0, ErrNotLeader
	}
	if err := record.Validate(); err != nil {
		return 0, err
	}
	if record.Cell != r.config.Scope {
		return 0, errors.New("managed update cell differs from authority scope")
	}
	payload, err := json.Marshal(record, json.Deterministic(true))
	if err != nil {
		return 0, err
	}
	scope := WorkloadScope{DatabaseID: record.DatabaseID, PartitionID: record.PartitionID}
	release, err := r.beginWorkloadGate(ctx, scope)
	if err != nil {
		return 0, err
	}
	defer release()
	if err := r.requireNoTerminalIntent(ctx, scope.DatabaseID, scope.PartitionID); err != nil {
		return 0, err
	}

	if prior, readErr := r.readManagedUpdatePhase(ctx, record.DatabaseID, record.PartitionID,
		record.OperationID, record.Phase); readErr == nil {
		if bytes.Equal(prior.Payload, payload) {
			return prior.Sequence, nil
		}
		return 0, ErrOperationConflict
	} else if !errors.Is(readErr, ErrNotFound) {
		return 0, readErr
	}
	if err := r.validateManagedUpdateTransition(ctx, record, expectedSequence); err != nil {
		return 0, err
	}
	subjectKey, err := managedUpdateSubjectKey(record.DatabaseID, record.PartitionID,
		record.OperationID, record.Phase)
	if err != nil {
		return 0, err
	}
	return r.commitMutationVerified(ctx, epoch, MutationManagedUpdate, subjectKey,
		record.OperationID, 0, payload, func(ctx context.Context) error {
			if err := r.requireNoTerminalIntent(ctx, scope.DatabaseID, scope.PartitionID); err != nil {
				return err
			}
			if err := r.requireNoActiveBackup(ctx, scope.DatabaseID, scope.PartitionID); err != nil {
				return err
			}
			if err := r.validateManagedUpdateTransition(ctx, record, expectedSequence); err != nil {
				return err
			}
			if verify != nil {
				return verify(ctx)
			}
			return nil
		})
}

// ReadManagedUpdate returns the latest immutable phase record for one
// database partition, regardless of which operation produced it.
func (r *Runtime) ReadManagedUpdate(ctx context.Context, databaseID, partitionID string) (LogEntry, error) {
	if r == nil || r.readStream == nil {
		return LogEntry{}, ErrNotFound
	}
	r.readMu.Lock()
	defer r.readMu.Unlock()
	entries, err := listManagedUpdateEntries(ctx, r.readStream, r.config.Scope, databaseID, partitionID)
	if err != nil {
		return LogEntry{}, err
	}
	if len(entries) == 0 {
		return LogEntry{}, ErrNotFound
	}
	return entries[len(entries)-1], nil
}

// ReadManagedUpdateOperation returns the exact phase history for one
// operation. It reads the operation's phase subjects directly, so later
// operation records cannot erase the original Prepare receipt.
func (r *Runtime) ReadManagedUpdateOperation(
	ctx context.Context,
	databaseID, partitionID, operationID string,
) ([]LogEntry, error) {
	if r == nil || r.readStream == nil {
		return nil, ErrNotFound
	}
	r.readMu.Lock()
	defer r.readMu.Unlock()
	return readManagedUpdateOperation(ctx, r.readStream, r.config.Scope,
		databaseID, partitionID, operationID)
}

// ListManagedUpdates returns every retained phase receipt for one workload in
// authority sequence order. Invalid or unreadable history is an error.
func (r *Runtime) ListManagedUpdates(ctx context.Context, databaseID, partitionID string) ([]LogEntry, error) {
	if r == nil || r.readStream == nil {
		return nil, ErrNotFound
	}
	r.readMu.Lock()
	defer r.readMu.Unlock()
	return listManagedUpdateEntries(ctx, r.readStream, r.config.Scope, databaseID, partitionID)
}

func (r *Runtime) validateManagedUpdateTransition(
	ctx context.Context,
	record ManagedUpdateRecord,
	expectedSequence uint64,
) error {
	latest, err := r.ReadManagedUpdate(ctx, record.DatabaseID, record.PartitionID)
	if record.Phase == ManagedUpdatePrepared {
		if errors.Is(err, ErrNotFound) {
			if expectedSequence != 0 {
				return ErrConflict
			}
			return nil
		}
		if err != nil {
			return err
		}
		if latest.Sequence != expectedSequence {
			return ErrConflict
		}
		// A rolling release or a held-seat rollback is a new operation after the
		// previous operation's terminal outcome. Placement verifies each seat's
		// durable predecessor; an unfinished operation blocks any successor.
		if latest.Kind != MutationManagedUpdate {
			return ErrInvalidTransition
		}
		switch ManagedUpdatePhase(latest.SubjectKey[strings.LastIndexByte(latest.SubjectKey, '.')+1:]) {
		case ManagedUpdateCanaryServing, ManagedUpdateHeld:
			return nil
		default:
			return ErrInvalidTransition
		}
	}
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return ErrInvalidTransition
		}
		return err
	}
	prepared, err := r.readManagedUpdatePhase(ctx, record.DatabaseID, record.PartitionID,
		record.OperationID, ManagedUpdatePrepared)
	if err != nil {
		return ErrInvalidTransition
	}
	preparedRecord, err := decodeManagedUpdateRecord(prepared, r.config.Scope,
		record.DatabaseID, record.PartitionID, record.OperationID, ManagedUpdatePrepared)
	if err != nil || !sameManagedUpdateIdentity(preparedRecord, record) ||
		prepared.Sequence != expectedSequence || latest.Sequence != expectedSequence ||
		latest.OperationID != record.OperationID || latest.Kind != MutationManagedUpdate {
		return ErrInvalidTransition
	}
	return nil
}

func (record ManagedUpdateRecord) Validate() error {
	if record.SchemaVersion != 1 || !natsToken.MatchString(record.Cell) ||
		!entityid.Valid(record.DatabaseID) || !entityid.Valid(record.PartitionID) ||
		!entityid.Valid(record.OperationID) ||
		record.Phase != ManagedUpdatePrepared && record.Phase != ManagedUpdateCanaryServing &&
			record.Phase != ManagedUpdateHeld ||
		len(record.SignedRequest) == 0 || len(record.SignedRequest) > maxManagedUpdateRequestBytes ||
		!validTerminalDigest(record.SignedRequestSHA256) ||
		!validTerminalDigest(record.PlacementPayloadDigest) || record.PlacementGeneration == 0 ||
		record.PlacementSequence == 0 || !entityid.Valid(record.CanarySeatID) ||
		record.CanaryDesiredGeneration == 0 || !validTerminalDigest(record.OldArtifactDigest) ||
		!validTerminalDigest(record.CandidateArtifactDigest) ||
		record.CandidateArtifactDigest == record.OldArtifactDigest ||
		!validTerminalDigest(record.CandidateManifestDigest) ||
		!validTerminalDigest(record.CandidateSourceDigest) ||
		!validTerminalDigest(record.DurabilityProfileSHA256) {
		return errors.New("managed update record has incomplete identity or phase")
	}
	digest := sha256.Sum256(record.SignedRequest)
	if hex.EncodeToString(digest[:]) != record.SignedRequestSHA256 {
		return errors.New("managed update request digest differs from its exact signed bytes")
	}
	if record.Phase == ManagedUpdatePrepared {
		if record.Outcome != "" {
			return errors.New("prepared managed update cannot carry an outcome")
		}
	} else if record.Outcome == "" || len(record.Outcome) > 256 ||
		strings.ContainsAny(record.Outcome, "\r\n\x00") {
		return errors.New("terminal managed update phase requires a bounded outcome")
	}
	return nil
}

func sameManagedUpdateIdentity(left, right ManagedUpdateRecord) bool {
	return left.SchemaVersion == right.SchemaVersion && left.Cell == right.Cell &&
		left.DatabaseID == right.DatabaseID && left.PartitionID == right.PartitionID &&
		left.OperationID == right.OperationID &&
		bytes.Equal(left.SignedRequest, right.SignedRequest) &&
		left.SignedRequestSHA256 == right.SignedRequestSHA256 &&
		left.PlacementGeneration == right.PlacementGeneration &&
		left.PlacementPayloadDigest == right.PlacementPayloadDigest &&
		left.PlacementSequence == right.PlacementSequence && left.CanarySeatID == right.CanarySeatID &&
		left.CanaryDesiredGeneration == right.CanaryDesiredGeneration &&
		left.OldArtifactDigest == right.OldArtifactDigest &&
		left.CandidateArtifactDigest == right.CandidateArtifactDigest &&
		left.CandidateManifestDigest == right.CandidateManifestDigest &&
		left.CandidateSourceDigest == right.CandidateSourceDigest &&
		left.DurabilityProfileSHA256 == right.DurabilityProfileSHA256
}

// SameIdentity reports whether two phase records retain the exact signed
// managed-update identity while allowing their phase and outcome to differ.
func (record ManagedUpdateRecord) SameIdentity(other ManagedUpdateRecord) bool {
	return sameManagedUpdateIdentity(record, other)
}

func managedUpdateSubjectKey(databaseID, partitionID, operationID string, phase ManagedUpdatePhase) (string, error) {
	if !entityid.Valid(databaseID) || !entityid.Valid(partitionID) ||
		!entityid.Valid(operationID) ||
		phase != ManagedUpdatePrepared && phase != ManagedUpdateCanaryServing && phase != ManagedUpdateHeld {
		return "", errors.New("managed update subject identity is invalid")
	}
	return strings.Join([]string{databaseID, partitionID, operationID, string(phase)}, "."), nil
}

func (r *Runtime) readManagedUpdatePhase(
	ctx context.Context,
	databaseID, partitionID, operationID string,
	phase ManagedUpdatePhase,
) (LogEntry, error) {
	if r == nil || r.readStream == nil {
		return LogEntry{}, ErrNotFound
	}
	r.readMu.Lock()
	defer r.readMu.Unlock()
	return readManagedUpdatePhase(ctx, r.readStream, r.config.Scope,
		databaseID, partitionID, operationID, phase)
}

func readManagedUpdatePhase(
	ctx context.Context,
	stream jetstream.Stream,
	scope, databaseID, partitionID, operationID string,
	phase ManagedUpdatePhase,
) (LogEntry, error) {
	subjectKey, err := managedUpdateSubjectKey(databaseID, partitionID, operationID, phase)
	if err != nil {
		return LogEntry{}, err
	}
	return readManagedUpdateSubject(ctx, stream, scope, subjectKey, operationID, phase)
}

func readManagedUpdateSubject(
	ctx context.Context,
	stream jetstream.Stream,
	scope, subjectKey, operationID string,
	phase ManagedUpdatePhase,
) (LogEntry, error) {
	entry, err := stream.GetLastMsgForSubject(ctx, mutationSubject(scope, MutationManagedUpdate, subjectKey))
	if errors.Is(err, jetstream.ErrMsgNotFound) {
		return LogEntry{}, ErrNotFound
	}
	if err != nil {
		return LogEntry{}, err
	}
	record, err := decodeControlRecord(entry.Data)
	if err != nil || record.Scope != scope || record.Kind != MutationManagedUpdate ||
		record.SubjectKey != subjectKey {
		return LogEntry{}, errors.New("managed update control log identity is invalid")
	}
	result := LogEntry{Kind: record.Kind, SubjectKey: record.SubjectKey, OperationID: record.OperationID,
		Epoch: record.Epoch, Sequence: entry.Sequence, CreatedAt: entry.Time, Payload: bytes.Clone(record.Payload)}
	if _, err := decodeManagedUpdateRecord(result, scope, "", "", operationID, phase); err != nil {
		return LogEntry{}, err
	}
	return result, nil
}

func readManagedUpdateOperation(
	ctx context.Context,
	stream jetstream.Stream,
	scope, databaseID, partitionID, operationID string,
) ([]LogEntry, error) {
	entries := make([]LogEntry, 0, 3)
	for _, phase := range []ManagedUpdatePhase{ManagedUpdatePrepared, ManagedUpdateCanaryServing, ManagedUpdateHeld} {
		entry, err := readManagedUpdatePhase(ctx, stream, scope, databaseID, partitionID, operationID, phase)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	if len(entries) == 0 {
		return nil, ErrNotFound
	}
	slices.SortFunc(entries, compareLogEntrySequence)
	firstPhase := managedUpdatePhaseFromSubject(entries[0].SubjectKey)
	if firstPhase != ManagedUpdatePrepared || len(entries) > 2 {
		return nil, errors.New("managed update history has an invalid phase sequence")
	}
	var identity ManagedUpdateRecord
	for index, entry := range entries {
		phase := managedUpdatePhaseFromSubject(entry.SubjectKey)
		record, err := decodeManagedUpdateRecord(entry, scope, databaseID, partitionID, operationID, phase)
		if err != nil {
			return nil, err
		}
		if index == 0 {
			identity = record
		} else if phase == ManagedUpdatePrepared || !sameManagedUpdateIdentity(identity, record) {
			return nil, errors.New("managed update phase history changed immutable signed request identity")
		}
	}
	return entries, nil
}

func listManagedUpdateEntries(
	ctx context.Context,
	stream jetstream.Stream,
	scope, databaseID, partitionID string,
) ([]LogEntry, error) {
	if _, err := placementIntentSubjectKey(databaseID, partitionID); err != nil {
		return nil, err
	}
	prefix := fmt.Sprintf("%s.%s.placement.managed-update.%s.%s.",
		controlSubjectRoot, scope, databaseID, partitionID)
	info, err := stream.Info(ctx, jetstream.WithSubjectFilter(prefix+">"))
	if err != nil {
		return nil, err
	}
	if err := verifyControlStreamConfig(info.Config, info.Config.Replicas); err != nil {
		return nil, err
	}
	if len(info.State.Subjects) > maxManagedUpdateRecords*3 {
		return nil, ErrListTooLarge
	}
	entries := make([]LogEntry, 0, len(info.State.Subjects))
	operations := make(map[string]struct{})
	for subject := range info.State.Subjects {
		key, ok := strings.CutPrefix(subject, prefix)
		if !ok {
			return nil, errors.New("managed update subject is outside its workload prefix")
		}
		parts := strings.Split(key, ".")
		if len(parts) != 2 || !entityid.Valid(parts[0]) {
			return nil, errors.New("managed update subject has an invalid operation identity")
		}
		phase := ManagedUpdatePhase(parts[1])
		if phase != ManagedUpdatePrepared && phase != ManagedUpdateCanaryServing && phase != ManagedUpdateHeld {
			return nil, errors.New("managed update subject has an invalid phase")
		}
		key = strings.Join([]string{databaseID, partitionID, parts[0], parts[1]}, ".")
		entry, err := readManagedUpdateSubject(ctx, stream, scope, key, parts[0], phase)
		if err != nil {
			return nil, err
		}
		if _, err := decodeManagedUpdateRecord(entry, scope, databaseID, partitionID, parts[0], phase); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
		operations[parts[0]] = struct{}{}
	}
	for operationID := range operations {
		if _, err := readManagedUpdateOperation(ctx, stream, scope, databaseID, partitionID, operationID); err != nil {
			return nil, err
		}
	}
	slices.SortFunc(entries, compareLogEntrySequence)
	return entries, nil
}

func decodeManagedUpdateRecord(
	entry LogEntry,
	scope, databaseID, partitionID, operationID string,
	phase ManagedUpdatePhase,
) (ManagedUpdateRecord, error) {
	var record ManagedUpdateRecord
	if entry.Kind != MutationManagedUpdate || entry.Sequence == 0 || entry.Epoch == 0 ||
		entry.OperationID != operationID || entry.Payload == nil {
		return record, errors.New("managed update log entry identity is invalid")
	}
	if err := json.Unmarshal(entry.Payload, &record, json.RejectUnknownMembers(true)); err != nil {
		return record, err
	}
	canonical, err := json.Marshal(record, json.Deterministic(true))
	if err != nil || !bytes.Equal(entry.Payload, canonical) || record.Validate() != nil ||
		record.Cell != scope || databaseID != "" && record.DatabaseID != databaseID ||
		partitionID != "" && record.PartitionID != partitionID ||
		record.OperationID != operationID || record.Phase != phase {
		return record, errors.New("managed update log payload is noncanonical or differs from its subject")
	}
	wantKey, err := managedUpdateSubjectKey(record.DatabaseID, record.PartitionID, record.OperationID, record.Phase)
	if err != nil || entry.SubjectKey != wantKey {
		return record, errors.New("managed update log subject differs from its signed request identity")
	}
	return record, nil
}

func managedUpdatePhaseFromSubject(subjectKey string) ManagedUpdatePhase {
	_, phase, ok := strings.CutLast(subjectKey, ".")
	if !ok {
		return ""
	}
	return ManagedUpdatePhase(phase)
}

func compareLogEntrySequence(left, right LogEntry) int {
	if left.Sequence < right.Sequence {
		return -1
	}
	if left.Sequence > right.Sequence {
		return 1
	}
	return 0
}
