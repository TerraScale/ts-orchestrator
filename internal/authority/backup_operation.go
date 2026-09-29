package authority

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"uuid"
)

// BackupOperationRecord is the sole allocator for signed backup attempts in
// one partition. The exact Prepare is committed here before any host delivery.
// A terminal Abort retains the attempt high water when the next operation is
// allocated at the same catalog ordinal.
type BackupOperationRecord struct {
	Version               uint64                  `json:"version"`
	DatabaseID            string                  `json:"database_id"`
	PartitionID           string                  `json:"partition_id"`
	PlacementSequence     uint64                  `json:"placement_sequence"`
	SourceScopeDigest     string                  `json:"source_scope_digest"`
	SourceAuthoritySHA256 string                  `json:"source_authority_sha256"`
	SourceConfigurationID string                  `json:"source_configuration_id"`
	SourceTargetDigest    string                  `json:"source_target_digest"`
	BackupSet             string                  `json:"backup_set"`
	BackupTargetDigest    string                  `json:"backup_target_digest"`
	CompletedOrdinal      uint64                  `json:"completed_ordinal"`
	AttemptHighWater      uint64                  `json:"attempt_high_water"`
	Ordinal               uint64                  `json:"ordinal"`
	Attempt               uint64                  `json:"attempt"`
	OperationID           string                  `json:"operation_id"`
	Nonce                 string                  `json:"nonce"`
	PrepareEnvelope       []byte                  `json:"prepare_envelope"`
	PrepareExpiresAtMS    uint64                  `json:"prepare_expires_at_ms"`
	AbortEnvelope         []byte                  `json:"abort_envelope,omitempty"`
	AbortExpiresAtMS      uint64                  `json:"abort_expires_at_ms,omitzero"`
	State                 string                  `json:"state"`
	Roster                []BackupOperationMember `json:"roster"`
	Terminal              []BackupTerminalReceipt `json:"terminal,omitempty"`
}

type BackupOperationMember struct {
	Origin            string `json:"origin"`
	MemberID          string `json:"member_id"`
	Incarnation       string `json:"incarnation"`
	TLSLeafSHA256     string `json:"tls_leaf_sha256"`
	Node              string `json:"node"`
	Role              string `json:"role"`
	CutEnvelope       []byte `json:"cut_envelope,omitempty"`
	AbortAcknowledged bool   `json:"abort_acknowledged,omitzero"`
}

type BackupTerminalReceipt struct {
	OperationID string `json:"operation_id"`
	Ordinal     uint64 `json:"ordinal"`
	Attempt     uint64 `json:"attempt"`
	State       string `json:"state"`
}

func backupHex(value string, bytes int) bool {
	if len(value) != bytes*2 {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			if c < 'a' || c > 'f' {
				return false
			}
		}
	}
	return true
}

func backupUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil() && parsed.String() == value
}

func (record BackupOperationRecord) validate() error {
	if record.Version != 1 || record.DatabaseID == "" || record.PartitionID == "" ||
		record.PlacementSequence == 0 ||
		!backupHex(record.SourceScopeDigest, 32) || !backupHex(record.SourceAuthoritySHA256, 32) ||
		!backupHex(record.SourceConfigurationID, 32) || !backupHex(record.SourceTargetDigest, 32) ||
		!backupHex(record.BackupSet, 16) || !backupHex(record.BackupTargetDigest, 32) ||
		record.Ordinal == 0 || record.CompletedOrdinal == math.MaxUint64 ||
		record.Ordinal != record.CompletedOrdinal+1 || record.Attempt == 0 ||
		record.Attempt != record.AttemptHighWater || !backupUUID(record.OperationID) ||
		!backupHex(record.Nonce, 16) || len(record.PrepareEnvelope) == 0 ||
		len(record.PrepareEnvelope) > 64<<10 || record.PrepareExpiresAtMS == 0 ||
		record.PrepareExpiresAtMS > math.MaxInt64-30_000 ||
		len(record.AbortEnvelope) > 64<<10 ||
		len(record.Roster) < 2 || len(record.Roster) > 8 || len(record.Terminal) > 1024 {
		return errors.New("backup operation allocator record is invalid")
	}
	if record.State != "accepted" && record.State != "held" && record.State != "uncertain" &&
		record.State != "aborting" && record.State != "aborted" {
		return errors.New("backup operation allocator state is invalid")
	}
	if record.AbortExpiresAtMS > math.MaxInt64-30_000 ||
		(len(record.AbortEnvelope) == 0) != (record.AbortExpiresAtMS == 0) ||
		(record.State == "aborting" || record.State == "aborted") && len(record.AbortEnvelope) == 0 ||
		(record.State == "accepted" || record.State == "held") && len(record.AbortEnvelope) != 0 {
		return errors.New("backup abort envelope is inconsistent with state")
	}
	memberIDs := make(map[string]bool, len(record.Roster))
	hostRoles := make(map[string]bool, len(record.Roster))
	for index, member := range record.Roster {
		hostRole := member.Node + "\x00" + member.Role
		if !backupUUID(member.MemberID) || !backupHex(member.Origin, 32) ||
			!backupHex(member.Incarnation, 16) || !backupHex(member.TLSLeafSHA256, 32) ||
			!natsToken.MatchString(member.Node) || !natsToken.MatchString(member.Role) ||
			!strings.HasPrefix(member.Origin, strings.ReplaceAll(member.MemberID, "-", "")) ||
			!strings.HasSuffix(member.Origin, member.Incarnation) ||
			len(member.CutEnvelope) > 64<<10 ||
			index > 0 && record.Roster[index-1].Origin >= member.Origin ||
			memberIDs[member.MemberID] || hostRoles[hostRole] {
			return errors.New("backup operation roster is invalid")
		}
		memberIDs[member.MemberID] = true
		hostRoles[hostRole] = true
		if member.AbortAcknowledged && len(record.AbortEnvelope) == 0 {
			return errors.New("backup member acknowledged an absent Abort")
		}
	}
	if record.State == "aborted" {
		for _, member := range record.Roster {
			if !member.AbortAcknowledged {
				return errors.New("backup abort lacks a roster acknowledgment")
			}
		}
	}
	if record.State == "held" {
		for _, member := range record.Roster {
			if len(member.CutEnvelope) == 0 {
				return errors.New("backup held state lacks a roster cut")
			}
		}
	}
	for _, terminal := range record.Terminal {
		if !backupUUID(terminal.OperationID) || terminal.Ordinal == 0 ||
			terminal.Attempt == 0 || terminal.State != "aborted" {
			return errors.New("backup terminal receipt is invalid")
		}
	}
	return nil
}

func sameBackupBinding(left, right BackupOperationRecord) bool {
	if left.Version != right.Version || left.DatabaseID != right.DatabaseID ||
		left.PartitionID != right.PartitionID || left.PlacementSequence != right.PlacementSequence ||
		left.SourceScopeDigest != right.SourceScopeDigest ||
		left.SourceAuthoritySHA256 != right.SourceAuthoritySHA256 ||
		left.SourceConfigurationID != right.SourceConfigurationID ||
		left.SourceTargetDigest != right.SourceTargetDigest || left.BackupSet != right.BackupSet ||
		left.BackupTargetDigest != right.BackupTargetDigest ||
		left.CompletedOrdinal != right.CompletedOrdinal || left.AttemptHighWater != right.AttemptHighWater ||
		left.Ordinal != right.Ordinal || left.Attempt != right.Attempt ||
		left.OperationID != right.OperationID || left.Nonce != right.Nonce ||
		left.PrepareExpiresAtMS != right.PrepareExpiresAtMS ||
		!bytes.Equal(left.PrepareEnvelope, right.PrepareEnvelope) || len(left.Roster) != len(right.Roster) {
		return false
	}
	for index, member := range left.Roster {
		other := right.Roster[index]
		if member.Origin != other.Origin || member.MemberID != other.MemberID ||
			member.Incarnation != other.Incarnation || member.TLSLeafSHA256 != other.TLSLeafSHA256 ||
			member.Node != other.Node || member.Role != other.Role {
			return false
		}
	}
	return true
}

func validateBackupTransition(prior *BackupOperationRecord, next BackupOperationRecord) error {
	if err := next.validate(); err != nil {
		return err
	}
	if prior == nil {
		if next.CompletedOrdinal != 0 || next.Ordinal != 1 || next.Attempt != 1 ||
			next.State != "accepted" || len(next.AbortEnvelope) != 0 || len(next.Terminal) != 0 {
			return ErrInvalidTransition
		}
		return nil
	}
	if next.DatabaseID != prior.DatabaseID || next.PartitionID != prior.PartitionID ||
		next.SourceAuthoritySHA256 != prior.SourceAuthoritySHA256 ||
		next.BackupSet != prior.BackupSet || next.CompletedOrdinal != prior.CompletedOrdinal {
		return ErrInvalidTransition
	}
	if next.OperationID != prior.OperationID {
		terminal := BackupTerminalReceipt{OperationID: prior.OperationID,
			Ordinal: prior.Ordinal, Attempt: prior.Attempt, State: prior.State}
		wantTerminal := append(slices.Clone(prior.Terminal), terminal)
		if len(wantTerminal) > 1024 {
			wantTerminal = wantTerminal[len(wantTerminal)-1024:]
		}
		if prior.State != "aborted" || next.Ordinal != prior.Ordinal ||
			prior.AttemptHighWater == math.MaxUint64 ||
			next.Attempt != prior.AttemptHighWater+1 || next.State != "accepted" ||
			next.Nonce == prior.Nonce || len(next.AbortEnvelope) != 0 ||
			!slices.Equal(next.Terminal, wantTerminal) {
			return ErrInvalidTransition
		}
		return nil
	}
	if len(next.Roster) != len(prior.Roster) || !sameBackupBinding(*prior, next) ||
		next.AttemptHighWater != prior.AttemptHighWater ||
		!slices.Equal(next.Terminal, prior.Terminal) {
		return ErrInvalidTransition
	}
	for index, old := range prior.Roster {
		member := next.Roster[index]
		if len(old.CutEnvelope) != 0 && !bytes.Equal(old.CutEnvelope, member.CutEnvelope) ||
			old.AbortAcknowledged && !member.AbortAcknowledged ||
			prior.State != "aborting" && next.State == "aborting" && member.AbortAcknowledged {
			return ErrInvalidTransition
		}
	}
	if len(prior.AbortEnvelope) != 0 && !bytes.Equal(prior.AbortEnvelope, next.AbortEnvelope) &&
		(next.AbortExpiresAtMS <= prior.AbortExpiresAtMS || prior.State == "aborted") {
		return ErrInvalidTransition
	}
	if prior.State == "aborted" ||
		prior.State == "accepted" && next.State != "accepted" && next.State != "held" && next.State != "aborting" ||
		prior.State == "held" && next.State != "held" && next.State != "aborting" ||
		prior.State == "uncertain" && next.State != "uncertain" && next.State != "aborting" ||
		prior.State == "aborting" && next.State != "aborting" && next.State != "aborted" {
		return ErrInvalidTransition
	}
	return nil
}

func decodeBackupRecord(payload []byte, databaseID, partitionID string) (BackupOperationRecord, error) {
	var record BackupOperationRecord
	if err := json.Unmarshal(payload, &record, json.RejectUnknownMembers(true)); err != nil {
		return BackupOperationRecord{}, err
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(canonical, payload) ||
		record.DatabaseID != databaseID || record.PartitionID != partitionID || record.validate() != nil {
		return BackupOperationRecord{}, errors.New("backup operation control record is invalid")
	}
	return record, nil
}

func (r *Runtime) ReadBackupOperation(ctx context.Context, databaseID, partitionID string) (BackupOperationRecord, uint64, error) {
	key, err := placementIntentSubjectKey(databaseID, partitionID)
	if err != nil {
		return BackupOperationRecord{}, 0, err
	}
	entry, err := r.ReadHostMutation(ctx, MutationBackupOperation, key)
	if err != nil {
		return BackupOperationRecord{}, 0, err
	}
	record, err := decodeBackupRecord(entry.Payload, databaseID, partitionID)
	return record, entry.Sequence, err
}

func (r *Reader) ReadBackupOperation(ctx context.Context, databaseID, partitionID string) (BackupOperationRecord, uint64, error) {
	key, err := placementIntentSubjectKey(databaseID, partitionID)
	if err != nil {
		return BackupOperationRecord{}, 0, err
	}
	entry, err := r.ReadHostMutation(ctx, MutationBackupOperation, key)
	if err != nil {
		return BackupOperationRecord{}, 0, err
	}
	record, err := decodeBackupRecord(entry.Payload, databaseID, partitionID)
	return record, entry.Sequence, err
}

// CommitBackupOperation verifies the monotonic transition, then uses the same
// global lease/subject CAS and exact unknown-publish readback as placement.
func (r *Runtime) CommitBackupOperation(ctx context.Context, epoch uint64,
	databaseID, partitionID string, expectedSequence uint64, next BackupOperationRecord,
) (uint64, error) {
	return r.CommitBackupOperationVerified(ctx, epoch, databaseID, partitionID,
		expectedSequence, next, nil)
}

// CommitBackupOperationVerified adds a caller-owned final check to new
// operation admission. The check runs under the same authority mutation lock
// as the backup and managed-update R3 compare-and-set.
func (r *Runtime) CommitBackupOperationVerified(ctx context.Context, epoch uint64,
	databaseID, partitionID string, expectedSequence uint64, next BackupOperationRecord,
	callerVerify func(context.Context) error,
) (uint64, error) {
	key, err := placementIntentSubjectKey(databaseID, partitionID)
	if err != nil {
		return 0, err
	}
	if next.DatabaseID != databaseID || next.PartitionID != partitionID {
		return 0, ErrInvalidTransition
	}
	var prior *BackupOperationRecord
	current, sequence, err := r.ReadBackupOperation(ctx, databaseID, partitionID)
	if err == nil {
		prior = &current
	} else if !errors.Is(err, ErrNotFound) {
		return 0, err
	}
	if sequence != expectedSequence {
		return 0, ErrConflict
	}
	newOperation := prior == nil || next.OperationID != prior.OperationID
	if newOperation && callerVerify == nil {
		return 0, ErrFenced
	}
	if err := validateBackupTransition(prior, next); err != nil {
		return 0, err
	}
	payload, err := json.Marshal(next)
	if err != nil || len(payload) > maxControlPayload {
		return 0, errors.New("backup operation control payload exceeds bound")
	}
	release, err := r.beginWorkloadGate(ctx, WorkloadScope{DatabaseID: databaseID, PartitionID: partitionID})
	if err != nil {
		return 0, err
	}
	defer release()
	if err := r.requireNoTerminalIntent(ctx, databaseID, partitionID); err != nil {
		return 0, err
	}
	digest := sha256.Sum256(payload)
	mutationID := "backup-" + hex.EncodeToString(digest[:16])
	var verify func(context.Context) error
	if newOperation {
		verify = func(check context.Context) error {
			placement, err := r.ReadPlacementIntent(check, databaseID, partitionID)
			if err != nil {
				return err
			}
			if placement.Sequence != next.PlacementSequence {
				return ErrFenced
			}
			if err := r.requireNoActiveManagedUpdate(check, databaseID, partitionID); err != nil {
				return err
			}
			if err := r.requireNoTerminalIntent(check, databaseID, partitionID); err != nil {
				return err
			}
			if callerVerify != nil {
				return callerVerify(check)
			}
			return nil
		}
	}
	committed, err := r.commitMutationVerified(ctx, epoch, MutationBackupOperation,
		key, mutationID, expectedSequence, payload, verify)
	if err != nil {
		return 0, err
	}
	observed, observedSequence, err := r.ReadBackupOperation(ctx, databaseID, partitionID)
	if err != nil || observedSequence != committed {
		return 0, fmt.Errorf("%w: backup operation readback: %v", ErrOutcomeUnknown, err)
	}
	wire, err := json.Marshal(observed)
	if err != nil || !bytes.Equal(wire, payload) {
		return 0, ErrOperationConflict
	}
	return committed, nil
}

// An active hold or unresolved Abort fences placement and terminal changes.
// Call this inside the globally ordered R3 mutation retry.
func (r *Runtime) requireNoActiveBackup(ctx context.Context, databaseID, partitionID string) error {
	record, _, err := r.ReadBackupOperation(ctx, databaseID, partitionID)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if record.State != "aborted" {
		return ErrFenced
	}
	return nil
}

// A new backup cannot start while a signed managed update is still preparing
// or awaiting its canary outcome. Call this from commitMutationVerified so it
// shares the typed workload gate and final Runtime.mu sequence boundary with
// CommitManagedUpdate. A durable Held result is terminal, but backup admission
// still requires the caller's final exact-serving-roster check because the
// failed canary may no longer be serving.
func (r *Runtime) requireNoActiveManagedUpdate(ctx context.Context, databaseID, partitionID string) error {
	entry, err := r.ReadManagedUpdate(ctx, databaseID, partitionID)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	_, phase, ok := strings.CutLast(entry.SubjectKey, ".")
	if !ok {
		return errors.New("managed update subject has no phase")
	}
	switch ManagedUpdatePhase(phase) {
	case ManagedUpdatePrepared, ManagedUpdateCanaryServing:
		return ErrFenced
	case ManagedUpdateHeld:
		return nil
	default:
		return errors.New("managed update phase is invalid")
	}
}
