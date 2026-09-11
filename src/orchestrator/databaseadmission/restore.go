package databaseadmission

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/oklog/ulid"
	"github.com/zeebo/blake3"
)

// RestoreConfig is supplied by the native recovery authority. Resolve must
// authenticate the source point and backup configuration before target admission.
// Restore must return only after durable native installation and receipt verification.
// Neither callback accepts identity or grant fields from the public caller.
type RestoreConfig struct {
	Resolve func(context.Context, Record, RestoreSelection) (RestoreAdmissionFacts, error)
	Restore func(context.Context, Record) ([]byte, error)
}

// AcceptRestore reserves the same target namespace as create, while journaling
// the original restore selection separately from server-resolved immutable facts.
func (p *Pipeline) AcceptRestore(ctx context.Context, request RestoreRequest) (Record, error) {
	if ValidateRestoreRequest(request) != nil {
		return Record{}, ErrInvalid
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.config.CheckAuthority(ctx); err != nil {
		return Record{}, err
	}
	records, err := p.config.Journal.List(ctx)
	if err != nil {
		return Record{}, err
	}
	scope := Request{Environment: request.Environment, TenantID: request.TenantID, ProjectID: request.ProjectID, Name: request.Name, OperationID: request.OperationID}
	var parent *Record
	var epoch uint64
	for _, record := range records {
		if operationKey(record.Request) == operationKey(scope) {
			if record.Restore == nil || !reflect.DeepEqual(*record.Restore, request) {
				return Record{}, ErrConflict
			}
			if err := p.config.Authorize(ctx, record.Request); err != nil {
				return Record{}, err
			}
			return record, nil
		}
		if ScopeKey(record.Request) == ScopeKey(scope) {
			return Record{}, ErrConflict
		}
		if record.DatabaseID == request.SourceDatabaseID {
			parent = new(record)
		}
		epoch = max(epoch, record.Request.RestoreEpoch)
	}
	if parent == nil {
		return Record{}, ErrForbidden
	}
	source := parent.Request
	if source.Environment != request.Environment || source.TenantID != request.TenantID || source.ProjectID != request.ProjectID {
		return Record{}, ErrForbidden
	}
	if parent.State != "ready" {
		return Record{}, ErrConflict
	}
	if err := p.config.Authorize(ctx, source); err != nil {
		return Record{}, err
	}
	scope.ParentDatabaseID, scope.Regions, scope.Residency = parent.DatabaseID, slices.Clone(source.Regions), source.Residency
	if err := p.config.Authorize(ctx, scope); err != nil {
		return Record{}, err
	}
	if p.config.Restore == nil || p.config.Restore.Resolve == nil || p.config.Restore.Restore == nil {
		return Record{}, errors.New("database restore: native authority unavailable")
	}
	facts, err := p.config.Restore.Resolve(ctx, *parent, request.Selection)
	if err != nil {
		return Record{}, err
	}
	// The control journal owns the epoch. Native resolution cannot inject one.
	if facts.Epoch != 0 || epoch == math.MaxUint64 {
		return Record{}, ErrInvalid
	}
	if facts.SourceDigest != RestoreSourceDigest(*parent) {
		return Record{}, ErrInvalid
	}
	facts = cloneRestoreAdmissionFacts(facts)
	facts.Epoch = epoch + 1
	scope.RecoveryPointID, scope.JournalCut, scope.RestoreProvider, scope.RestoreEpoch = facts.PointID, facts.JournalCut, facts.Provider, facts.Epoch
	record := Record{Request: scope, Restore: new(request), RestoreFacts: new(facts)}
	if validateRestoreRecord(record) != nil {
		return Record{}, ErrInvalid
	}
	if err := p.config.CheckAuthority(ctx); err != nil {
		return Record{}, err
	}
	return p.acceptRecord(ctx, record)
}

// RestoreSourceDigest identifies immutable source identity. Mutable progress
// and readiness evidence are excluded so the value remains stable on replay.
func RestoreSourceDigest(source Record) string {
	value, _ := json.Marshal(struct {
		Environment string   `json:"environment"`
		TenantID    string   `json:"tenant_id"`
		ProjectID   string   `json:"project_id"`
		Name        string   `json:"name"`
		OperationID string   `json:"operation_id"`
		DatabaseID  string   `json:"database_id"`
		KeyVersion  string   `json:"key_version"`
		Regions     []string `json:"regions"`
		Residency   string   `json:"residency"`
	}{source.Request.Environment, source.Request.TenantID, source.Request.ProjectID, source.Request.Name, source.Request.OperationID, source.DatabaseID, source.KeyVersion, source.Request.Regions, source.Request.Residency})
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func validateRestoreAcknowledgement(record Record, raw []byte) error {
	var acknowledgement RestoreAcknowledgement
	if json.Unmarshal(raw, &acknowledgement, json.RejectUnknownMembers(true)) != nil || acknowledgement.Version != 1 || record.Restore == nil || record.RestoreFacts == nil || acknowledgement.TargetDatabaseID != record.DatabaseID || acknowledgement.SourceDatabaseID != record.Request.ParentDatabaseID || !reflect.DeepEqual(acknowledgement.Facts, *record.RestoreFacts) {
		return ErrInvalid
	}
	return nil
}

func validateRestoreRecord(r Record) error {
	if r.Restore == nil {
		if r.RestoreFacts != nil || len(r.RestoreReceipt) != 0 {
			return ErrInvalid
		}
		return nil
	}
	if len(r.RestoreReceipt) > 32<<10 {
		return ErrInvalid
	}
	if len(r.RestoreReceipt) > 0 && validateRestoreAcknowledgement(r, r.RestoreReceipt) != nil {
		return ErrInvalid
	}
	request, facts := r.Restore, r.RestoreFacts
	if ValidateRestoreRequest(*request) != nil || facts == nil || !validDigest(facts.PointID) || !validDigest(facts.SourceDigest) || !validDigest(facts.RecoveryPointDigest) || !validDigest(facts.Checksum) || facts.CapturedAtMillis == 0 || facts.CapturedAtMillis > math.MaxInt64 || facts.RowCount > math.MaxInt64 || facts.Epoch == 0 || !validJournalCut(facts.JournalCut) || !validRestoreProvider(facts.Provider) || validateRestoreEnvelope(facts, request.SourceDatabaseID) != nil {
		return ErrInvalid
	}
	if request.Environment != r.Request.Environment || request.TenantID != r.Request.TenantID || request.ProjectID != r.Request.ProjectID || request.Name != r.Request.Name || request.OperationID != r.Request.OperationID || request.SourceDatabaseID != r.Request.ParentDatabaseID || facts.PointID != r.Request.RecoveryPointID || facts.JournalCut != r.Request.JournalCut || facts.Provider != r.Request.RestoreProvider || facts.Epoch != r.Request.RestoreEpoch {
		return ErrInvalid
	}
	if request.Selection.Kind == "point_id" && request.Selection.PointID != facts.PointID {
		return ErrInvalid
	}
	return nil
}

func cloneRestoreAdmissionFacts(facts RestoreAdmissionFacts) RestoreAdmissionFacts {
	clone := facts
	if facts.Envelope != nil {
		envelope := *facts.Envelope
		envelope.Participants = slices.Clone(facts.Envelope.Participants)
		clone.Envelope = &envelope
	}
	return clone
}

func validateRestoreEnvelope(facts *RestoreAdmissionFacts, sourceDatabaseID string) error {
	if facts.Envelope == nil {
		return nil
	}
	envelope := facts.Envelope
	if !validDigest(envelope.EnvelopeDigest) || envelope.DatabaseID != sourceDatabaseID || !canonicalID.MatchString(envelope.DatabaseID) || len(envelope.DatabaseIncarnation) != 32 || strings.ToLower(envelope.DatabaseIncarnation) != envelope.DatabaseIncarnation || envelope.RouteGeneration == math.MaxUint64 || len(envelope.Participants) == 0 || len(envelope.Participants) > 64 {
		return ErrInvalid
	}
	incarnation, err := strconv.ParseUint(envelope.DatabaseIncarnation[:16], 16, 64)
	if err != nil {
		return ErrInvalid
	}
	if _, err := strconv.ParseUint(envelope.DatabaseIncarnation[16:], 16, 64); err != nil || envelope.DatabaseIncarnation == strings.Repeat("0", 32) {
		return ErrInvalid
	}
	var wire [16]byte
	for i := range 8 {
		wire[i] = byte(incarnation >> (56 - 8*i))
	}
	low, _ := strconv.ParseUint(envelope.DatabaseIncarnation[16:], 16, 64)
	for i := range 8 {
		wire[8+i] = byte(low >> (56 - 8*i))
	}
	if ulid.ULID(wire).String() != envelope.DatabaseID {
		return ErrInvalid
	}
	maxCut, maxCapture, totalRows := uint64(0), uint64(0), uint64(0)
	logical := make([]byte, 0, len(envelope.Participants)*80)
	previous := ""
	for _, participant := range envelope.Participants {
		if participant.DatabaseID != envelope.DatabaseID || participant.ParticipantID == previous || participant.ParticipantID < previous || len(participant.ParticipantID) != len("shard-")+16 || !strings.HasPrefix(participant.ParticipantID, "shard-") || strings.ToLower(participant.ParticipantID) != participant.ParticipantID {
			return ErrInvalid
		}
		shard, err := strconv.ParseUint(participant.ParticipantID[len("shard-"):], 16, 64)
		if err != nil || shard == 0 || !validDigest(participant.ManifestDigest) || !validDigest(participant.Checksum) || participant.JournalCut == 0 || participant.JournalCut > math.MaxInt64 || participant.CapturedAtMillis == 0 || participant.CapturedAtMillis > math.MaxInt64 || participant.RetainedUntilMillis < participant.CapturedAtMillis || participant.RowCount > math.MaxInt64 {
			return ErrInvalid
		}
		previous = participant.ParticipantID
		maxCut = max(maxCut, participant.JournalCut)
		maxCapture = max(maxCapture, participant.CapturedAtMillis)
		if totalRows > math.MaxInt64-participant.RowCount {
			return ErrInvalid
		}
		totalRows += participant.RowCount
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(participant.ParticipantID)))
		logical = append(logical, length[:]...)
		logical = append(logical, participant.ParticipantID...)
		binary.BigEndian.PutUint64(length[:], uint64(len(participant.Checksum)))
		logical = append(logical, length[:]...)
		logical = append(logical, participant.Checksum...)
	}
	prefix := []byte("terrabase-backup-envelope-logical-v1\x00")
	hash := blake3.Sum256(append(prefix, logical...))
	if facts.PointID != envelope.EnvelopeDigest || facts.RecoveryPointDigest != envelope.EnvelopeDigest || facts.Checksum != hexDigest(hash[:]) || facts.RowCount != totalRows || facts.CapturedAtMillis != maxCapture || facts.JournalCut != strconv.FormatUint(maxCut, 10) {
		return ErrInvalid
	}
	return nil
}

func hexDigest(value []byte) string { return hex.EncodeToString(value) }
