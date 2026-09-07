package databaseadmission

import (
	"context"
	"errors"
	"math"
	"reflect"
	"slices"
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
	request, facts := r.Restore, r.RestoreFacts
	if ValidateRestoreRequest(*request) != nil || facts == nil || !validDigest(facts.PointID) || !validDigest(facts.SourceDigest) || !validDigest(facts.Checksum) || facts.CapturedAtMillis == 0 || facts.Epoch == 0 || !validJournalCut(facts.JournalCut) || !validRestoreProvider(facts.Provider) {
		return ErrInvalid
	}
	if request.Environment != r.Request.Environment || request.TenantID != r.Request.TenantID || request.ProjectID != r.Request.ProjectID || request.Name != r.Request.Name || request.OperationID != r.Request.OperationID || request.SourceDatabaseID != r.Request.ParentDatabaseID || facts.PointID != r.Request.RecoveryPointID || facts.JournalCut != r.Request.JournalCut || facts.Provider != r.Request.RestoreProvider || facts.Epoch != r.Request.RestoreEpoch {
		return ErrInvalid
	}
	if request.Selection.Kind == "point_id" && request.Selection.PointID != facts.PointID || request.Selection.Kind == "unix_millis" && facts.CapturedAtMillis > uint64(request.Selection.UnixMillis) {
		return ErrInvalid
	}
	return nil
}
