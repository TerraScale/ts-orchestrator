package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/restoredrill"
)

// productionDatabaseBranchPort uses the already admitted database pipeline to
// create an isolated child identity. The pipeline persists the child and its
// parent-bound branch evidence under the same NATS authority and is therefore
// safe to retry with the deterministic operation identity.
type productionDatabaseBranchPort struct {
	database **productionDatabase
}

func (p productionDatabaseBranchPort) CreateScratch(ctx context.Context, request restoredrill.ScratchBranchRequest) (restoredrill.ScratchBranch, error) {
	if p.database == nil || *p.database == nil || (*p.database).pipeline == nil || (*p.database).lifecycleJournal == nil {
		return restoredrill.ScratchBranch{}, errors.New("restore branch: admitted database pipeline is unavailable")
	}
	if request.SourceDatabaseID == "" || request.RecoveryPointID == "" || request.JournalCut == "" || request.RestoreEpoch == 0 || request.IdempotencyKey == "" {
		return restoredrill.ScratchBranch{}, restoredrill.ErrInvalidRestoreRequest
	}
	database := *p.database
	parent, err := database.AcceptedRecord(ctx, request.SourceDatabaseID)
	if err != nil {
		return restoredrill.ScratchBranch{}, err
	}
	if err := database.check(ctx); err != nil {
		return restoredrill.ScratchBranch{}, err
	}
	digest := sha256.Sum256([]byte(request.IdempotencyKey))
	childRequest := parent.Request
	childRequest.ParentDatabaseID = parent.DatabaseID
	childRequest.Name = "restore-" + hex.EncodeToString(digest[:])[:32]
	childRequest.OperationID = request.IdempotencyKey
	child, err := database.pipeline.Accept(ctx, childRequest)
	if err != nil {
		return restoredrill.ScratchBranch{}, err
	}
	return restoredrill.ScratchBranch{ID: child.DatabaseID}, nil
}

func (p productionDatabaseBranchPort) Stats(context.Context, restoredrill.ScratchBranch) (restoredrill.RestoreStats, error) {
	return restoredrill.RestoreStats{}, fmt.Errorf("%w: native branch statistics target", ErrProductionGlobalDependency)
}

func (p productionDatabaseBranchPort) Delete(ctx context.Context, branch restoredrill.ScratchBranch) error {
	if p.database == nil || *p.database == nil || (*p.database).deletion == nil || branch.ID == "" {
		return errors.New("restore branch: deletion workflow is unavailable")
	}
	database := *p.database
	record, err := database.AcceptedRecord(ctx, branch.ID)
	if err != nil {
		return err
	}
	_, err = database.deletion.Begin(ctx, databaseadmission.DeleteRequest{
		Environment: record.Request.Environment, TenantID: record.Request.TenantID,
		ProjectID: record.Request.ProjectID, DatabaseID: record.DatabaseID,
		OperationID: "restore-delete-" + branch.ID,
	})
	return err
}

// productionAdmissionDatabaseLister is the read side of the restore bridge.
// It projects only durable, validated admission records; no creation timestamp
// or process-local inventory is treated as a serving database fact.
type productionAdmissionDatabaseLister struct {
	journal *databaseadmission.NATSJournal
}

func (l productionAdmissionDatabaseLister) ListDatabases(ctx context.Context) ([]restoredrill.Database, error) {
	if l.journal == nil {
		return nil, errors.New("restore database inventory: admission journal is unavailable")
	}
	records, err := l.journal.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("restore database inventory: %w", err)
	}
	result := make([]restoredrill.Database, 0, len(records))
	for _, record := range records {
		if databaseadmission.ValidateRecord(record) != nil {
			return nil, errors.New("restore database inventory: invalid admission record")
		}
		if len(record.Request.Regions) == 0 {
			return nil, errors.New("restore database inventory: admitted record has no placement Region")
		}
		result = append(result, restoredrill.Database{ID: record.DatabaseID, Region: record.Request.Regions[0]})
	}
	return result, nil
}
