package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
	"terrascale.tech/orchestrator/src/orchestrator/restoredrill"
	"terrascale.tech/orchestrator/src/orchestrator/tbep"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

type productionDatabaseBackupPort struct {
	database **productionDatabase
	config   productionDatabaseConfig
}

func (p productionDatabaseBackupPort) ListDatabases(ctx context.Context) ([]restoredrill.Database, error) {
	if p.database == nil || *p.database == nil {
		return nil, errors.New("restore database inventory: admitted database is unavailable")
	}
	return (productionAdmissionDatabaseLister{journal: (*p.database).lifecycleJournal}).ListDatabases(ctx)
}

func (p productionDatabaseBackupPort) Restore(ctx context.Context, request restoredrill.RestoreRequest) error {
	if p.database == nil || *p.database == nil || (*p.database).lifecycleJournal == nil || request.SourceDatabaseID == "" || request.BranchID == "" {
		return errors.New("restore backup: admitted database authority is unavailable")
	}
	database := *p.database
	source, err := database.AcceptedRecord(ctx, request.SourceDatabaseID)
	if err != nil {
		return err
	}
	target, err := database.AcceptedRecord(ctx, request.BranchID)
	if err != nil {
		return err
	}
	if target.Request.ParentDatabaseID != source.DatabaseID || target.Request.RecoveryPointID != request.RecoveryPointID || target.Request.JournalCut != request.JournalCut || target.Request.RestoreEpoch != request.RestoreEpoch || target.BranchSource == nil {
		return errors.New("restore backup: source and target provenance differs")
	}
	var evidence databaseadmission.BranchSourceEvidence
	if json.Unmarshal(target.BranchSource.Evidence.Payload, &evidence) != nil || evidence.SourceSnapshotDigest == "" || evidence.RecoveryPointID != request.RecoveryPointID || evidence.JournalCut != request.JournalCut || evidence.RestoreEpoch != request.RestoreEpoch {
		return errors.New("restore backup: authenticated source point is unavailable")
	}
	placement, host, err := (productionDatabaseBackupPort{database: p.database, config: p.config}).targetAssignment(target)
	if err != nil {
		return err
	}
	client, err := newProductionTBEPClient(host, target)
	if err != nil {
		return err
	}
	defer client.Close()
	_, err = client.RestoreToTarget(ctx, placement, request.IdempotencyKey, source.Targets[0].ServerIdentity, source.DatabaseID, request.RecoveryPointID, evidence.SourceSnapshotDigest, host.ServerIdentity, target.DatabaseID, request.JournalCut, request.RestoreEpoch, pb.RestoreProvider_RESTORE_PROVIDER_OCI)
	return err
}

func (p productionDatabaseBackupPort) targetAssignment(record databaseadmission.Record) (tbep.LifecycleAssignment, productionDatabaseHost, error) {
	if len(record.PlacementTargets) == 0 || len(record.Targets) == 0 {
		return tbep.LifecycleAssignment{}, productionDatabaseHost{}, errors.New("restore backup: accepted target placement is unavailable")
	}
	accepted := record.PlacementTargets[0]
	if accepted.AcceptedEpoch == 0 || accepted.AcceptedRevision == 0 || accepted.AcceptedGeneration == 0 || len(accepted.AcceptedProof) == 0 || len(accepted.AcceptedReceipt) == 0 {
		return tbep.LifecycleAssignment{}, productionDatabaseHost{}, errors.New("restore backup: accepted target proof is incomplete")
	}
	var proof placementtransition.Signed
	if json.Unmarshal(accepted.AcceptedProof, &proof) != nil {
		return tbep.LifecycleAssignment{}, productionDatabaseHost{}, errors.New("restore backup: accepted target proof is invalid")
	}
	var host productionDatabaseHost
	for _, region := range p.config.Regions {
		if region.Region != accepted.Region {
			continue
		}
		for _, candidate := range []productionDatabaseHost{region.Writer, region.Follower} {
			if candidate.ServerIdentity == accepted.ServerIdentity {
				host = candidate
			}
		}
	}
	if host.ServerIdentity == "" {
		return tbep.LifecycleAssignment{}, productionDatabaseHost{}, errors.New("restore backup: target host is not admitted")
	}
	return tbep.LifecycleAssignment{Environment: record.Request.Environment, Tenant: record.Request.TenantID, Project: record.Request.ProjectID, Database: record.DatabaseID, Region: accepted.Region, Member: accepted.MemberID, PlacementRevision: accepted.AcceptedRevision, AuthorityEpoch: accepted.AcceptedEpoch, AuthorityLease: headProofLease(proof), AuthoritySignature: accepted.AcceptedProof, OperationGrant: accepted.AcceptedReceipt}, host, nil
}

func newProductionTBEPClient(host productionDatabaseHost, record databaseadmission.Record) (*tbep.Client, error) {
	tlsConfig, err := host.LifecycleTLS.LoadTLS()
	if err != nil {
		return nil, err
	}
	return tbep.New(tbep.Config{Endpoint: host.LifecycleEndpoint, ServerIdentity: host.LifecycleIdentity, Certificate: tlsConfig.Certificates[0], Roots: tlsConfig.RootCAs, Tenant: record.Request.TenantID, Project: record.Request.ProjectID, Database: record.DatabaseID, Timeout: time.Minute})
}

// productionDatabaseBranchPort uses the already admitted database pipeline to
// create an isolated child identity. The pipeline persists the child and its
// parent-bound branch evidence under the same NATS authority and is therefore
// safe to retry with the deterministic operation identity.
type productionDatabaseBranchPort struct {
	database **productionDatabase
	config   productionDatabaseConfig
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
	childRequest.RecoveryPointID = request.RecoveryPointID
	childRequest.JournalCut = request.JournalCut
	childRequest.RestoreEpoch = request.RestoreEpoch
	childRequest.Name = "restore-" + hex.EncodeToString(digest[:])[:32]
	childRequest.OperationID = request.IdempotencyKey
	child, err := database.pipeline.Accept(ctx, childRequest)
	if err != nil {
		return restoredrill.ScratchBranch{}, err
	}
	return restoredrill.ScratchBranch{ID: child.DatabaseID}, nil
}

func (p productionDatabaseBranchPort) Stats(ctx context.Context, branch restoredrill.ScratchBranch) (restoredrill.RestoreStats, error) {
	if p.database == nil || *p.database == nil || branch.ID == "" {
		return restoredrill.RestoreStats{}, errors.New("restore branch: admitted database is unavailable")
	}
	database := *p.database
	record, err := database.AcceptedRecord(ctx, branch.ID)
	if err != nil {
		return restoredrill.RestoreStats{}, err
	}
	placement, host, err := (productionDatabaseBackupPort{database: p.database, config: p.config}).targetAssignment(record)
	if err != nil {
		return restoredrill.RestoreStats{}, err
	}
	client, err := newProductionTBEPClient(host, record)
	if err != nil {
		return restoredrill.RestoreStats{}, err
	}
	defer client.Close()
	operation := "restore-stats-" + branch.ID
	response, err := client.RestoreStats(ctx, placement, operation, host.ServerIdentity, record.DatabaseID, record.Request.JournalCut, record.Request.RestoreEpoch)
	if err != nil {
		return restoredrill.RestoreStats{}, err
	}
	return restoredrill.RestoreStats{Checksum: response.GetChecksum(), RowCount: response.GetRowCount()}, nil
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
