package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/authorityjournal"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
	"terrascale.tech/orchestrator/src/orchestrator/restoredrill"
	"terrascale.tech/orchestrator/src/orchestrator/tbep"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

type productionDatabaseBackupPort struct {
	database         **productionDatabase
	config           productionDatabaseConfig
	refresh          func(context.Context) (authority.RegionalAuthorityLeaseDocument, error)
	check            func(context.Context) error
	keyID            string
	key              ed25519.PrivateKey
	grantJournal     func(string) (*authorityjournal.Journal[lifecycleGrantRecord], error)
	restoreCompleted func(databaseadmission.Record, *pb.RestoreStatsResponse) error
}

func (p productionDatabaseBackupPort) ListDatabases(ctx context.Context) ([]restoredrill.Database, error) {
	if p.database == nil || *p.database == nil {
		return nil, errors.New("restore database inventory: admitted database is unavailable")
	}
	return (productionAdmissionDatabaseLister{journal: (*p.database).currentJournal}).ListDatabases(ctx)
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
	if len(source.Targets) == 0 || target.Request.ParentDatabaseID != source.DatabaseID || target.Request.TenantID != source.Request.TenantID || target.Request.ProjectID != source.Request.ProjectID || target.Request.OperationID != request.IdempotencyKey || target.Request.RecoveryPointID != request.RecoveryPointID || target.Request.JournalCut != request.JournalCut || target.Request.RestoreEpoch != request.RestoreEpoch || target.RestoreFacts == nil && target.BranchSource == nil {
		return errors.New("restore backup: source and target provenance differs")
	}
	// TBEP owner is the stable tenant/project scope. Host identities belong in
	// the placement assignment and must never be sent as the owner.
	sourceOwner := strings.Join([]string{source.Request.TenantID, source.Request.ProjectID}, "/")
	targetOwner := strings.Join([]string{target.Request.TenantID, target.Request.ProjectID}, "/")
	var evidence databaseadmission.BranchSourceEvidence
	if target.BranchSource != nil {
		if json.Unmarshal(target.BranchSource.Evidence.Payload, &evidence) != nil {
			return errors.New("restore backup: authenticated source point is unavailable")
		}
	} else {
		evidence.SourceSnapshotDigest = target.RestoreFacts.RecoveryPointDigest
		evidence.RecoveryPointID, evidence.JournalCut, evidence.RestoreEpoch, evidence.RestoreProvider = target.RestoreFacts.PointID, target.RestoreFacts.JournalCut, target.RestoreFacts.Epoch, target.RestoreFacts.Provider
	}
	if evidence.SourceSnapshotDigest == "" || evidence.SourceSnapshotDigest != request.ManifestDigest || evidence.RecoveryPointID != request.RecoveryPointID || evidence.JournalCut != request.JournalCut || evidence.RestoreEpoch != request.RestoreEpoch {
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
	provider := map[string]pb.RestoreProvider{"oci": pb.RestoreProvider_RESTORE_PROVIDER_OCI, "tigris": pb.RestoreProvider_RESTORE_PROVIDER_TIGRIS, "customer-s3": pb.RestoreProvider_RESTORE_PROVIDER_CUSTOMER_S3}[target.Request.RestoreProvider]
	if provider == pb.RestoreProvider_RESTORE_PROVIDER_UNSPECIFIED || target.Request.RestoreProvider != evidence.RestoreProvider {
		return errors.New("restore backup: authenticated restore provider is unavailable")
	}
	if p.refresh == nil || p.check == nil || len(p.key) != ed25519.PrivateKeySize {
		return errors.New("restore backup: lifecycle grant authority is unavailable")
	}
	lease, err := p.refresh(ctx)
	if err != nil {
		return err
	}
	now := time.UnixMilli(time.Now().UTC().UnixMilli())
	leaseExpiry := lease.IssuedAt.Add(time.Duration(lease.DurationMilliseconds) * time.Millisecond)
	expires := now.Add(30 * time.Second)
	if leaseExpiry.Before(expires) {
		expires = leaseExpiry
	}
	digest := restoreRequestDigest(sourceOwner, source.DatabaseID, request.RecoveryPointID, evidence.SourceSnapshotDigest, targetOwner, target.DatabaseID, request.JournalCut, request.RestoreEpoch, uint32(provider))
	proofDigest := sha256.Sum256(placement.AuthoritySignature)
	grant, err := issueLifecycleOperationGrant(p.keyID, p.key, func() error { return p.check(ctx) }, lifecycleOperationGrant{Version: 1, Domain: lifecycleGrantDomain, Environment: placement.Environment, Tenant: placement.Tenant, Project: placement.Project, Database: placement.Database, Region: placement.Region, Member: placement.Member, Action: "restore_to_target", OperationID: request.IdempotencyKey, AcceptedProofDigest: hex.EncodeToString(proofDigest[:]), AcceptedPlacementRevision: placement.PlacementRevision, AuthorityEpoch: uint64(lease.Epoch), AuthorityLease: lease.LeaseId, IssuedAtUnixMillis: now.UnixMilli(), ExpiresAtUnixMillis: expires.UnixMilli(), AcceptedRestoreRequestDigest: digest}, now, leaseExpiry, time.Second)
	if err != nil {
		return err
	}
	placement.AuthorityEpoch, placement.AuthorityLease = uint64(lease.Epoch), lease.LeaseId
	placement.OperationGrant, err = json.Marshal(grant)
	if err != nil {
		return err
	}
	if p.grantJournal == nil {
		return errors.New("restore backup: grant journal unavailable")
	}
	j, err := p.grantJournal(request.IdempotencyKey)
	if err != nil {
		return err
	}
	if err = j.Transact(ctx, true, func(r *lifecycleGrantRecord) error {
		if r.Operation != "" && (r.Operation != request.IdempotencyKey || r.ProofDigest != digest) {
			return errors.New("restore backup: operation identity conflict")
		}
		*r = lifecycleGrantRecord{Scope: placement.Tenant + ":" + placement.Project + ":" + placement.Database + ":" + target.DatabaseID, Action: "restore_to_target", Operation: request.IdempotencyKey, ProofDigest: digest, Revision: placement.PlacementRevision, Grant: append([]byte(nil), placement.OperationGrant...)}
		return nil
	}); err != nil {
		return err
	}
	var envelope *pb.RecoveryEnvelopeFacts
	if target.RestoreFacts != nil {
		envelope = restoreEnvelopeWire(target.RestoreFacts.Envelope)
	}
	_, err = client.RestoreToTarget(ctx, placement, request.IdempotencyKey, tbep.RestoreRequest{
		SourceOwner: sourceOwner, SourceDatabase: source.DatabaseID, RecoveryPointID: request.RecoveryPointID,
		RecoveryPointDigest: evidence.SourceSnapshotDigest, TargetOwner: targetOwner, TargetDatabase: target.DatabaseID,
		JournalCut: request.JournalCut, RestoreEpoch: request.RestoreEpoch, ExpectedPlacement: target.Request.Regions,
		Provider: provider, Envelope: envelope,
	})
	if err != nil {
		if errors.Is(err, tbep.ErrRestorePending) || errors.Is(err, context.DeadlineExceeded) {
			return restoredrill.ErrPending
		}
		return err
	}
	stats, err := client.RestoreStats(ctx, placement, request.IdempotencyKey, targetOwner, target.DatabaseID, request.JournalCut, request.RestoreEpoch, target.Request.Regions)
	if err != nil {
		return err
	}
	if p.restoreCompleted != nil {
		if err := p.restoreCompleted(target, stats); err != nil {
			return err
		}
	}
	return j.Transact(ctx, true, func(r *lifecycleGrantRecord) error { r.Completed = true; return nil })
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
type restoreStatsGrantJournal interface {
	Transact(context.Context, bool, func(*lifecycleGrantRecord) error) error
}

type productionDatabaseBranchPort struct {
	acceptedRecord  func(context.Context, string) (databaseadmission.Record, error)
	statsClient     func(productionDatabaseHost, databaseadmission.Record) (*tbep.Client, error)
	renewStatsGrant func(context.Context, tbep.LifecycleAssignment, lifecycleOperationGrant) (tbep.LifecycleAssignment, error)
	grantJournal    func(string) (restoreStatsGrantJournal, error)
	database        **productionDatabase
	config          productionDatabaseConfig
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
	// Restore drills always branch from a root database. Keeping this check at
	// the caller protects the production path even if a stale admission record
	// or an alternate provisioning implementation bypasses Pipeline validation.
	if parent.Request.ParentDatabaseID != "" {
		return restoredrill.ScratchBranch{}, errors.New("restore branch: source database is not a root database")
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
	// RestoreProvider is authenticated capture provenance. Do not inherit a
	// provider from the parent admission record when creating the child.
	childRequest.RestoreProvider = request.RestoreProvider
	childRequest.Name = "restore-" + hex.EncodeToString(digest[:])[:32]
	childRequest.OperationID = request.IdempotencyKey
	child, err := database.pipeline.Accept(ctx, childRequest)
	if err != nil {
		return restoredrill.ScratchBranch{}, err
	}
	return restoredrill.ScratchBranch{ID: child.DatabaseID}, nil
}

func (p productionDatabaseBranchPort) Stats(ctx context.Context, branch restoredrill.ScratchBranch) (restoredrill.RestoreStats, error) {
	if p.acceptedRecord == nil || p.statsClient == nil || branch.ID == "" {
		return restoredrill.RestoreStats{}, errors.New("restore branch: admitted database is unavailable")
	}
	record, err := p.acceptedRecord(ctx, branch.ID)
	if err != nil {
		return restoredrill.RestoreStats{}, err
	}
	placement, host, err := (productionDatabaseBackupPort{database: p.database, config: p.config}).targetAssignment(record)
	if err != nil {
		return restoredrill.RestoreStats{}, err
	}
	client, err := p.statsClient(host, record)
	if err != nil {
		return restoredrill.RestoreStats{}, err
	}
	defer client.Close()
	operation := record.Request.OperationID
	if operation == "" || p.grantJournal == nil || p.renewStatsGrant == nil {
		return restoredrill.RestoreStats{}, errors.New("restore branch: original operation grant unavailable")
	}
	j, err := p.grantJournal(operation)
	if err != nil {
		return restoredrill.RestoreStats{}, err
	}
	var original lifecycleOperationGrant
	if err = j.Transact(ctx, false, func(grant *lifecycleGrantRecord) error {
		if grant.Operation != operation || grant.Action != "restore_to_target" || grant.Scope != placement.Tenant+":"+placement.Project+":"+placement.Database+":"+record.DatabaseID || len(grant.Grant) == 0 {
			return errors.New("restore branch: original operation grant differs")
		}
		var envelope placementtransition.Signed
		if json.Unmarshal(grant.Grant, &envelope) != nil || json.Unmarshal(envelope.Payload, &original) != nil || original.OperationID != operation || original.AcceptedRestoreRequestDigest != grant.ProofDigest {
			return errors.New("restore branch: original grant malformed")
		}
		return nil
	}); err != nil {
		return restoredrill.RestoreStats{}, err
	}
	placement, err = p.renewStatsGrant(ctx, placement, original)
	if err != nil {
		return restoredrill.RestoreStats{}, err
	}
	if err := j.Transact(ctx, true, func(grant *lifecycleGrantRecord) error {
		grant.Grant = append([]byte(nil), placement.OperationGrant...)
		return nil
	}); err != nil {
		return restoredrill.RestoreStats{}, err
	}
	targetOwner := strings.Join([]string{record.Request.TenantID, record.Request.ProjectID}, "/")
	response, err := client.RestoreStats(ctx, placement, operation, targetOwner, record.DatabaseID, record.Request.JournalCut, record.Request.RestoreEpoch, record.Request.Regions)
	if err != nil {
		return restoredrill.RestoreStats{}, err
	}
	return verifyProductionRestoreStats(p.config.NativeReceiptKeys, host, record, branch.Expected, response)
}

// Verifies the member observation against independently retained drill facts and admission.
func verifyProductionRestoreStats(keys map[string]databaseadmission.ReadinessKey, host productionDatabaseHost, record databaseadmission.Record, facts restoredrill.JournalFacts, response *pb.RestoreStatsResponse) (restoredrill.RestoreStats, error) {
	pin, ok := keys[host.ServerIdentity]
	if !ok {
		return restoredrill.RestoreStats{}, restoredrill.ErrNativeReceipt
	}
	verifier, err := restoredrill.NewNativeReceiptVerifier(pin.KeyID, pin.PublicKey)
	if err != nil {
		return restoredrill.RestoreStats{}, err
	}
	cut, err := strconv.ParseUint(record.Request.JournalCut, 10, 64)
	if err != nil || facts.RowCount < 0 {
		return restoredrill.RestoreStats{}, restoredrill.ErrNativeReceipt
	}
	expected := restoredrill.NativeReceiptBinding{TenantID: record.Request.TenantID, ProjectID: record.Request.ProjectID, SourceDatabaseID: record.Request.ParentDatabaseID, TargetDatabaseID: record.DatabaseID, TargetIncarnation: record.DatabaseID, SourceJournalCut: cut, CapturedAtMillis: facts.CapturedAtMillis, SourceChecksum: facts.Checksum, SourceRowCount: uint64(facts.RowCount), RestoreEpoch: record.Request.RestoreEpoch, IdempotencyKey: record.Request.OperationID, OperationID: record.Request.OperationID, RecoveryPointID: record.Request.RecoveryPointID, RecoveryPointDigest: facts.ManifestDigest, Placement: record.Request.Regions}
	verified, err := verifier.Verify(response.GetSignedCompletedReceipt(), expected)
	if err != nil || verified.TargetChecksum != response.GetChecksum() || verified.TargetRowCount != uint64(response.GetRowCount()) {
		return restoredrill.RestoreStats{}, restoredrill.ErrNativeReceipt
	}
	return verified.Stats(), nil
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
	journal databaseadmission.Journal
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
		if record.Request.ParentDatabaseID != "" {
			continue
		}
		result = append(result, restoredrill.Database{ID: record.DatabaseID, Region: record.Request.Regions[0]})
	}
	return result, nil
}

// renewRestoreStatsGrant authorizes observation of the same immutable restore under
// the current authority lease. The expired mutation grant remains unchanged.
func (p productionDatabaseBackupPort) renewRestoreStatsGrant(ctx context.Context, placement tbep.LifecycleAssignment, original lifecycleOperationGrant) (tbep.LifecycleAssignment, error) {
	digest := sha256.Sum256(placement.AuthoritySignature)
	if p.refresh == nil || p.check == nil || original.Action != "restore_to_target" || original.OperationID == "" || original.Environment != placement.Environment || original.Tenant != placement.Tenant || original.Project != placement.Project || original.Database != placement.Database || original.AcceptedRestoreRequestDigest == "" || original.Region != placement.Region || original.Member != placement.Member || original.AcceptedPlacementRevision != placement.PlacementRevision || original.AcceptedProofDigest != hex.EncodeToString(digest[:]) {
		return placement, errors.New("restore stats: immutable operation authorization differs")
	}
	lease, err := p.refresh(ctx)
	if err != nil {
		return placement, err
	}
	now := time.UnixMilli(time.Now().UTC().UnixMilli())
	leaseExpiry := lease.IssuedAt.Add(time.Duration(lease.DurationMilliseconds) * time.Millisecond)
	expires := now.Add(30 * time.Second)
	if leaseExpiry.Before(expires) {
		expires = leaseExpiry
	}
	renewed := original
	renewed.AcceptedProofDigest = hex.EncodeToString(digest[:])
	renewed.AcceptedPlacementRevision = placement.PlacementRevision
	renewed.Region, renewed.Member = placement.Region, placement.Member
	renewed.AuthorityEpoch, renewed.AuthorityLease = uint64(lease.Epoch), lease.LeaseId
	renewed.IssuedAtUnixMillis, renewed.ExpiresAtUnixMillis = now.UnixMilli(), expires.UnixMilli()
	signed, err := issueLifecycleOperationGrant(p.keyID, p.key, func() error { return p.check(ctx) }, renewed, now, leaseExpiry, time.Second)
	if err != nil {
		return placement, err
	}
	placement.OperationGrant, err = json.Marshal(signed)
	placement.AuthorityEpoch, placement.AuthorityLease = renewed.AuthorityEpoch, renewed.AuthorityLease
	return placement, err
}

func newProductionDatabaseBranchPort(database **productionDatabase, config productionDatabaseConfig, backup productionDatabaseBackupPort) productionDatabaseBranchPort {
	return productionDatabaseBranchPort{database: database, config: config, renewStatsGrant: backup.renewRestoreStatsGrant, statsClient: newProductionTBEPClient,
		acceptedRecord: func(ctx context.Context, id string) (databaseadmission.Record, error) {
			if database == nil || *database == nil {
				return databaseadmission.Record{}, errors.New("restore branch: admitted database unavailable")
			}
			return (*database).AcceptedRecord(ctx, id)
		},
		grantJournal: func(op string) (restoreStatsGrantJournal, error) {
			if backup.grantJournal == nil {
				return nil, errors.New("restore branch: grant journal unavailable")
			}
			return backup.grantJournal(op)
		},
	}
}
