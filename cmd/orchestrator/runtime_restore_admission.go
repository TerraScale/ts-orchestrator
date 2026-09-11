package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/authorityjournal"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/restoredrill"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

// productionRestoreAdmission connects public restore admission to the source
// member's authenticated native resolver. It deliberately handles scalar
// points only; an envelope must be qualified as a complete composition before
// it can enter the immutable admission journal.
func productionRestoreAdmission(config productionDatabaseConfig, session globalWorkerSession, keyID string, key ed25519.PrivateKey, grants func(string) (*authorityjournal.Journal[lifecycleGrantRecord], error), backup productionDatabaseBackupPort) *databaseadmission.RestoreConfig {
	return &databaseadmission.RestoreConfig{Resolve: func(ctx context.Context, source databaseadmission.Record, selection databaseadmission.RestoreSelection) (databaseadmission.RestoreAdmissionFacts, error) {
		if selection.Kind != "latest" && selection.Kind != "point_id" || selection.UnixMillis != 0 {
			return databaseadmission.RestoreAdmissionFacts{}, errors.New("restore resolution: unsupported selection")
		}
		assignment, host, err := (productionDatabaseBackupPort{config: config}).targetAssignment(source)
		if err != nil {
			return databaseadmission.RestoreAdmissionFacts{}, err
		}
		client, err := newProductionTBEPClient(host, source)
		if err != nil {
			return databaseadmission.RestoreAdmissionFacts{}, err
		}
		defer client.Close()
		operation := restoreResolutionOperation(source, selection)
		lease, err := session.guard.RefreshAuthority(ctx)
		if err != nil {
			return databaseadmission.RestoreAdmissionFacts{}, err
		}
		if grants == nil || len(key) != ed25519.PrivateKeySize {
			return databaseadmission.RestoreAdmissionFacts{}, errors.New("restore resolution: lifecycle grant authority unavailable")
		}
		now := time.UnixMilli(time.Now().UTC().UnixMilli())
		leaseExpiry := lease.IssuedAt.Add(time.Duration(lease.DurationMilliseconds) * time.Millisecond)
		expires := now.Add(30 * time.Second)
		if leaseExpiry.Before(expires) {
			expires = leaseExpiry
		}
		proofDigest := sha256.Sum256(assignment.AuthoritySignature)
		grant, err := issueLifecycleOperationGrant(keyID, key, func() error { return session.CheckEffectAuthority(ctx) }, lifecycleOperationGrant{
			Version: 1, Domain: lifecycleGrantDomain, Environment: assignment.Environment, Tenant: assignment.Tenant, Project: assignment.Project,
			Database: assignment.Database, Region: assignment.Region, Member: assignment.Member, Action: "resolve_recovery_point", OperationID: operation,
			AcceptedProofDigest: hex.EncodeToString(proofDigest[:]), AcceptedPlacementRevision: assignment.PlacementRevision, AuthorityEpoch: uint64(lease.Epoch), AuthorityLease: lease.LeaseId,
			IssuedAtUnixMillis: now.UnixMilli(), ExpiresAtUnixMillis: expires.UnixMilli(), AcceptedRestoreRequestDigest: "",
		}, now, leaseExpiry, time.Second)
		if err != nil {
			return databaseadmission.RestoreAdmissionFacts{}, err
		}
		assignment.AuthorityEpoch, assignment.AuthorityLease = uint64(lease.Epoch), lease.LeaseId
		assignment.OperationGrant, err = json.Marshal(grant)
		if err != nil {
			return databaseadmission.RestoreAdmissionFacts{}, err
		}
		journal, err := grants(operation)
		if err != nil {
			return databaseadmission.RestoreAdmissionFacts{}, err
		}
		if err := journal.Transact(ctx, true, func(r *lifecycleGrantRecord) error {
			if r.Operation != "" && r.Operation != operation {
				return errors.New("restore resolution: operation identity conflict")
			}
			*r = lifecycleGrantRecord{Scope: assignment.Tenant + ":" + assignment.Project + ":" + assignment.Database, Action: "resolve_recovery_point", Operation: operation, Grant: assignment.OperationGrant}
			return nil
		}); err != nil {
			return databaseadmission.RestoreAdmissionFacts{}, err
		}
		pointID := selection.PointID
		response, err := client.ResolveRecoveryPoint(ctx, assignment, operation, selection.Kind, pointID, 0)
		if err != nil {
			return databaseadmission.RestoreAdmissionFacts{}, err
		}
		if response.GetEnvelope() != nil || response.GetSourceDatabase() != source.DatabaseID || response.GetRecoveryPointId() == "" || response.GetRecoveryPointDigest() == "" || response.GetJournalCut() == "" || response.GetCapturedAtMillis() == 0 || response.GetChecksum() == "" || len(response.GetPlacement()) == 0 {
			return databaseadmission.RestoreAdmissionFacts{}, errors.New("restore resolution: incomplete scalar response")
		}
		wantPlacement, gotPlacement := slices.Clone(source.Request.Regions), slices.Clone(response.GetPlacement())
		slices.Sort(wantPlacement)
		slices.Sort(gotPlacement)
		if !slices.Equal(wantPlacement, gotPlacement) || selection.Kind == "point_id" && response.GetRecoveryPointId() != pointID {
			return databaseadmission.RestoreAdmissionFacts{}, errors.New("restore resolution: authenticated facts differ from selection")
		}
		provider := map[pb.RestoreProvider]string{pb.RestoreProvider_RESTORE_PROVIDER_OCI: "oci", pb.RestoreProvider_RESTORE_PROVIDER_TIGRIS: "tigris", pb.RestoreProvider_RESTORE_PROVIDER_CUSTOMER_S3: "customer-s3"}[response.GetProvider()]
		if provider == "" || !restoreDigest(response.GetRecoveryPointDigest()) || !restoreDigest(response.GetChecksum()) {
			return databaseadmission.RestoreAdmissionFacts{}, errors.New("restore resolution: invalid provider or digest")
		}
		return databaseadmission.RestoreAdmissionFacts{SourceDigest: databaseadmission.RestoreSourceDigest(source), RecoveryPointDigest: response.GetRecoveryPointDigest(), CapturedAtMillis: response.GetCapturedAtMillis(), Checksum: response.GetChecksum(), RowCount: response.GetRowCount(), PointID: response.GetRecoveryPointId(), Provider: provider, JournalCut: response.GetJournalCut()}, nil
	}, Restore: func(ctx context.Context, target databaseadmission.Record) ([]byte, error) {
		if target.RestoreFacts == nil {
			return nil, errors.New("restore admission: resolved facts unavailable")
		}
		var acknowledgement []byte
		port := backup
		port.restoreCompleted = func(record databaseadmission.Record, response *pb.LifecycleControlResponse) error {
			if response == nil || len(response.GetSignedCompletedReceipt()) == 0 {
				return errors.New("restore admission: native completed receipt unavailable")
			}
			facts := record.RestoreFacts
			cut, err := strconv.ParseUint(facts.JournalCut, 10, 64)
			if err != nil {
				return errors.New("restore admission: invalid journal cut")
			}
			_, host, err := port.targetAssignment(record)
			if err != nil {
				return err
			}
			pin, ok := config.NativeReceiptKeys[host.ServerIdentity]
			if !ok {
				return errors.New("restore admission: native receipt key unavailable")
			}
			verifier, err := restoredrill.NewNativeReceiptVerifier(pin.KeyID, pin.PublicKey)
			if err != nil {
				return err
			}
			_, err = verifier.Verify(response.GetSignedCompletedReceipt(), restoredrill.NativeReceiptBinding{
				TenantID: record.Request.TenantID, ProjectID: record.Request.ProjectID, SourceDatabaseID: record.Request.ParentDatabaseID,
				TargetDatabaseID: record.DatabaseID, TargetIncarnation: record.DatabaseID, SourceJournalCut: cut,
				CapturedAtMillis: facts.CapturedAtMillis, SourceChecksum: facts.Checksum, SourceRowCount: facts.RowCount,
				RestoreEpoch: facts.Epoch, IdempotencyKey: record.Request.OperationID, OperationID: record.Request.OperationID,
				RecoveryPointID: facts.PointID, RecoveryPointDigest: facts.RecoveryPointDigest, Placement: record.Request.Regions,
			})
			if err != nil {
				return errors.New("restore admission: native receipt does not match admitted facts")
			}
			value := databaseadmission.RestoreAcknowledgement{Version: 1, TargetDatabaseID: record.DatabaseID, SourceDatabaseID: record.Request.ParentDatabaseID, Facts: *record.RestoreFacts}
			acknowledgement, err = json.Marshal(value)
			return err
		}
		request := restoredrill.RestoreRequest{SourceDatabaseID: target.Request.ParentDatabaseID, BranchID: target.DatabaseID, RecoveryPointID: target.RestoreFacts.PointID, ManifestDigest: target.RestoreFacts.RecoveryPointDigest, JournalCut: target.RestoreFacts.JournalCut, RestoreEpoch: target.RestoreFacts.Epoch, IdempotencyKey: target.Request.OperationID, RestoreProvider: target.RestoreFacts.Provider}
		if err := port.Restore(ctx, request); err != nil {
			return nil, err
		}
		return acknowledgement, nil
	}}
}

func restoreResolutionOperation(source databaseadmission.Record, selection databaseadmission.RestoreSelection) string {
	sum := sha256.Sum256([]byte(databaseadmission.RestoreSourceDigest(source) + "\x00" + selection.Kind + "\x00" + selection.PointID))
	return "restore-resolve-" + hex.EncodeToString(sum[:])
}

func restoreDigest(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
