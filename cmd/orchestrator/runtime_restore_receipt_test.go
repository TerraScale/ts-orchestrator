package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/restoredrill"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
	"testing"
	"time"
)

func TestProductionRestoreStatsRequiresPinnedCompletedObservation(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	record := databaseadmission.Record{DatabaseID: "01ARZ3NDEKTSV4RRFFQ69G5FAY", Request: databaseadmission.Request{TenantID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ProjectID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", ParentDatabaseID: "01ARZ3NDEKTSV4RRFFQ69G5FAX", OperationID: "restore-operation", JournalCut: "42", RecoveryPointID: strings.Repeat("b", 64), RestoreEpoch: 7, Regions: []string{"gru", "sfo", "fra"}}}
	facts := restoredrill.JournalFacts{CapturedAtMillis: uint64(time.Now().Add(-time.Minute).UnixMilli()), ManifestDigest: strings.Repeat("b", 64), Checksum: strings.Repeat("a", 64), RowCount: 8}
	host := productionDatabaseHost{ServerIdentity: "admitted-member"}
	keys := map[string]databaseadmission.ReadinessKey{host.ServerIdentity: {KeyID: "receipt-key", PublicKey: public}}
	payload := map[string]any{"schema_version": 1, "tenant_id": record.Request.TenantID, "project_id": record.Request.ProjectID, "source_database_id": record.Request.ParentDatabaseID, "target_database_id": record.DatabaseID, "target_incarnation": record.DatabaseID, "source_journal_cut": 42, "captured_at_millis": facts.CapturedAtMillis, "source_checksum": facts.Checksum, "source_row_count": facts.RowCount, "target_checksum": facts.Checksum, "target_row_count": facts.RowCount, "restore_epoch": 7, "idempotency_key": record.Request.OperationID, "operation_id": record.Request.OperationID, "recovery_point_id": record.Request.RecoveryPointID, "recovery_point_digest": facts.ManifestDigest, "placement": record.Request.Regions, "completed_at_millis": uint64(time.Now().UnixMilli())}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(private, append([]byte("terrascale/native-recovery-receipt/v1\x00"), raw...))
	envelope, err := json.Marshal(map[string]string{"key_id": "receipt-key", "payload_base64": base64.StdEncoding.EncodeToString(raw), "signature_base64": base64.StdEncoding.EncodeToString(signature)})
	if err != nil {
		t.Fatal(err)
	}
	response := &pb.RestoreStatsResponse{Checksum: facts.Checksum, RowCount: facts.RowCount, SignedCompletedReceipt: envelope}
	if _, err := verifyProductionRestoreStats(keys, host, record, facts, response); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*databaseadmission.Record){func(r *databaseadmission.Record) { r.Request.TenantID = "01ARZ3NDEKTSV4RRFFQ69G5FAZ" }, func(r *databaseadmission.Record) { r.Request.RestoreEpoch++ }, func(r *databaseadmission.Record) { r.Request.OperationID = "another-operation" }} {
		foreign := record
		mutate(&foreign)
		if _, err := verifyProductionRestoreStats(keys, host, foreign, facts, response); err == nil {
			t.Fatal("foreign or replayed observation accepted")
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(*databaseadmission.Record, *restoredrill.JournalFacts)
	}{
		{"source", func(r *databaseadmission.Record, _ *restoredrill.JournalFacts) {
			r.Request.ParentDatabaseID = "01ARZ3NDEKTSV4RRFFQ69G5FAZ"
		}},
		{"target incarnation", func(r *databaseadmission.Record, _ *restoredrill.JournalFacts) {
			r.DatabaseID = "01ARZ3NDEKTSV4RRFFQ69G5FAZ"
		}},
		{"capture timestamp", func(_ *databaseadmission.Record, f *restoredrill.JournalFacts) { f.CapturedAtMillis++ }},
		{"manifest", func(_ *databaseadmission.Record, f *restoredrill.JournalFacts) {
			f.ManifestDigest = strings.Repeat("c", 64)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			foreign, foreignFacts := record, facts
			tc.mutate(&foreign, &foreignFacts)
			if _, err := verifyProductionRestoreStats(keys, host, foreign, foreignFacts, response); err == nil {
				t.Fatal("receipt accepted for different admitted source or target facts")
			}
		})
	}
	if _, err := verifyProductionRestoreStats(keys, productionDatabaseHost{ServerIdentity: "foreign-member"}, record, facts, response); err == nil {
		t.Fatal("unadmitted signer accepted")
	}
	response.SignedCompletedReceipt = nil
	if _, err := verifyProductionRestoreStats(keys, host, record, facts, response); err == nil {
		t.Fatal("pending unsigned observation accepted")
	}
	response.SignedCompletedReceipt = append([]byte(nil), envelope...)
	response.SignedCompletedReceipt[len(envelope)/2] ^= 1
	if _, err := verifyProductionRestoreStats(keys, host, record, facts, response); err == nil {
		t.Fatal("tampered observation accepted")
	}
}
