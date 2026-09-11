package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"reflect"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/restoredrill"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

func TestProductionRestoreAdmissionResolve(t *testing.T) {
	source := databaseadmission.Record{DatabaseID: "source", Request: databaseadmission.Request{Regions: []string{"GRU", "VCP"}}}
	for _, kind := range []string{"latest", "point_id"} {
		for _, mutation := range []string{"valid", "source", "selection", "provider", "digest", "checksum", "placement", "envelope"} {
			t.Run(kind+"/"+mutation, func(t *testing.T) {
				selection := databaseadmission.RestoreSelection{Kind: kind}
				if kind == "point_id" {
					selection.PointID = strings.Repeat("b", 64)
				}
				response := &pb.ResolveRecoveryPointResponse{SourceDatabase: "source", RecoveryPointId: strings.Repeat("b", 64), RecoveryPointDigest: strings.Repeat("d", 64), JournalCut: "42", CapturedAtMillis: 1000, Checksum: strings.Repeat("c", 64), RowCount: 7, Placement: []string{"VCP", "GRU"}, Provider: pb.RestoreProvider_RESTORE_PROVIDER_OCI}
				switch mutation {
				case "source":
					response.SourceDatabase = "other"
				case "selection":
					response.RecoveryPointId = strings.Repeat("a", 64)
				case "provider":
					response.Provider = pb.RestoreProvider_RESTORE_PROVIDER_UNSPECIFIED
				case "digest":
					response.RecoveryPointDigest = "bad"
				case "checksum":
					response.Checksum = "bad"
				case "placement":
					response.Placement = []string{"GRU"}
				case "envelope":
					response.Envelope = new(pb.RecoveryEnvelopeFacts)
				}
				calls := 0
				adapter := newRestoreAdmission(productionDatabaseConfig{}, func(_ context.Context, got databaseadmission.Record, selected databaseadmission.RestoreSelection) (*pb.ResolveRecoveryPointResponse, error) {
					calls++
					if !reflect.DeepEqual(got, source) || selected != selection {
						t.Fatal("resolver input changed")
					}
					return response, nil
				}, nil)
				got, err := adapter.Resolve(t.Context(), source, selection)
				valid := mutation == "valid" || mutation == "selection" && kind == "latest"
				if calls != 1 {
					t.Fatal("resolver not called")
				}
				if !valid {
					if err == nil {
						t.Fatal("altered native response accepted")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				want := databaseadmission.RestoreAdmissionFacts{SourceDigest: databaseadmission.RestoreSourceDigest(source), RecoveryPointDigest: strings.Repeat("d", 64), PointID: response.RecoveryPointId, Provider: "oci", JournalCut: "42", CapturedAtMillis: 1000, Checksum: strings.Repeat("c", 64), RowCount: 7}
				if got != want {
					t.Fatalf("facts = %+v, want %+v", got, want)
				}
			})
		}
	}
}

func TestProductionRestoreAdmissionCompletedReceipt(t *testing.T) {
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	facts := databaseadmission.RestoreAdmissionFacts{SourceDigest: strings.Repeat("a", 64), RecoveryPointDigest: strings.Repeat("b", 64), PointID: "point-1", Provider: "oci", JournalCut: "42", CapturedAtMillis: 1000, Checksum: strings.Repeat("c", 64), RowCount: 7, Epoch: 8}
	record := databaseadmission.Record{DatabaseID: "01ARZ3NDEKTSV4RRFFQ69G5FAY", Request: databaseadmission.Request{TenantID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ProjectID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", ParentDatabaseID: "01ARZ3NDEKTSV4RRFFQ69G5FAX", OperationID: "restore-1", Regions: []string{"GRU", "VCP"}}, RestoreFacts: &facts, Targets: []databaseadmission.Target{{}}, PlacementTargets: []databaseadmission.PlacementTarget{{Region: "GRU", ServerIdentity: "host", AcceptedEpoch: 1, AcceptedRevision: 1, AcceptedGeneration: 1, AcceptedProof: []byte(`{"key_id":"placement","payload":"e30=","signature":"AA=="}`), AcceptedReceipt: []byte("accepted")}}}
	config := productionDatabaseConfig{Regions: []productionDatabaseRegion{{Region: "GRU", Writer: productionDatabaseHost{ServerIdentity: "host"}}}, NativeReceiptKeys: map[string]databaseadmission.ReadinessKey{"host": {KeyID: "receipt-key", PublicKey: public}}}
	for _, mutation := range []string{"valid", "source", "target", "epoch", "point", "artifact", "capture", "checksum", "count", "placement", "signature"} {
		t.Run(mutation, func(t *testing.T) {
			// Expected values are independently authored native wire facts, not copied from the callback binding.
			receipt := restoredrill.VerifiedNativeReceipt{SchemaVersion: 1, NativeReceiptBinding: restoredrill.NativeReceiptBinding{TenantID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ProjectID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", SourceDatabaseID: "01ARZ3NDEKTSV4RRFFQ69G5FAX", TargetDatabaseID: "01ARZ3NDEKTSV4RRFFQ69G5FAY", TargetIncarnation: "01ARZ3NDEKTSV4RRFFQ69G5FAY", SourceJournalCut: 42, CapturedAtMillis: 1000, SourceChecksum: strings.Repeat("c", 64), SourceRowCount: 7, RestoreEpoch: 8, IdempotencyKey: "restore-1", OperationID: "restore-1", RecoveryPointID: "point-1", RecoveryPointDigest: strings.Repeat("b", 64), Placement: []string{"GRU", "VCP"}}, TargetChecksum: strings.Repeat("c", 64), TargetRowCount: 7, CompletedAtMillis: 2000}
			switch mutation {
			case "source":
				receipt.SourceDatabaseID = "01ARZ3NDEKTSV4RRFFQ69G5FAZ"
			case "target":
				receipt.TargetDatabaseID = "01ARZ3NDEKTSV4RRFFQ69G5FAZ"
				receipt.TargetIncarnation = receipt.TargetDatabaseID
			case "epoch":
				receipt.RestoreEpoch++
			case "point":
				receipt.RecoveryPointID = "other"
			case "artifact":
				receipt.RecoveryPointDigest = strings.Repeat("d", 64)
			case "capture":
				receipt.CapturedAtMillis++
			case "checksum":
				receipt.SourceChecksum = strings.Repeat("d", 64)
				receipt.TargetChecksum = receipt.SourceChecksum
			case "count":
				receipt.SourceRowCount++
				receipt.TargetRowCount++
			case "placement":
				receipt.Placement = []string{"GRU"}
			}
			payload, err := json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			signature := ed25519.Sign(key, append([]byte("terrascale/native-recovery-receipt/v1\x00"), payload...))
			if mutation == "signature" {
				signature[0] ^= 1
			}
			raw, err := json.Marshal(map[string]string{"key_id": "receipt-key", "payload_base64": base64.StdEncoding.EncodeToString(payload), "signature_base64": base64.StdEncoding.EncodeToString(signature)})
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			adapter := newRestoreAdmission(config, nil, func(_ context.Context, got databaseadmission.Record, completed func(databaseadmission.Record, *pb.LifecycleControlResponse) error) error {
				calls++
				if !reflect.DeepEqual(got, record) {
					t.Fatal("restore target changed")
				}
				return completed(got, &pb.LifecycleControlResponse{SignedCompletedReceipt: raw})
			})
			ack, err := adapter.Restore(t.Context(), record)
			if calls != 1 {
				t.Fatal("restore dispatch not called")
			}
			if mutation != "valid" {
				if err == nil || len(ack) != 0 {
					t.Fatal("altered receipt acknowledged")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var got databaseadmission.RestoreAcknowledgement
			if err := json.Unmarshal(ack, &got); err != nil {
				t.Fatal(err)
			}
			want := databaseadmission.RestoreAcknowledgement{Version: 1, TargetDatabaseID: record.DatabaseID, SourceDatabaseID: record.Request.ParentDatabaseID, Facts: facts}
			if got != want {
				t.Fatalf("ack = %+v, want %+v", got, want)
			}
		})
	}
}

func TestProductionRestoreAdmissionWiresCallbacks(t *testing.T) {
	adapter := productionRestoreAdmission(productionDatabaseConfig{}, globalWorkerSession{}, "", nil, nil, productionDatabaseBackupPort{})
	if adapter.Resolve == nil || adapter.Restore == nil {
		t.Fatal("production callbacks missing")
	}
	// These denials must precede concrete authority, transport, and mutation effects.
	if _, err := adapter.Resolve(t.Context(), databaseadmission.Record{}, databaseadmission.RestoreSelection{Kind: "timestamp", UnixMillis: 1}); err == nil {
		t.Fatal("unsupported selection accepted")
	}
	if ack, err := adapter.Restore(t.Context(), databaseadmission.Record{}); err == nil || len(ack) != 0 {
		t.Fatal("unresolved restore acknowledged")
	}
}
