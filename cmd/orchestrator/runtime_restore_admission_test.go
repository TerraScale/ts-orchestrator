package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/v2"
	"reflect"
	"strings"
	"testing"

	"github.com/oklog/ulid"
	"github.com/zeebo/blake3"
	"google.golang.org/protobuf/proto"

	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/restoredrill"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

func TestProductionRestoreAdmissionResolve(t *testing.T) {
	source := databaseadmission.Record{DatabaseID: "source", Request: databaseadmission.Request{Regions: []string{"GRU", "VCP"}}}
	for _, kind := range []string{"latest", "point_id"} {
		for _, mutation := range []string{"valid", "source", "selection", "provider", "digest", "checksum", "placement"} {
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
				if !reflect.DeepEqual(got, want) {
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
	for _, mutation := range []string{"valid", "source", "target", "epoch", "point", "artifact", "capture", "checksum", "count", "placement", "signature", "stats-envelope"} {
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
			adapter := newRestoreAdmission(config, nil, func(_ context.Context, got databaseadmission.Record, completed func(databaseadmission.Record, *pb.RestoreStatsResponse) error) error {
				calls++
				if !reflect.DeepEqual(got, record) {
					t.Fatal("restore target changed")
				}
				response := &pb.RestoreStatsResponse{SignedCompletedReceipt: raw, Checksum: facts.Checksum, RowCount: int64(facts.RowCount), JournalCut: facts.JournalCut, OperationId: got.Request.OperationID, TargetDatabase: got.DatabaseID, TargetOwner: got.Request.TenantID + "/" + got.Request.ProjectID, Placement: got.Request.Regions}
				if mutation == "stats-envelope" {
					response.Envelope = new(pb.RecoveryEnvelopeFacts)
				}
				return completed(got, response)
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

func TestProductionRestoreAdmissionRoutedStatsAcknowledgement(t *testing.T) {
	const sourceID = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
	const targetID = "01ARZ3NDEKTSV4RRFFQ69G5FAY"
	source := databaseadmission.Record{DatabaseID: sourceID, Request: databaseadmission.Request{Environment: "production", TenantID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ProjectID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", Regions: []string{"GRU", "SFO"}}}
	id, err := ulid.Parse(sourceID)
	if err != nil {
		t.Fatal(err)
	}
	incarnation := hex.EncodeToString(id[:])
	// Producer-shaped ordered shard facts have distinct cuts. The scalar fields
	// summarize this vector; they cannot replace it at the acknowledgement boundary.
	participants := []databaseadmission.RestoreParticipantFacts{
		{ParticipantID: "shard-0000000000000001", DatabaseID: sourceID, JournalCut: 7, ManifestDigest: strings.Repeat("a", 64), Checksum: strings.Repeat("b", 64), RowCount: 3, CapturedAtMillis: 1000, RetainedUntilMillis: 2000},
		{ParticipantID: "shard-0000000000000002", DatabaseID: sourceID, JournalCut: 19, ManifestDigest: strings.Repeat("c", 64), Checksum: strings.Repeat("d", 64), RowCount: 5, CapturedAtMillis: 1100, RetainedUntilMillis: 2100},
	}
	logical := []byte("terrabase-backup-envelope-logical-v1\x00")
	for _, participant := range participants {
		logical = binary.BigEndian.AppendUint64(logical, uint64(len(participant.ParticipantID)))
		logical = append(logical, participant.ParticipantID...)
		logical = binary.BigEndian.AppendUint64(logical, uint64(len(participant.Checksum)))
		logical = append(logical, participant.Checksum...)
	}
	hash := blake3.Sum256(logical)
	checksum := hex.EncodeToString(hash[:])
	digest := strings.Repeat("e", 64)
	expected := databaseadmission.RestoreAdmissionFacts{SourceDigest: databaseadmission.RestoreSourceDigest(source), RecoveryPointDigest: digest, PointID: digest, Provider: "oci", JournalCut: "19", CapturedAtMillis: 1100, Checksum: checksum, RowCount: 8, Envelope: &databaseadmission.RestoreEnvelopeFacts{EnvelopeDigest: digest, DatabaseID: sourceID, DatabaseIncarnation: incarnation, RouteGeneration: 4, Participants: participants}}
	// Author the wire vector separately so omissions in either converter fail.
	wire := &pb.RecoveryEnvelopeFacts{EnvelopeDigest: digest, DatabaseId: sourceID, DatabaseIncarnation: incarnation, RouteGeneration: 4, Participants: []*pb.RecoveryParticipant{
		{ParticipantId: "shard-0000000000000001", DatabaseId: sourceID, JournalCut: 7, ManifestDigest: strings.Repeat("a", 64), Checksum: strings.Repeat("b", 64), RowCount: 3, CapturedAtMillis: 1000, RetainedUntilMillis: 2000},
		{ParticipantId: "shard-0000000000000002", DatabaseId: sourceID, JournalCut: 19, ManifestDigest: strings.Repeat("c", 64), Checksum: strings.Repeat("d", 64), RowCount: 5, CapturedAtMillis: 1100, RetainedUntilMillis: 2100},
	}}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config := productionDatabaseConfig{Regions: []productionDatabaseRegion{{Region: "GRU", Writer: productionDatabaseHost{ServerIdentity: "host"}}}, NativeReceiptKeys: map[string]databaseadmission.ReadinessKey{"host": {KeyID: "receipt-key", PublicKey: public}}}
	for _, mutation := range []string{"valid", "signature", "receipt-digest", "checksum", "count", "missing-envelope", "envelope-digest", "envelope-source", "incarnation", "generation", "participant-id", "participant-source", "participant-cut", "participant-manifest", "participant-checksum", "participant-count", "participant-capture", "participant-retention", "participant-order", "extra-participant"} {
		t.Run(mutation, func(t *testing.T) {
			receipt := restoredrill.VerifiedNativeReceipt{SchemaVersion: 1, NativeReceiptBinding: restoredrill.NativeReceiptBinding{TenantID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ProjectID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", SourceDatabaseID: sourceID, TargetDatabaseID: targetID, TargetIncarnation: targetID, SourceJournalCut: 19, CapturedAtMillis: 1100, SourceChecksum: checksum, SourceRowCount: 8, RestoreEpoch: 8, IdempotencyKey: "restore-routed-1", OperationID: "restore-routed-1", RecoveryPointID: digest, RecoveryPointDigest: digest, Placement: []string{"GRU", "SFO"}}, TargetChecksum: checksum, TargetRowCount: 8, CompletedAtMillis: 1500}
			if mutation == "receipt-digest" {
				receipt.RecoveryPointDigest = strings.Repeat("f", 64)
			}
			payload, err := json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			signature := ed25519.Sign(key, append([]byte("terrascale/native-recovery-receipt/v1\x00"), payload...))
			if mutation == "signature" {
				signature[0] ^= 1
			}
			signed, err := json.Marshal(map[string]string{"key_id": "receipt-key", "payload_base64": base64.StdEncoding.EncodeToString(payload), "signature_base64": base64.StdEncoding.EncodeToString(signature)})
			if err != nil {
				t.Fatal(err)
			}
			stats := &pb.RestoreStatsResponse{SignedCompletedReceipt: signed, Checksum: checksum, RowCount: 8, JournalCut: "19", OperationId: "restore-routed-1", TargetDatabase: targetID, TargetOwner: source.Request.TenantID + "/" + source.Request.ProjectID, Placement: []string{"GRU", "SFO"}, Envelope: proto.Clone(wire).(*pb.RecoveryEnvelopeFacts)}
			switch mutation {
			case "checksum":
				stats.Checksum = strings.Repeat("f", 64)
			case "count":
				stats.RowCount++
			case "missing-envelope":
				stats.Envelope = nil
			case "envelope-digest":
				stats.Envelope.EnvelopeDigest = strings.Repeat("f", 64)
			case "envelope-source":
				stats.Envelope.DatabaseId = targetID
			case "incarnation":
				stats.Envelope.DatabaseIncarnation = strings.Repeat("1", 32)
			case "generation":
				stats.Envelope.RouteGeneration++
			case "participant-id":
				stats.Envelope.Participants[0].ParticipantId = "shard-0000000000000003"
			case "participant-source":
				stats.Envelope.Participants[0].DatabaseId = targetID
			case "participant-cut":
				stats.Envelope.Participants[0].JournalCut++ // max remains19; scalar receipt still matches.
			case "participant-manifest":
				stats.Envelope.Participants[0].ManifestDigest = strings.Repeat("f", 64)
			case "participant-checksum":
				stats.Envelope.Participants[0].Checksum = strings.Repeat("f", 64)
			case "participant-count":
				stats.Envelope.Participants[0].RowCount++
			case "participant-capture":
				stats.Envelope.Participants[0].CapturedAtMillis++
			case "participant-retention":
				stats.Envelope.Participants[0].RetainedUntilMillis++
			case "participant-order":
				stats.Envelope.Participants[0], stats.Envelope.Participants[1] = stats.Envelope.Participants[1], stats.Envelope.Participants[0]
			case "extra-participant":
				stats.Envelope.Participants = append(stats.Envelope.Participants, proto.Clone(stats.Envelope.Participants[0]).(*pb.RecoveryParticipant))
			}
			resolved, dispatched, completedCalls := 0, 0, 0
			adapter := newRestoreAdmission(config, func(_ context.Context, got databaseadmission.Record, selection databaseadmission.RestoreSelection) (*pb.ResolveRecoveryPointResponse, error) {
				resolved++
				if !reflect.DeepEqual(got, source) || selection.Kind != "latest" {
					t.Fatal("wrong resolver request")
				}
				return &pb.ResolveRecoveryPointResponse{SourceDatabase: sourceID, RecoveryPointId: digest, RecoveryPointDigest: digest, JournalCut: "19", CapturedAtMillis: 1100, Checksum: checksum, RowCount: 8, Placement: []string{"GRU", "SFO"}, Provider: pb.RestoreProvider_RESTORE_PROVIDER_OCI, Envelope: proto.Clone(wire).(*pb.RecoveryEnvelopeFacts)}, nil
			}, func(_ context.Context, target databaseadmission.Record, complete func(databaseadmission.Record, *pb.RestoreStatsResponse) error) error {
				dispatched++
				admitted := expected
				admitted.Epoch = 8
				if target.DatabaseID != targetID || !reflect.DeepEqual(*target.RestoreFacts, admitted) {
					t.Fatal("dispatch changed admitted facts")
				}
				completedCalls++
				return complete(target, stats)
			})
			facts, err := adapter.Resolve(t.Context(), source, databaseadmission.RestoreSelection{Kind: "latest"})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(facts, expected) {
				t.Fatalf("resolver facts = %+v, want %+v", facts, expected)
			}
			if !proto.Equal(restoreEnvelopeWire(facts.Envelope), wire) {
				t.Fatal("restore transport changes resolved vector")
			}
			facts.Epoch = 8 // Admission owns the epoch after native resolution.
			target := databaseadmission.Record{DatabaseID: targetID, Request: databaseadmission.Request{Environment: "production", TenantID: source.Request.TenantID, ProjectID: source.Request.ProjectID, ParentDatabaseID: sourceID, OperationID: "restore-routed-1", Regions: []string{"GRU", "SFO"}, RecoveryPointID: digest, JournalCut: "19", RestoreEpoch: 8, RestoreProvider: "oci"}, RestoreFacts: &facts, Restore: &databaseadmission.RestoreRequest{}, Targets: []databaseadmission.Target{{}}, PlacementTargets: []databaseadmission.PlacementTarget{{Region: "GRU", ServerIdentity: "host", AcceptedEpoch: 1, AcceptedRevision: 1, AcceptedGeneration: 1, AcceptedProof: []byte(`{"key_id":"placement","payload":"e30=","signature":"AA=="}`), AcceptedReceipt: []byte("accepted")}}}
			ack, err := adapter.Restore(t.Context(), target)
			if resolved != 1 || dispatched != 1 || completedCalls != 1 {
				t.Fatalf("wrong callback counts: %d/%d/%d", resolved, dispatched, completedCalls)
			}
			if mutation != "valid" {
				if err == nil || len(ack) != 0 {
					t.Fatalf("altered stats acknowledged: %s", mutation)
				}
				return
			}
			if err != nil || len(ack) == 0 {
				t.Fatalf("valid routed completion rejected: %v", err)
			}
			var value databaseadmission.RestoreAcknowledgement
			if err := json.Unmarshal(ack, &value, json.RejectUnknownMembers(true)); err != nil {
				t.Fatal(err)
			}
			want := databaseadmission.RestoreAcknowledgement{Version: 1, SourceDatabaseID: sourceID, TargetDatabaseID: targetID, Facts: facts}
			if !reflect.DeepEqual(value, want) {
				t.Fatalf("acknowledgement differs: %+v", value)
			}
		})
	}
}
