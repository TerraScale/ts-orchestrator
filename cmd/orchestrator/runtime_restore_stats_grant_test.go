package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"net"
	"strings"
	"sync"
	"terrascale.tech/orchestrator/internal/testtls"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
	"terrascale.tech/orchestrator/src/orchestrator/restoredrill"
	"terrascale.tech/orchestrator/src/orchestrator/tbep"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
	"testing"
	"time"
)

// Matches native grant signature, expiry, authority and immutable restore checks.
type expiringRestoreStatsServer struct {
	pb.UnimplementedLifecycleControlServiceServer
	public  ed25519.PublicKey
	digest  string
	mu      sync.Mutex
	receipt []byte
}

func (s *expiringRestoreStatsServer) RestoreStats(_ context.Context, r *pb.RestoreStatsRequest) (*pb.RestoreStatsResponse, error) {
	c := r.GetContext()
	var envelope placementtransition.Signed
	var g lifecycleOperationGrant
	if c == nil || json.Unmarshal(c.OperationGrant, &envelope) != nil || envelope.KeyID != "authority-key" || !ed25519.Verify(s.public, append([]byte("terrabase-placement-transition-v1\x00"), envelope.Payload...), envelope.Signature) || json.Unmarshal(envelope.Payload, &g) != nil {
		return nil, status.Error(codes.PermissionDenied, "signature")
	}
	now := time.Now().UnixMilli()
	proof := sha256.Sum256(c.AuthoritySignature)
	if now < g.IssuedAtUnixMillis || now >= g.ExpiresAtUnixMillis || g.ExpiresAtUnixMillis-g.IssuedAtUnixMillis > 300000 || g.Action != "restore_to_target" || g.OperationID != r.OperationId || g.AcceptedRestoreRequestDigest != s.digest || g.Tenant != c.Tenant || g.Project != c.Project || g.Database != c.Database || g.Region != c.Region || g.Member != c.Member || g.AuthorityEpoch != c.AuthorityEpoch || g.AuthorityLease != c.AuthorityLease || g.AcceptedPlacementRevision != c.PlacementRevision || g.AcceptedProofDigest != hex.EncodeToString(proof[:]) {
		return nil, status.Error(codes.PermissionDenied, "expired or rebound grant")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return &pb.RestoreStatsResponse{OperationId: r.OperationId, TargetOwner: r.TargetOwner, TargetDatabase: r.TargetDatabase, JournalCut: r.JournalCut, Checksum: strings.Repeat("a", 64), RowCount: 1, Placement: []string{"GRU", "SFO", "FRA"}, SignedCompletedReceipt: s.receipt}, nil
}
func TestRestoreStatsRPCRenewsExpiredOriginalGrantWithoutChangingRestore(t *testing.T) {
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := testtls.NewCA(t)
	serverID := "spiffe://terrascale.test/region/GRU/host/a/terrabase"
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{ca.Issue(t, serverID, x509.ExtKeyUsageServerAuth)}, ClientCAs: ca.Roots, ClientAuth: tls.RequireAndVerifyClientCert})))
	digest := strings.Repeat("b", 64)
	fixture := &expiringRestoreStatsServer{public: public, digest: digest, receipt: []byte("fixture-complete-observation")}
	pb.RegisterLifecycleControlServiceServer(server, fixture)
	go server.Serve(listener)
	t.Cleanup(server.Stop)
	clientConfig := tbep.Config{Endpoint: listener.Addr().String(), ServerIdentity: serverID, Certificate: ca.Issue(t, "spiffe://terrascale.test/region/GRU/host/a/orchestrator", x509.ExtKeyUsageClientAuth), Roots: ca.Roots, Tenant: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Project: "01ARZ3NDEKTSV4RRFFQ69G5FAW", Database: "01ARZ3NDEKTSV4RRFFQ69G5FAY", Timeout: time.Second}
	client, err := tbep.New(clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	placement := tbep.LifecycleAssignment{Environment: "production", Tenant: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Project: "01ARZ3NDEKTSV4RRFFQ69G5FAW", Database: "01ARZ3NDEKTSV4RRFFQ69G5FAY", Region: "GRU", Member: "member", PlacementRevision: 1, AuthorityEpoch: 1, AuthorityLease: "old-lease", AuthoritySignature: []byte(`{"key_id":"placement","payload":"e30=","signature":"AA=="}`)}
	now := time.Now()
	proof := sha256.Sum256(placement.AuthoritySignature)
	original := lifecycleOperationGrant{Version: 1, Domain: lifecycleGrantDomain, Environment: placement.Environment, Tenant: placement.Tenant, Project: placement.Project, Database: placement.Database, Region: placement.Region, Member: placement.Member, Action: "restore_to_target", OperationID: "original-restore", AcceptedProofDigest: hex.EncodeToString(proof[:]), AcceptedPlacementRevision: 1, AuthorityEpoch: 1, AuthorityLease: "old-lease", IssuedAtUnixMillis: now.Add(-time.Minute).UnixMilli(), ExpiresAtUnixMillis: now.Add(-30 * time.Second).UnixMilli(), AcceptedRestoreRequestDigest: digest}
	signed, err := placementtransition.SignEvidence("authority-key", key, original)
	if err != nil {
		t.Fatal(err)
	}
	placement.OperationGrant, err = json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	call := func(a tbep.LifecycleAssignment) error {
		_, err := client.RestoreStats(t.Context(), a, original.OperationID, placement.Tenant+"/"+placement.Project, "01ARZ3NDEKTSV4RRFFQ69G5FAY", "42", 7, []string{"GRU", "SFO", "FRA"})
		return err
	}
	if err := call(placement); err == nil {
		t.Fatal("expired original grant accepted")
	}
	issuer := productionDatabaseBackupPort{keyID: "authority-key", key: key, check: func(context.Context) error { return nil }, refresh: func(context.Context) (authority.RegionalAuthorityLeaseDocument, error) {
		return authority.RegionalAuthorityLeaseDocument{Epoch: 2, LeaseId: "current-lease", IssuedAt: time.Now(), DurationMilliseconds: 60000}, nil
	}}
	renewed, err := issuer.renewRestoreStatsGrant(t.Context(), placement, original)
	if err != nil {
		t.Fatal(err)
	}
	if err := call(renewed); err != nil {
		t.Fatal(err)
	}
	foreign := original
	foreign.AcceptedRestoreRequestDigest = strings.Repeat("c", 64)
	rebound, err := issuer.renewRestoreStatsGrant(t.Context(), placement, foreign)
	if err != nil {
		t.Fatal(err)
	}
	if err := call(rebound); err == nil {
		t.Fatal("different immutable restore digest accepted")
	}
	changedPlacement := placement
	changedPlacement.AuthoritySignature = []byte("changed-full-placement")
	if _, err := issuer.renewRestoreStatsGrant(t.Context(), changedPlacement, original); err == nil {
		t.Fatal("changed accepted placement admitted")
	}
	if original.ExpiresAtUnixMillis >= time.Now().UnixMilli() {
		t.Fatal("original grant was mutated")
	}
	t.Run("actual production branch Stats renews and verifies completion", func(t *testing.T) {
		facts := restoredrill.JournalFacts{CapturedAtMillis: uint64(now.Add(-time.Minute).UnixMilli()), ManifestDigest: digest, Checksum: strings.Repeat("a", 64), RowCount: 1}
		record := databaseadmission.Record{Targets: []databaseadmission.Target{{}}, DatabaseID: placement.Database, Request: databaseadmission.Request{Environment: placement.Environment, TenantID: placement.Tenant, ProjectID: placement.Project, ParentDatabaseID: "01ARZ3NDEKTSV4RRFFQ69G5FAX", OperationID: original.OperationID, RecoveryPointID: digest, JournalCut: "42", RestoreEpoch: 7, Regions: []string{"GRU", "SFO", "FRA"}}, PlacementTargets: []databaseadmission.PlacementTarget{{ServerIdentity: serverID, MemberID: placement.Member, Region: placement.Region, AcceptedRevision: 1, AcceptedEpoch: 1, AcceptedGeneration: 1, AcceptedProof: placement.AuthoritySignature, AcceptedReceipt: []byte("accepted"), AcceptedProofDigest: original.AcceptedProofDigest}}}
		binding := restoredrill.NativeReceiptBinding{TenantID: record.Request.TenantID, ProjectID: record.Request.ProjectID, SourceDatabaseID: record.Request.ParentDatabaseID, TargetDatabaseID: record.DatabaseID, TargetIncarnation: record.DatabaseID, SourceJournalCut: 42, CapturedAtMillis: facts.CapturedAtMillis, SourceChecksum: facts.Checksum, SourceRowCount: 1, RestoreEpoch: 7, IdempotencyKey: original.OperationID, OperationID: original.OperationID, RecoveryPointID: digest, RecoveryPointDigest: digest, Placement: record.Request.Regions}
		payload, err := json.Marshal(restoredrill.VerifiedNativeReceipt{SchemaVersion: 1, NativeReceiptBinding: binding, TargetChecksum: facts.Checksum, TargetRowCount: 1, CompletedAtMillis: uint64(now.UnixMilli())})
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := json.Marshal(map[string]string{"key_id": "receipt-key", "payload_base64": base64.StdEncoding.EncodeToString(payload), "signature_base64": base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte("terrascale/native-recovery-receipt/v1\x00"), payload...)))})
		if err != nil {
			t.Fatal(err)
		}
		fixture.mu.Lock()
		fixture.receipt = receipt
		fixture.mu.Unlock()
		host := productionDatabaseHost{ServerIdentity: serverID, MemberID: placement.Member}
		config := productionDatabaseConfig{Regions: []productionDatabaseRegion{{Region: "GRU", Writer: host}}, NativeReceiptKeys: map[string]databaseadmission.ReadinessKey{serverID: {KeyID: "receipt-key", PublicKey: public}}}
		port := newProductionDatabaseBranchPort(nil, config, issuer)
		if port.renewStatsGrant == nil || port.acceptedRecord == nil || port.statsClient == nil || port.grantJournal == nil {
			t.Fatal("production constructor omitted Stats dependencies")
		}
		port.acceptedRecord = func(context.Context, string) (databaseadmission.Record, error) { return record, nil }
		port.statsClient = func(productionDatabaseHost, databaseadmission.Record) (*tbep.Client, error) {
			return tbep.New(clientConfig)
		}
		journal := &memoryRestoreStatsGrant{record: lifecycleGrantRecord{Scope: placement.Tenant + ":" + placement.Project + ":" + placement.Database + ":" + record.DatabaseID, Action: "restore_to_target", Operation: original.OperationID, ProofDigest: digest, Grant: placement.OperationGrant}}
		port.grantJournal = func(op string) (restoreStatsGrantJournal, error) {
			if op != original.OperationID {
				t.Fatal("Stats invented operation")
			}
			return journal, nil
		}
		got, err := port.Stats(t.Context(), restoredrill.ScratchBranch{ID: record.DatabaseID, Expected: facts})
		if err != nil {
			t.Fatal(err)
		}
		if got.Checksum != facts.Checksum || got.RowCount != facts.RowCount {
			t.Fatal("wrong verified stats")
		}
	})

}

type memoryRestoreStatsGrant struct{ record lifecycleGrantRecord }

func (j *memoryRestoreStatsGrant) Transact(_ context.Context, _ bool, change func(*lifecycleGrantRecord) error) error {
	return change(&j.record)
}
