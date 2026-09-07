package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"net"
	"strings"
	"terrascale.tech/orchestrator/internal/testtls"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
	"terrascale.tech/orchestrator/src/orchestrator/tbep"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
	"testing"
	"time"
)

// Matches native grant signature, expiry, authority and immutable restore checks.
type expiringRestoreStatsServer struct {
	pb.UnimplementedLifecycleControlServiceServer
	public ed25519.PublicKey
	digest string
}

func (s expiringRestoreStatsServer) RestoreStats(_ context.Context, r *pb.RestoreStatsRequest) (*pb.RestoreStatsResponse, error) {
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
	return &pb.RestoreStatsResponse{OperationId: r.OperationId, TargetOwner: r.TargetOwner, TargetDatabase: r.TargetDatabase, JournalCut: r.JournalCut, Checksum: strings.Repeat("a", 64), RowCount: 1, Placement: []string{"GRU", "SFO", "FRA"}, SignedCompletedReceipt: []byte("fixture-complete-observation")}, nil
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
	pb.RegisterLifecycleControlServiceServer(server, expiringRestoreStatsServer{public: public, digest: digest})
	go server.Serve(listener)
	t.Cleanup(server.Stop)
	client, err := tbep.New(tbep.Config{Endpoint: listener.Addr().String(), ServerIdentity: serverID, Certificate: ca.Issue(t, "spiffe://terrascale.test/region/GRU/host/a/orchestrator", x509.ExtKeyUsageClientAuth), Roots: ca.Roots, Tenant: "tenant", Project: "project", Database: "target", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	placement := tbep.LifecycleAssignment{Environment: "production", Tenant: "tenant", Project: "project", Database: "target", Region: "GRU", Member: "member", PlacementRevision: 1, AuthorityEpoch: 1, AuthorityLease: "old-lease", AuthoritySignature: []byte("accepted-full-GRU-SFO-FRA-proof")}
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
		_, err := client.RestoreStats(t.Context(), a, original.OperationID, "tenant/project", "target", "42", 7, []string{"GRU", "SFO", "FRA"})
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
}
