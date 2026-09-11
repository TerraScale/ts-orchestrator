package tbep

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

type recoveryPointServer struct {
	pb.UnimplementedLifecycleControlServiceServer
	response *pb.ResolveRecoveryPointResponse
	request  *pb.ResolveRecoveryPointRequest
}

func (s *recoveryPointServer) ResolveRecoveryPoint(_ context.Context, request *pb.ResolveRecoveryPointRequest) (*pb.ResolveRecoveryPointResponse, error) {
	s.request = request
	return s.response, nil
}

func startRecoveryPointServer(t *testing.T, ca testCA, response *pb.ResolveRecoveryPointResponse) (*recoveryPointServer, Config) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &recoveryPointServer{response: response}
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{ca.issue(t, []string{serverIdentity}, x509.ExtKeyUsageServerAuth, false)},
		ClientCAs:    ca.roots, ClientAuth: tls.RequireAndVerifyClientCert,
	})))
	pb.RegisterLifecycleControlServiceServer(grpcServer, server)
	go func() { _ = grpcServer.Serve(listener) }()
	t.Cleanup(grpcServer.Stop)
	return server, Config{Endpoint: listener.Addr().String(), ServerIdentity: serverIdentity,
		Certificate: ca.issue(t, []string{clientIdentity}, x509.ExtKeyUsageClientAuth, false),
		Roots:       ca.roots, Tenant: "tenant", Project: "project", Database: "database", Timeout: time.Second}
}

func TestResolveRecoveryPointForwardsAuthenticatedSelectionAndFacts(t *testing.T) {
	ca := newTestCA(t)
	want := &pb.ResolveRecoveryPointResponse{OperationId: "resolve-1", SourceDatabase: "source", RecoveryPointId: "point", RecoveryPointDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", JournalCut: "42", Provider: pb.RestoreProvider_RESTORE_PROVIDER_OCI, CapturedAtMillis: 123, Checksum: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", RowCount: 9, Placement: []string{"GRU"}}
	server, config := startRecoveryPointServer(t, ca, want)
	client, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	assignment := LifecycleAssignment{Environment: "production", Tenant: "tenant", Project: "project", Database: "database", Region: "GRU", Member: "member", PlacementRevision: 3, AuthorityEpoch: 4, AuthorityLease: "lease", AuthoritySignature: []byte("proof"), OperationGrant: []byte("grant")}
	got, err := client.ResolveRecoveryPoint(t.Context(), assignment, "resolve-1", "point_id", "point", 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.GetRecoveryPointDigest() != want.GetRecoveryPointDigest() || server.request.GetSelectionKind() != "point_id" || server.request.GetPointId() != "point" || server.request.GetContext().GetAuthorityEpoch() != 4 {
		t.Fatalf("request/response lost authenticated facts: request=%+v response=%+v", server.request, got)
	}
}

func TestResolveRecoveryPointRejectsInvalidSelectionAndRebinding(t *testing.T) {
	ca := newTestCA(t)
	server, config := startRecoveryPointServer(t, ca, &pb.ResolveRecoveryPointResponse{OperationId: "other"})
	client, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	assignment := LifecycleAssignment{AuthoritySignature: []byte("proof"), OperationGrant: []byte("grant")}
	for _, tc := range []struct {
		name, kind, point string
		millis            uint64
	}{
		{"unknown kind", "archive", "", 0}, {"latest with point", "latest", "point", 0}, {"point without id", "point_id", "", 0}, {"unix selection", "latest", "", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := client.ResolveRecoveryPoint(t.Context(), assignment, "resolve", tc.kind, tc.point, tc.millis); err == nil {
				t.Fatal("invalid selection accepted")
			}
		})
	}
	if _, err := client.ResolveRecoveryPoint(t.Context(), assignment, "resolve-1", "latest", "", 0); err == nil {
		t.Fatal("response for another operation accepted")
	}
	_ = server
}
