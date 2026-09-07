package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"net"
	"terrascale.tech/orchestrator/internal/testtls"
	"terrascale.tech/orchestrator/src/orchestrator/tbep"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
	"testing"
	"time"
)

type transportLifecycleServer struct {
	pb.UnimplementedLifecycleControlServiceServer
}

func (transportLifecycleServer) EnsureSnapshot(_ context.Context, r *pb.LifecycleControlRequest) (*pb.LifecycleControlResponse, error) {
	return &pb.LifecycleControlResponse{Status: pb.LifecycleStatus_LIFECYCLE_STATUS_APPLIED, OperationId: r.OperationId}, nil
}
func startTransportLifecycleServer(t *testing.T, ca testtls.CA, identity string) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{ca.Issue(t, identity, tlsExtServerAuth())}, ClientCAs: ca.Roots, ClientAuth: tls.RequireAndVerifyClientCert})))
	pb.RegisterLifecycleControlServiceServer(s, transportLifecycleServer{})
	go s.Serve(l)
	t.Cleanup(s.Stop)
	return l.Addr().String()
}
func tlsExtServerAuth() x509.ExtKeyUsage { return x509.ExtKeyUsageServerAuth }
func TestTBEPTransportExactIdentity(t *testing.T) {
	ca := testtls.NewCA(t)
	clientID := "spiffe://terrascale.test/region/GRU/host/a/orchestrator"
	for _, serverID := range []string{"spiffe://terrascale.test/region/GRU/host/a/terrabase", "spiffe://terrascale.test/region/SFO/host/b/terrabase"} {
		endpoint := startTransportLifecycleServer(t, ca, serverID)
		c, err := tbep.New(tbep.Config{Endpoint: endpoint, ServerIdentity: serverID, Certificate: ca.Issue(t, clientID, x509.ExtKeyUsageClientAuth), Roots: ca.Roots, Tenant: "tenant", Project: "project", Database: "database", Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		err = c.EnsureSnapshot(t.Context(), tbep.LifecycleAssignment{Environment: "production", Tenant: "tenant", Project: "project", Database: "database", Region: "GRU", Member: "member", PlacementRevision: 1, AuthorityEpoch: 1, AuthorityLease: "lease", AuthoritySignature: []byte("proof"), OperationGrant: []byte("grant")}, "op")
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
}
