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
	"google.golang.org/grpc/metadata"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

type authBootstrapTestServer struct {
	pb.UnimplementedAuthGroupBootstrapServiceServer
	t *testing.T
}

func (server *authBootstrapTestServer) check(ctx context.Context) {
	scope, _ := metadata.FromIncomingContext(ctx)
	if values := scope.Get("x-tb-principal"); len(values) != 1 || values[0] != clientIdentity {
		server.t.Error("principal not pinned")
	}
	for _, key := range []string{"x-tb-tenant", "x-tb-project", "x-tb-database"} {
		if len(scope.Get(key)) != 0 {
			server.t.Error("unexpected database metadata")
		}
	}
}
func (server *authBootstrapTestServer) Identity(ctx context.Context, _ *pb.AuthStorageIdentityRequest) (*pb.AuthStorageIdentity, error) {
	server.check(ctx)
	return &pb.AuthStorageIdentity{Member: "01ARZ3NDEKTSV4RRFFQ69G5FA5", StorageIncarnation: "01ARZ3NDEKTSV4RRFFQ69G5FA5"}, nil
}
func (server *authBootstrapTestServer) Bootstrap(ctx context.Context, request *pb.AuthGroupBootstrapRequest) (*pb.AuthGroupBootstrapReceipt, error) {
	server.check(ctx)
	scope, _ := metadata.FromIncomingContext(ctx)
	if values := scope.Get("x-tb-idempotency-key"); len(values) != 1 || values[0] != request.OperationId {
		server.t.Error("retry identity changed")
	}
	return &pb.AuthGroupBootstrapReceipt{GroupId: request.Grant.GroupId, Generation: 1, AuthorityRevision: request.Grant.AuthorityRevision, StorageIncarnation: request.Grant.Voters[0].StorageIncarnation, Status: 1, Grant: request.Grant, OperationId: request.OperationId}, nil
}
func TestAuthBootstrapHostScopeAndPinnedTLS(t *testing.T) {
	const serverIdentity = "spiffe://terrascale.tech/production/terrabase-member/01ARZ3NDEKTSV4RRFFQ69G5FA0/01ARZ3NDEKTSV4RRFFQ69G5FA5"
	ca := newTestCA(t)
	serverCertificate := ca.issue(t, []string{serverIdentity}, x509.ExtKeyUsageServerAuth, false)
	clientCertificate := ca.issue(t, []string{clientIdentity}, x509.ExtKeyUsageClientAuth, false)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: ca.roots, Certificates: []tls.Certificate{serverCertificate}})))
	pb.RegisterAuthGroupBootstrapServiceServer(server, &authBootstrapTestServer{t: t})
	go server.Serve(listener)
	defer server.Stop()
	config := Config{Endpoint: listener.Addr().String(), ServerIdentity: serverIdentity, Certificate: clientCertificate, Roots: ca.roots, Timeout: time.Second}
	client, err := NewAuthBootstrap(config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	grant := &pb.AuthGroupBootstrapGrant{Environment: "production", Cluster: "01ARZ3NDEKTSV4RRFFQ69G5FA0", GroupId: "01ARZ3NDEKTSV4RRFFQ69G5FA1", Tenant: "01ARZ3NDEKTSV4RRFFQ69G5FA2", Project: "01ARZ3NDEKTSV4RRFFQ69G5FA3", Database: "01ARZ3NDEKTSV4RRFFQ69G5FA4", Generation: 1, Regions: []string{"GRU"}, AuthorityRevision: 9, GenesisNode: 1}
	for i := range 2 {
		identity := serverIdentity
		if i > 0 {
			identity = "spiffe://terrascale.tech/production/terrabase-member/01ARZ3NDEKTSV4RRFFQ69G5FA0/01ARZ3NDEKTSV4RRFFQ69G5FA" + string(rune('5'+i))
		}
		member := "01ARZ3NDEKTSV4RRFFQ69G5FA" + string(rune('5'+i))
		grant.Voters = append(grant.Voters, &pb.AuthGroupVoter{NodeId: uint64(i + 1), Member: member, SpiffeUri: identity, Region: "GRU", StorageIncarnation: member})
	}
	ctx := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("x-tb-principal", "foreign", "x-tb-tenant", "foreign"))
	if _, err := client.Identity(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Bootstrap(ctx, &pb.AuthGroupBootstrapRequest{OperationId: grant.GroupId, Grant: grant}); err != nil {
		t.Fatal(err)
	}
	config.ServerIdentity = "spiffe://terrascale.test/foreign"
	wrong, err := NewAuthBootstrap(config)
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.Close()
	if _, err := wrong.Identity(ctx); err == nil {
		t.Fatal("foreign server accepted")
	}
}
