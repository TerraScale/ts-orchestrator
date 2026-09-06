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
	"google.golang.org/protobuf/proto"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

type placementTestServer struct {
	pb.UnimplementedPlacementControlServiceServer
	t       *testing.T
	request *pb.PlacementStageRequest
}

func (server *placementTestServer) Stage(ctx context.Context, request *pb.PlacementStageRequest) (*pb.PlacementProposalResponse, error) {
	scope, _ := metadata.FromIncomingContext(ctx)
	for _, key := range []string{"x-tb-tenant", "x-tb-project", "x-tb-database"} {
		if len(scope.Get(key)) != 0 {
			server.t.Errorf("unexpected database scope %s", key)
		}
	}
	if values := scope.Get("x-tb-principal"); len(values) != 1 || values[0] != clientIdentity {
		server.t.Error("principal not pinned to certificate")
	}
	if values := scope.Get("x-tb-idempotency-key"); len(values) != 1 || values[0] != "op-1" {
		server.t.Error("operation ID not exact")
	}
	if server.request != nil && !proto.Equal(server.request, request) {
		server.t.Error("retry request changed")
	}
	server.request = request
	return &pb.PlacementProposalResponse{Revision: 1, Proposal: request.Proposal, Status: pb.PlacementProposalStatus_PLACEMENT_PROPOSAL_STATUS_PENDING}, nil
}
func TestPlacementHostScopeAndExactTLS(t *testing.T) {
	ca := newTestCA(t)
	serverCertificate := ca.issue(t, []string{serverIdentity}, x509.ExtKeyUsageServerAuth, false)
	clientCertificate := ca.issue(t, []string{clientIdentity}, x509.ExtKeyUsageClientAuth, false)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: ca.roots, Certificates: []tls.Certificate{serverCertificate}})))
	pb.RegisterPlacementControlServiceServer(server, &placementTestServer{t: t})
	go server.Serve(listener)
	defer server.Stop()
	config := Config{Endpoint: listener.Addr().String(), ServerIdentity: serverIdentity, Certificate: clientCertificate, Roots: ca.roots, Timeout: time.Second}
	client, err := NewPlacement(config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	request := &pb.PlacementStageRequest{Proposal: &pb.PlacementProposal{Environment: "production", Cluster: "cluster", Generation: 1, Epoch: 1, Regions: []*pb.PlacementRegionSeats{{Region: "GRU", Members: []string{"b", "a"}}}, Assignments: []*pb.PlacementDatabaseAssignment{{Tenant: "tenant", Project: "project", Database: "database", Region: "GRU", WriterMember: "a", FollowerMember: "b"}}}}
	ctx := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("x-tb-principal", "foreign", "x-tb-tenant", "foreign", "x-tb-idempotency-key", "foreign"))
	for range 2 {
		result, err := client.Stage(ctx, "op-1", request)
		if err != nil || result.Revision != 1 {
			t.Fatalf("result=%v error=%v", result, err)
		}
	}
	if request.Proposal.Regions[0].Members[0] != "b" {
		t.Fatal("canonicalization mutated caller request")
	}
	config.Tenant = "scope"
	if _, err := NewPlacement(config); err == nil {
		t.Fatal("database metadata accepted")
	}
	config.Tenant = ""
	config.ServerIdentity = "spiffe://terrascale.test/region/GRU/host/foreign/terrabase"
	wrong, err := NewPlacement(config)
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.Close()
	if _, err := wrong.Stage(t.Context(), "op-1", request); err == nil {
		t.Fatal("wrong engine identity accepted")
	}
}
