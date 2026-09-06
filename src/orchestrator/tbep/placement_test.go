package tbep

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"errors"
	"net"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
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
	proofPayload, _ := json.Marshal(placementtransition.Proof{SchemaVersion: 1, Kind: "accepted_epoch", Request: placementtransition.Request{OperationID: "proof-op", Epoch: 2, Generation: 3}, AuthorityEpoch: 1, JournalRevision: 7})
	proofEnvelope, _ := json.Marshal(placementtransition.Signed{KeyID: "authority", Payload: proofPayload, Signature: make([]byte, 64)})
	proofRequest := &pb.PlacementAcceptRequest{ProposalRevision: 1, Proof: proofEnvelope}
	if receipt, err := client.Accept(ctx, "proof-op", proofRequest); err != nil || receipt.Status != pb.PlacementAcceptanceStatus_PLACEMENT_ACCEPTANCE_STATUS_ADMITTED_CATCHING_UP {
		t.Fatalf("proof transport: %v %v", receipt, err)
	}
	if _, err := client.Accept(ctx, "wrong-op", proofRequest); err == nil {
		t.Fatal("mismatched proof operation accepted")
	}
	next := placementtransition.Request{OperationID: "next", ScopeID: "production/cluster", PriorEpoch: 1, Epoch: 2, Generation: 2, Members: []placementtransition.Member{{Identity: serverIdentity, Region: "GRU", PlacementDigest: strings.Repeat("b", 64)}, {Identity: "spiffe://terrascale.test/region/GRU/host/b/terrabase", Region: "GRU", PlacementDigest: strings.Repeat("c", 64)}}}
	nextDigest, err := placementtransition.RequestDigest(next)
	if err != nil {
		t.Fatal(err)
	}
	preparePayload, _ := json.Marshal(placementtransition.Prepared{SchemaVersion: 1, Kind: "prepared_epoch", Request: next, RequestDigest: nextDigest, PriorGeneration: 1, PreviousProofDigest: strings.Repeat("d", 64), AuthorityEpoch: 1, LeaseID: "lease", JournalRevision: 8})
	prepareEnvelope, _ := json.Marshal(placementtransition.Signed{KeyID: "authority", Payload: preparePayload, Signature: make([]byte, 64)})
	if _, err := client.Drain(ctx, "next", &pb.PlacementDrainRequest{PreparedTransition: prepareEnvelope}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Readiness(ctx, &pb.PlacementReadinessRequest{Tenant: "tenant", Project: "project", Database: "database", OperationId: "next", Nonce: strings.Repeat("a", 64)}); err != nil {
		t.Fatal(err)
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

func (server *placementTestServer) Accept(ctx context.Context, request *pb.PlacementAcceptRequest) (*pb.PlacementAcceptanceResponse, error) {
	scope, _ := metadata.FromIncomingContext(ctx)
	if len(scope.Get("x-tb-tenant")) != 0 || len(scope.Get("x-tb-project")) != 0 || len(scope.Get("x-tb-database")) != 0 {
		server.t.Error("proof received forbidden database scope")
	}
	if values := scope.Get("x-tb-principal"); len(values) != 1 || values[0] != clientIdentity {
		server.t.Error("proof principal not bound")
	}
	values := scope.Get("x-tb-idempotency-key")
	if len(values) != 1 {
		server.t.Error("proof operation metadata missing")
		return nil, errors.New("missing operation")
	}
	return AcceptanceBinding(values[0], request)
}

func (server *placementTestServer) Drain(ctx context.Context, request *pb.PlacementDrainRequest) (*pb.PlacementDrainResponse, error) {
	scope, _ := metadata.FromIncomingContext(ctx)
	if len(scope.Get("x-tb-tenant")) != 0 || len(scope.Get("x-tb-project")) != 0 || len(scope.Get("x-tb-database")) != 0 {
		server.t.Error("drain received database scope")
	}
	values := scope.Get("x-tb-idempotency-key")
	if len(values) != 1 {
		return nil, errors.New("drain operation absent")
	}
	prepared, err := DrainBinding(values[0], request)
	if err != nil {
		return nil, err
	}
	payload, _ := json.Marshal(placementtransition.DrainReceipt{Kind: "old_epoch_drained_fenced", MemberIdentity: serverIdentity, ScopeID: prepared.Request.ScopeID, PriorEpoch: prepared.Request.PriorEpoch, PriorGeneration: prepared.PriorGeneration, RequestDigest: prepared.RequestDigest, FrontierDigest: strings.Repeat("f", 64)})
	signed, _ := json.Marshal(placementtransition.Signed{KeyID: serverIdentity, Payload: payload, Signature: make([]byte, 64)})
	return &pb.PlacementDrainResponse{SignedReceipt: signed}, nil
}
func (server *placementTestServer) Readiness(ctx context.Context, request *pb.PlacementReadinessRequest) (*pb.PlacementDrainResponse, error) {
	scope, _ := metadata.FromIncomingContext(ctx)
	for _, key := range []string{"x-tb-tenant", "x-tb-project", "x-tb-database", "x-tb-idempotency-key"} {
		if len(scope.Get(key)) != 0 {
			server.t.Errorf("readiness received forbidden %s metadata", key)
		}
	}
	if request.Nonce != strings.Repeat("a", 64) {
		server.t.Error("challenge changed")
	}
	payload, _ := json.Marshal(map[string]string{"nonce": request.Nonce})
	signed, _ := json.Marshal(placementtransition.Signed{KeyID: "member-key", Payload: payload, Signature: make([]byte, 64)})
	return &pb.PlacementDrainResponse{SignedReceipt: signed}, nil
}
