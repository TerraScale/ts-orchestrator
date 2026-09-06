package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"github.com/nats-io/nats.go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"testing"

	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/placementpublisher"
	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

func TestBootstrapRetriesOnlyTypedTransportOutage(t *testing.T) {
	for _, err := range []error{nats.ErrNoResponders, nats.ErrTimeout, status.Error(codes.Unavailable, "offline"), context.DeadlineExceeded} {
		if !transientBootstrapError(err) {
			t.Fatal("outage became static failure", err)
		}
	}
	for _, err := range []error{placementtransition.ErrInvalid, placementtransition.ErrConflict, status.Error(codes.PermissionDenied, "denied"), errors.New("bootstrap head missing for retained operation")} {
		if transientBootstrapError(err) {
			t.Fatal("invalid authority retried as outage", err)
		}
	}
}

type bootstrapTestJournal struct{ databasePlacementJournal }

func (j bootstrapTestJournal) Accept(_ context.Context, r placementpublisher.Record) error {
	j.databasePlacementJournal[r.ServerIdentity] = r
	return nil
}
func (j bootstrapTestJournal) Acknowledge(_ context.Context, r placementpublisher.Record, response *pb.PlacementControlServiceStageResponse) error {
	r.Receipt, _ = proto.Marshal(response)
	j.databasePlacementJournal[r.ServerIdentity] = r
	return nil
}

type bootstrapTestTarget struct {
	identity string
	staged   *int
}

func (t bootstrapTestTarget) Principal() string {
	return "spiffe://terrascale.tech/production/orchestrator/gru-1"
}
func (t bootstrapTestTarget) ServerIdentity() string { return t.identity }
func (t bootstrapTestTarget) Stage(_ context.Context, _ string, r *pb.PlacementControlServiceStageRequest) (*pb.PlacementControlServiceStageResponse, error) {
	*t.staged++
	return &pb.PlacementControlServiceStageResponse{Revision: 1, Proposal: r.Proposal, Status: pb.PlacementProposalStatus_PLACEMENT_PROPOSAL_STATUS_PENDING}, nil
}

func TestEmptyClusterBootstrapUsesConfiguredGrantAndNeverRecreatesMissingHead(t *testing.T) {
	record, _ := transitionFixture(t)
	config := &productionPlacementBootstrap{OperationID: "cluster-genesis", Environment: record.Request.Environment}
	staged := 0
	journal := bootstrapTestJournal{databasePlacementJournal{}}
	worker := &productionPlacementTransition{allocateStreams: func(context.Context, databaseadmission.Record, string) error { return nil }, registerUsage: func(context.Context, databaseadmission.Record, string) error { return nil }, issuer: &runtimeTestIssuer{}, pending: journal, check: func(context.Context) error { return nil }, bootstrapPublishers: map[string]*placementpublisher.Publisher{}}
	for n := range record.PlacementTargets {
		target := &record.PlacementTargets[n]
		request := new(pb.PlacementControlServiceStageRequest)
		_ = proto.Unmarshal(target.Proposal, request)
		request.Proposal.Assignments = nil
		request.Declarations = nil
		target.Proposal, _ = (proto.MarshalOptions{Deterministic: true}).Marshal(request)
		config.Targets = append(config.Targets, productionPlacementBootstrapTarget{target.ServerIdentity, target.MemberID, target.Region, target.Proposal})
		publisher, err := placementpublisher.New(journal, bootstrapTestTarget{target.ServerIdentity, &staged}, worker.check)
		if err != nil {
			t.Fatal(err)
		}
		worker.bootstrapPublishers[target.ServerIdentity] = publisher
	}
	request, err := transitionRequest(record)
	if err != nil {
		t.Fatal(err)
	}
	request.OperationID = config.OperationID
	digest, _ := placementtransition.RequestDigest(request)
	worker.acceptance = func(context.Context, databaseadmission.Record, string, *pb.PlacementControlServiceAcceptResponse) error {
		return nil
	}
	worker.acceptance = func(context.Context, databaseadmission.Record, string, *pb.PlacementControlServiceAcceptResponse) error {
		return nil
	}
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	grant, err := placementtransition.SignEvidence("genesis", key, placementtransition.GenesisGrant{Kind: "genesis_grant", GrantID: "explicit-cluster-grant", RequestDigest: digest})
	if err != nil {
		t.Fatal(err)
	}
	worker.config = productionPlacementTransitionConfig{Bootstrap: config, Issuer: placementtransition.Config{GenesisKeys: map[string]ed25519.PublicKey{"genesis": key.Public().(ed25519.PublicKey)}}, GenesisGrants: map[string]placementtransition.Signed{config.OperationID: grant}, Deliver: func(_ context.Context, _ string, _ string, revision uint64, proof placementtransition.Signed) (*pb.PlacementControlServiceAcceptResponse, error) {
		return testAcceptanceResponse(revision, proof), nil
	}}
	if err := worker.Bootstrap(t.Context()); err != nil {
		t.Fatal(err)
	}
	if staged != 2 {
		t.Fatal("bootstrap did not Stage both actual members")
	}
	// The fake retains its committed operation while reporting a lost head.
	if err := worker.Bootstrap(t.Context()); err == nil || !strings.Contains(err.Error(), "head missing") {
		t.Fatal("missing durable state became fresh genesis", err)
	}
	if staged != 2 {
		t.Fatal("re-genesis dispatched")
	}
}
