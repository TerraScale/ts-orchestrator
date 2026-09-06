package placementpublisher

import (
	"context"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
	"terrascale.tech/orchestrator/src/orchestrator/tbep"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

type controlTestTarget struct {
	fakeTarget
	fences         int
	prepared       []byte
	lost           bool
	readinessCalls int
}

func (target *controlTestTarget) Drain(_ context.Context, id string, request *pb.PlacementControlServiceDrainRequest) (*pb.PlacementControlServiceDrainResponse, error) {
	prepared, err := tbep.DrainBinding(id, request)
	if err != nil {
		return nil, err
	}
	if target.prepared == nil {
		target.prepared = request.PreparedTransition
		target.fences++
	}
	payload, _ := json.Marshal(placementtransition.DrainReceipt{Kind: "old_epoch_drained_fenced", MemberIdentity: target.ServerIdentity(), ScopeID: prepared.Request.ScopeID, PriorEpoch: prepared.Request.PriorEpoch, PriorGeneration: prepared.PriorGeneration, RequestDigest: prepared.RequestDigest, FrontierDigest: strings.Repeat("a", 64)})
	signed, _ := json.Marshal(placementtransition.Signed{KeyID: target.ServerIdentity(), Payload: payload, Signature: make([]byte, 64)})
	if target.lost {
		target.lost = false
		return nil, errors.New("fence reply lost")
	}
	return &pb.PlacementControlServiceDrainResponse{SignedReceipt: signed}, nil
}
func (target *controlTestTarget) Readiness(_ context.Context, request *pb.PlacementControlServiceReadinessRequest) (*pb.PlacementControlServiceReadinessResponse, error) {
	target.readinessCalls++
	payload, _ := json.Marshal(map[string]string{"nonce": request.Nonce, "operation_id": request.OperationId})
	envelope, _ := json.Marshal(placementtransition.Signed{KeyID: "readiness", Payload: payload, Signature: make([]byte, 64)})
	return &pb.PlacementControlServiceReadinessResponse{SignedReceipt: envelope}, nil
}
func TestDrainAndReadinessDispatchPreserveChallengesAndRetries(t *testing.T) {
	cluster := newPlacementJournalCluster(t)
	connection := cluster.connect(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	target := &controlTestTarget{lost: true}
	drain, err := StartDrainHostBridge(ctx, connection, target)
	if err != nil {
		t.Fatal(err)
	}
	defer drain.Close()
	readiness, err := StartReadinessHostBridge(ctx, connection, target)
	if err != nil {
		t.Fatal(err)
	}
	defer readiness.Close()
	remote, err := NewRemoteTarget(connection, target.ServerIdentity(), target.Principal(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	next := placementtransition.Request{OperationID: "next", ScopeID: "production/cluster", PriorEpoch: 1, Epoch: 2, Generation: 2, Members: []placementtransition.Member{{Identity: target.ServerIdentity(), Region: "GRU", PlacementDigest: strings.Repeat("a", 64)}, {Identity: "spiffe://terrascale.tech/production/terrabase/member-b", Region: "GRU", PlacementDigest: strings.Repeat("b", 64)}}}
	digest, err := placementtransition.RequestDigest(next)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(placementtransition.Prepared{SchemaVersion: 1, Kind: "prepared_epoch", Request: next, RequestDigest: digest, PriorGeneration: 1, PreviousProofDigest: strings.Repeat("c", 64), AuthorityEpoch: 4, LeaseID: "lease", JournalRevision: 20})
	prepared, _ := json.Marshal(placementtransition.Signed{KeyID: "authority", Payload: payload, Signature: make([]byte, 64)})
	request := &pb.PlacementControlServiceDrainRequest{PreparedTransition: prepared}
	if _, err := remote.Drain(ctx, "next", request); err == nil {
		t.Fatal("unknown fence treated as success")
	}
	if _, err := remote.Drain(ctx, "next", request); err != nil {
		t.Fatal(err)
	}
	if target.fences != 1 {
		t.Fatal("retry repeated fence effect")
	}
	if _, err := remote.Drain(ctx, "other", request); err == nil {
		t.Fatal("operation replacement accepted")
	}
	challenge := &pb.PlacementControlServiceReadinessRequest{Tenant: "tenant", Project: "project", Database: "database", OperationId: "next", Nonce: strings.Repeat("d", 64)}
	reply, err := remote.Readiness(ctx, challenge)
	if err != nil {
		t.Fatal(err)
	}
	var envelope placementtransition.Signed
	if json.Unmarshal(reply.SignedReceipt, &envelope) != nil {
		t.Fatal("signed bytes lost")
	}
	var observed map[string]string
	if json.Unmarshal(envelope.Payload, &observed) != nil || observed["nonce"] != challenge.Nonce || observed["operation_id"] != challenge.OperationId {
		t.Fatal("readiness challenge changed")
	}
	challenge.Nonce = ""
	if _, err := remote.Readiness(ctx, challenge); err == nil {
		t.Fatal("unchallenged readiness accepted")
	}
	if target.readinessCalls != 1 {
		t.Fatal("invalid challenge reached source")
	}
}
