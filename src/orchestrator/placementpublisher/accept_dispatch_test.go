package placementpublisher

import (
	"context"
	"encoding/json/v2"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
	"terrascale.tech/orchestrator/src/orchestrator/tbep"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

func acceptanceTestRequest(t *testing.T) *pb.PlacementControlServiceAcceptRequest {
	t.Helper()
	payload, err := json.Marshal(placementtransition.Proof{SchemaVersion: 1, Kind: "accepted_epoch", Request: placementtransition.Request{OperationID: "proof-op", Epoch: 2, Generation: 3}, AuthorityEpoch: 5, JournalRevision: 8})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := json.Marshal(placementtransition.Signed{KeyID: "authority", Payload: payload, Signature: make([]byte, 64)})
	if err != nil {
		t.Fatal(err)
	}
	return &pb.PlacementControlServiceAcceptRequest{ProposalRevision: 9, Proof: envelope}
}

type acceptanceTestTarget struct {
	fakeTarget
	request *pb.PlacementControlServiceAcceptRequest
	effect  int
	unknown bool
}

func (target *acceptanceTestTarget) Accept(_ context.Context, id string, request *pb.PlacementControlServiceAcceptRequest) (*pb.PlacementControlServiceAcceptResponse, error) {
	if target.request != nil && !proto.Equal(target.request, request) {
		return nil, errors.New("proof retry changed")
	}
	if target.request == nil {
		target.request = proto.Clone(request).(*pb.PlacementControlServiceAcceptRequest)
		target.effect++
	}
	result, err := tbep.AcceptanceBinding(id, request)
	if err != nil {
		return nil, err
	}
	if target.unknown {
		target.unknown = false
		return nil, errors.New("response lost after durable proof")
	}
	return result, nil
}
func TestAcceptedProofDispatchPreservesUnknownRetry(t *testing.T) {
	cluster := newPlacementJournalCluster(t)
	connection := cluster.connect(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	target := &acceptanceTestTarget{unknown: true}
	bridge, err := StartAcceptanceHostBridge(ctx, connection, target)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	remote, err := NewRemoteTarget(connection, target.ServerIdentity(), target.Principal(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	request := acceptanceTestRequest(t)
	if _, err := remote.Accept(ctx, "proof-op", request); err == nil {
		t.Fatal("lost receipt treated as acceptance")
	}
	response, err := remote.Accept(ctx, "proof-op", request)
	if err != nil || response.ProposalRevision != 9 || response.Epoch != 2 || response.Generation != 3 || target.effect != 1 {
		t.Fatalf("retry=%v error=%v effects=%d", response, err, target.effect)
	}
	if response.Status != pb.PlacementAcceptanceStatus_PLACEMENT_ACCEPTANCE_STATUS_ADMITTED_CATCHING_UP {
		t.Fatal("acceptance presented as readiness")
	}
	if _, err := remote.Accept(ctx, "different-op", request); err == nil {
		t.Fatal("proof operation changed")
	}
	if target.effect != 1 {
		t.Fatal("invalid proof operation reached engine")
	}
	foreign, err := NewRemoteTarget(connection, target.ServerIdentity(), "spiffe://terrascale.tech/production/orchestrator/foreign", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := foreign.Accept(ctx, "proof-op", request); err == nil {
		t.Fatal("foreign principal accepted")
	}
}
