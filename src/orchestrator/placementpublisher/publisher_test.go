package placementpublisher

import (
	"context"
	"errors"
	"google.golang.org/protobuf/proto"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
	"testing"
)

func testRequest() *pb.PlacementStageRequest {
	return &pb.PlacementStageRequest{Proposal: &pb.PlacementProposal{Environment: "production", Cluster: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Generation: 1, Epoch: 1, Regions: []*pb.PlacementRegionSeats{{Region: "GRU", Members: []string{"01ARZ3NDEKTSV4RRFFQ69G5FAW", "01ARZ3NDEKTSV4RRFFQ69G5FAX"}}}, Assignments: []*pb.PlacementDatabaseAssignment{{Tenant: "01ARZ3NDEKTSV4RRFFQ69G5FAY", Project: "01ARZ3NDEKTSV4RRFFQ69G5FAZ", Database: "01ARZ3NDEKTSV4RRFFQ69G5FB0", Region: "GRU", WriterMember: "01ARZ3NDEKTSV4RRFFQ69G5FAW", FollowerMember: "01ARZ3NDEKTSV4RRFFQ69G5FAX"}}}}
}

type fakeTarget struct {
	effects  int
	unknown  bool
	results  map[string]*pb.PlacementProposalResponse
	requests map[string]*pb.PlacementStageRequest
}

func newFakeTarget() *fakeTarget {
	return &fakeTarget{results: map[string]*pb.PlacementProposalResponse{}, requests: map[string]*pb.PlacementStageRequest{}}
}
func (*fakeTarget) Principal() string {
	return "spiffe://terrascale.tech/production/orchestrator/member-a"
}
func (*fakeTarget) ServerIdentity() string {
	return "spiffe://terrascale.tech/production/terrabase/member-a"
}
func (f *fakeTarget) Stage(_ context.Context, id string, request *pb.PlacementStageRequest) (*pb.PlacementProposalResponse, error) {
	if prior, ok := f.requests[id]; ok && !proto.Equal(prior, request) {
		return nil, errors.New("changed retry")
	}
	if result, ok := f.results[id]; ok {
		return result, nil
	}
	f.effects++
	f.requests[id] = proto.Clone(request).(*pb.PlacementStageRequest)
	result := &pb.PlacementProposalResponse{Revision: uint64(f.effects), Proposal: request.Proposal, Status: pb.PlacementProposalStatus_PLACEMENT_PROPOSAL_STATUS_PENDING}
	f.results[id] = result
	if f.unknown {
		f.unknown = false
		return nil, errors.New("response lost after persistence")
	}
	return result, nil
}
func TestRecordCanonicalizationAndIdentityBinding(t *testing.T) {
	target := newFakeTarget()
	request := testRequest()
	record, err := NewRecord("op", target.ServerIdentity(), target.Principal(), request)
	if err != nil {
		t.Fatal(err)
	}
	request.Proposal.Regions[0].Members[0], request.Proposal.Regions[0].Members[1] = request.Proposal.Regions[0].Members[1], request.Proposal.Regions[0].Members[0]
	same, err := NewRecord("op", target.ServerIdentity(), target.Principal(), request)
	if err != nil || !sameIntent(record, same) {
		t.Fatal("canonical order changed durable retry")
	}
	record.Principal = "untrusted"
	if _, err := decodeRecord(record); err == nil {
		t.Fatal("invalid identity accepted")
	}
}
