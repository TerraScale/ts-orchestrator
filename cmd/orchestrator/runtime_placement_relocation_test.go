package main

import (
	"encoding/json/v2"
	"testing"

	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/placementrelocation"
	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

func TestRelocationBuildPreservesDatabaseResidencyAndSurvivingSeats(t *testing.T) {
	record, _ := transitionFixture(t)
	request, err := transitionRequest(record)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := placementtransition.RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(placementtransition.Proof{Kind: "accepted_epoch", Request: request, RequestDigest: digest})
	if err != nil {
		t.Fatal(err)
	}
	removed := record.PlacementTargets[0]
	replacement := placementrelocation.Target{ServerIdentity: "spiffe://terrascale.tech/prod/terrabase-member/" + "01ARZ3NDEKTSV4RRFFQ69G5FAV/01ARZ3NDEKTSV4RRFFQ69G5FAZ", MemberID: "01ARZ3NDEKTSV4RRFFQ69G5FAZ", Region: removed.Region}
	stage := new(pb.PlacementStageRequest)
	if err := proto.Unmarshal(removed.Proposal, stage); err != nil {
		t.Fatal(err)
	}
	replacement.ServerIdentity = "spiffe://terrascale.tech/" + stage.Proposal.Environment + "/terrabase-member/" + stage.Proposal.Cluster + "/" + replacement.MemberID
	revisions := map[string]uint64{replacement.ServerIdentity: 0}
	for _, target := range record.PlacementTargets {
		revisions[target.ServerIdentity] = 1
	}
	input := placementrelocation.BuildInput{OperationID: "relocate-1", RemovedIdentity: removed.ServerIdentity, Replacement: replacement, PriorProof: placementtransition.Signed{Payload: payload}, PriorStage: removed.Proposal, Records: []databaseadmission.Record{record}, Revisions: revisions}
	plan, err := placementrelocation.Build(input)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Request.Epoch != request.Epoch+1 || plan.Request.Generation != request.Generation+1 || plan.Request.PriorEpoch != request.Epoch {
		t.Fatal("successor did not advance exact prior")
	}
	if len(plan.Targets) != len(record.PlacementTargets) {
		t.Fatal("RF2 seat count changed")
	}
	for _, target := range plan.Targets {
		if target.ServerIdentity == removed.ServerIdentity {
			t.Fatal("removed host retained")
		}
	}
	input.Replacement.Region = "FRA"
	if input.Replacement.Region == removed.Region {
		input.Replacement.Region = "SFO"
	}
	if _, err := placementrelocation.Build(input); err == nil {
		t.Fatal("residency change accepted")
	}
	input.Replacement = replacement
	delete(input.Revisions, replacement.ServerIdentity)
	if _, err := placementrelocation.Build(input); err == nil {
		t.Fatal("unknown target revision guessed")
	}
}
