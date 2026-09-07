package main

import (
	"encoding/json/v2"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/authorityjournal"
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
	t.Run("durable plan survives restart and fences old authority", func(t *testing.T) {
		cluster := newRotationStateCluster(t)
		connection := cluster.connect(t)
		store := openRotationTestLeaseStore(t, t.Context(), connection, true)
		lease := rotationTestLease(1, "global-controller-gru-relocation")
		putRotationTestLease(t, t.Context(), store, lease)
		config := authorityjournal.Config{Connection: connection, CandidateID: lease.CandidateId, AuthorityEpoch: 1, LeaseID: lease.LeaseId}
		journal, err := placementrelocation.New(config)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := journal.Begin(t.Context(), plan); err != nil {
			t.Fatal(err)
		}
		restarted, err := placementrelocation.New(config)
		if err != nil {
			t.Fatal(err)
		}
		retained, err := restarted.Load(t.Context(), plan.OperationID)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := placementrelocation.Digest(plan)
		got, _ := placementrelocation.Digest(retained.Plan)
		if want != got {
			t.Fatal("restart changed retained placement intent")
		}
		if _, err := restarted.Begin(t.Context(), plan); err != nil {
			t.Fatal("retry after lost acknowledgement", err)
		}
		changed := plan
		changed.Targets = append([]placementrelocation.Target(nil), plan.Targets...)
		request := new(pb.PlacementStageRequest)
		if err := proto.Unmarshal(changed.Targets[0].Proposal, request); err != nil {
			t.Fatal(err)
		}
		request.ExpectedRevision++
		changed.Targets[0].Proposal, _ = proto.Marshal(request)
		if _, err := restarted.Begin(t.Context(), changed); !errors.Is(err, placementrelocation.ErrConflict) {
			t.Fatalf("changed local CAS revision replay: %v", err)
		}
		putRotationTestLease(t, t.Context(), store, rotationTestLease(2, "global-controller-gru-successor"))
		if _, err := restarted.Load(t.Context(), plan.OperationID); !errors.Is(err, authorityjournal.ErrFenced) {
			t.Fatalf("expired authority read: %v", err)
		}
	})
	t.Run("accepted evidence cannot precede prepared intent", func(t *testing.T) {
		operation := placementrelocation.Operation{Plan: plan, Acceptances: map[string][]byte{}}
		if err := placementrelocation.ValidateOperation(operation); err != nil {
			t.Fatal(err)
		}
		operation.Ready = true
		if placementrelocation.ValidateOperation(operation) == nil {
			t.Fatal("readiness without accepted evidence passed")
		}
		operation.Ready = false
		d, _ := placementtransition.RequestDigest(plan.Request)
		proof := placementtransition.Proof{Kind: "accepted_epoch", Request: plan.Request, RequestDigest: d, PreviousProofDigest: placementrelocation.BytesDigest(plan.PriorProof.Payload)}
		operation.Accepted.Payload, _ = json.Marshal(proof)
		if placementrelocation.ValidateOperation(operation) == nil {
			t.Fatal("accepted proof without prepared intent passed")
		}
		prepared := placementtransition.Prepared{Kind: "prepared_epoch", Request: plan.Request, RequestDigest: d, PreviousProofDigest: proof.PreviousProofDigest}
		operation.Prepared.Payload, _ = json.Marshal(prepared)
		if err := placementrelocation.ValidateOperation(operation); err != nil {
			t.Fatal(err)
		}
		operation.Ready = true
		if placementrelocation.ValidateOperation(operation) == nil {
			t.Fatal("readiness without target acceptances passed")
		}
		for _, target := range plan.Targets {
			stage := new(pb.PlacementStageRequest)
			if err := proto.Unmarshal(target.Proposal, stage); err != nil {
				t.Fatal(err)
			}
			receipt := &pb.PlacementAcceptanceResponse{ProposalRevision: stage.ExpectedRevision + 1, Epoch: plan.Request.Epoch, Generation: plan.Request.Generation, ProofDigest: placementrelocation.BytesDigest(operation.Accepted.Payload), Status: pb.PlacementAcceptanceStatus_PLACEMENT_ACCEPTANCE_STATUS_ADMITTED_CATCHING_UP}
			operation.Acceptances[target.ServerIdentity], _ = proto.Marshal(receipt)
		}
		if err := placementrelocation.ValidateOperation(operation); err != nil {
			t.Fatal(err)
		}
		operation.Acceptances[plan.RemovedIdentity] = operation.Acceptances[plan.Targets[0].ServerIdentity]
		if placementrelocation.ValidateOperation(operation) == nil {
			t.Fatal("receipt for removed target passed")
		}
	})
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
