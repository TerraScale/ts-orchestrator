package databaseadmission

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

func emptySuccessorFixture(t *testing.T) (journalState, placementtransition.Signed, []PlacementTarget, ed25519.PublicKey) {
	t.Helper()
	record := journalFixture(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	stage := new(pb.PlacementStageRequest)
	if err := proto.Unmarshal(record.PlacementTargets[0].Proposal, stage); err != nil {
		t.Fatal(err)
	}
	stage.Proposal.Assignments = nil
	stage.Declarations = nil
	scope := stage.Proposal.Environment + "/" + stage.Proposal.Cluster
	payload, _ := (proto.MarshalOptions{Deterministic: true}).Marshal(stage.Proposal)
	hash := sha256.Sum256(payload)
	priorRequest := placementtransition.Request{OperationID: "empty-prior", ScopeID: scope, Epoch: 1, Generation: 1}
	for _, target := range record.PlacementTargets {
		priorRequest.Members = append(priorRequest.Members, placementtransition.Member{Identity: target.ServerIdentity, Region: target.Region, PlacementDigest: hex.EncodeToString(hash[:])})
	}
	digest, _ := placementtransition.RequestDigest(priorRequest)
	prior, err := placementtransition.SignEvidence("issuer", private, placementtransition.Proof{SchemaVersion: 1, Kind: "accepted_epoch", Request: priorRequest, RequestDigest: digest})
	if err != nil {
		t.Fatal(err)
	}
	binding := UnusedHostRemoval{OperationID: "empty-removal/placement", ScopeID: scope, MemberIdentity: record.PlacementTargets[0].ServerIdentity, ResourceID: "instance-old", Generation: 3, InventoryDigest: PlacementInventoryDigest(nil), Head: prior}
	replacement := "01ARZ3NDEKTSV4RRFFQ69G5FAU"
	stage.Proposal.Regions[0].Members[0] = replacement
	slices.Sort(stage.Proposal.Regions[0].Members)
	stage.Proposal.Epoch = 2
	stage.Proposal.Generation = 2
	stage.ExpectedRevision = 1
	payload, _ = (proto.MarshalOptions{Deterministic: true}).Marshal(stage.Proposal)
	hash = sha256.Sum256(payload)
	successor := placementtransition.Request{OperationID: binding.OperationID, ScopeID: scope, PriorEpoch: 1, Epoch: 2, Generation: 2}
	var targets []PlacementTarget
	encoded, _ := proto.Marshal(stage)
	for _, member := range stage.Proposal.Regions[0].Members {
		identity := "spiffe://terrascale.tech/" + stage.Proposal.Environment + "/terrabase-member/" + stage.Proposal.Cluster + "/" + member
		successor.Members = append(successor.Members, placementtransition.Member{Identity: identity, Region: "GRU", PlacementDigest: hex.EncodeToString(hash[:])})
		targets = append(targets, PlacementTarget{ServerIdentity: identity, MemberID: member, Region: "GRU", Proposal: encoded})
	}
	digest, _ = placementtransition.RequestDigest(successor)
	priorHash := sha256.Sum256(prior.Payload)
	accepted, err := placementtransition.SignEvidence("issuer", private, placementtransition.Proof{SchemaVersion: 1, Kind: "accepted_epoch", Request: successor, RequestDigest: digest, PriorGeneration: 1, PreviousProofDigest: hex.EncodeToString(priorHash[:])})
	if err != nil {
		t.Fatal(err)
	}
	acceptedBytes, _ := json.Marshal(accepted)
	acceptedHash := sha256.Sum256(accepted.Payload)
	acceptedDigest := hex.EncodeToString(acceptedHash[:])
	for i := range targets {
		target := &targets[i]
		target.AcceptedProof = acceptedBytes
		target.AcceptedRevision = 2
		target.AcceptedEpoch = 2
		target.AcceptedGeneration = 2
		target.AcceptedProofDigest = acceptedDigest
		target.AcceptedReceipt, _ = proto.Marshal(&pb.PlacementAcceptanceResponse{ProposalRevision: 2, Epoch: 2, Generation: 2, ProofDigest: acceptedDigest, Status: pb.PlacementAcceptanceStatus_PLACEMENT_ACCEPTANCE_STATUS_ADMITTED_CATCHING_UP})
	}
	state := newJournalState()
	state.PlacementRelocation = binding.OperationID
	state.PlacementRelocationStarted = true
	state.EmptyPlacementRelocations = map[string]EmptyPlacementRelocation{binding.OperationID: {Binding: binding}}
	return state, accepted, targets, public
}
func TestEmptyPlacementRelocationRequiresGenuineAcceptedSuccessor(t *testing.T) {
	state, accepted, targets, key := emptySuccessorFixture(t)
	operation := "empty-removal/placement"
	if err := commitEmptyPlacementRelocation(&state, operation, accepted, targets, key); err != nil {
		t.Fatal(err)
	}
	if len(state.Records) != 0 || len(state.CurrentPlacements) != 0 || state.PlacementRelocation != operation || len(state.EmptyPlacementRelocations[operation].Targets) != 2 {
		t.Fatal("empty transition invented data or released termination fence")
	}
	if err := commitEmptyPlacementRelocation(&state, operation, accepted, targets, key); err != nil {
		t.Fatal("commit retry", err)
	}
	for _, kind := range []string{"missing_accept", "signature", "active_database", "unstarted"} {
		t.Run(kind, func(t *testing.T) {
			state, accepted, targets, key := emptySuccessorFixture(t)
			switch kind {
			case "missing_accept":
				targets[0].AcceptedReceipt = nil
			case "signature":
				accepted.Signature[0] ^= 1
			case "active_database":
				record := journalFixture(t)
				state.Records[ScopeKey(record.Request)] = record
			case "unstarted":
				state.PlacementRelocationStarted = false
			}
			if err := commitEmptyPlacementRelocation(&state, operation, accepted, targets, key); err == nil {
				t.Fatal("unsafe empty successor accepted")
			}
			if len(state.CompletedRelocations) != 0 {
				t.Fatal("rejected successor committed")
			}
		})
	}
}
