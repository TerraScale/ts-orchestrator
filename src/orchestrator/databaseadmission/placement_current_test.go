package databaseadmission

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

func successorFixture(t *testing.T) (journalState, Record, Record, ed25519.PublicKey) {
	t.Helper()
	old := journalFixture(t)
	old.State = "ready"
	old.PlacementTargets = slices.Clone(old.PlacementTargets)
	for i := range old.PlacementTargets {
		old.PlacementTargets[i].AcceptedEpoch = 1
		old.PlacementTargets[i].AcceptedGeneration = 1
		old.PlacementTargets[i].AcceptedProofDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	}
	data, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	var current Record
	if err := json.Unmarshal(data, &current); err != nil {
		t.Fatal(err)
	}
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proof := placementtransition.Proof{SchemaVersion: 1, Kind: "accepted_epoch", Request: placementtransition.Request{OperationID: "relocate-one", ScopeID: "production/01ARZ3NDEKTSV4RRFFQ69G5FAV", PriorEpoch: 1, Epoch: 2, Generation: 2}, PriorGeneration: 1, PreviousProofDigest: old.PlacementTargets[0].AcceptedProofDigest}
	for i := range current.PlacementTargets {
		stage := new(pb.PlacementStageRequest)
		if err := proto.Unmarshal(current.PlacementTargets[i].Proposal, stage); err != nil {
			t.Fatal(err)
		}
		stage.Proposal.Epoch, stage.Proposal.Generation = 2, 2
		proposal, _ := (proto.MarshalOptions{Deterministic: true}).Marshal(stage.Proposal)
		hash := sha256.Sum256(proposal)
		proof.Request.Members = append(proof.Request.Members, placementtransition.Member{Identity: current.PlacementTargets[i].ServerIdentity, Region: "GRU", PlacementDigest: hex.EncodeToString(hash[:])})
		encoded, _ := proto.Marshal(stage)
		current.PlacementTargets[i].Proposal = encoded
		current.Targets[i].Proposal = encoded
	}
	proof.RequestDigest, _ = placementtransition.RequestDigest(proof.Request)
	payload, _ := json.Marshal(proof)
	signed := placementtransition.Signed{KeyID: "gru", Payload: payload, Signature: ed25519.Sign(private, append([]byte("terrabase-placement-transition-v1\x00"), payload...))}
	encodedProof, _ := json.Marshal(signed)
	hash := sha256.Sum256(payload)
	digest := hex.EncodeToString(hash[:])
	for i := range current.PlacementTargets {
		target := &current.PlacementTargets[i]
		target.AcceptedEpoch = 2
		target.AcceptedGeneration = 2
		target.AcceptedRevision = 2
		target.AcceptedProofDigest = digest
		target.AcceptedProof = encodedProof
		target.AcceptedReceipt, _ = proto.Marshal(&pb.PlacementAcceptanceResponse{ProposalRevision: 2, Epoch: 2, Generation: 2, ProofDigest: digest, Status: pb.PlacementAcceptanceStatus_PLACEMENT_ACCEPTANCE_STATUS_ADMITTED_CATCHING_UP})
	}
	state := newJournalState()
	state.Records[ScopeKey(old.Request)] = old
	return state, old, current, pub
}
func TestPlacementRelocationFenceAndImmutableHistory(t *testing.T) {
	state, old, current, key := successorFixture(t)
	if err := beginPlacementRelocation(&state, "relocate-one", []Record{old}); err != nil {
		t.Fatal(err)
	}
	if _, err := saveRecord(&state, ScopeKey(old.Request), old.Revision, old); !errors.Is(err, ErrConflict) {
		t.Fatalf("admission crossed fence: %v", err)
	}
	request := DeleteRequest{Environment: old.Request.Environment, TenantID: old.Request.TenantID, ProjectID: old.Request.ProjectID, DatabaseID: old.DatabaseID, OperationID: "delete-one"}
	if _, err := beginDeletion(&state, request, time.Now(), time.Time{}); !errors.Is(err, ErrConflict) {
		t.Fatalf("deletion crossed fence: %v", err)
	}
	if err := commitPlacementRelocation(&state, "relocate-one", []Record{current}, key); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(state.Records[ScopeKey(old.Request)], old) || !reflect.DeepEqual(currentPlacementRecords(state), []Record{current}) {
		t.Fatal("history overwritten or successor missing")
	}
	if err := commitPlacementRelocation(&state, "relocate-one", []Record{current}, key); err != nil {
		t.Fatal("retry failed", err)
	}
}
func TestPlacementRelocationRejectsChangedAuthority(t *testing.T) {
	for _, name := range []string{"snapshot", "deleted", "foreign", "stale_generation", "signature"} {
		t.Run(name, func(t *testing.T) {
			state, old, current, key := successorFixture(t)
			if name == "snapshot" {
				expected := old
				expected.Revision++
				if err := beginPlacementRelocation(&state, "relocate-one", []Record{expected}); !errors.Is(err, ErrConflict) {
					t.Fatal("changed snapshot accepted")
				}
				return
			}
			if name == "deleted" {
				state.Deletions["delete"] = Deletion{}
				if err := beginPlacementRelocation(&state, "relocate-one", []Record{old}); !errors.Is(err, ErrConflict) {
					t.Fatal("deletion accepted")
				}
				return
			}
			if err := beginPlacementRelocation(&state, "relocate-one", []Record{old}); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "foreign":
				current.Request.TenantID = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
			case "stale_generation":
				current.PlacementTargets[0].AcceptedGeneration = 1
			case "signature":
				key = make(ed25519.PublicKey, ed25519.PublicKeySize)
			}
			if err := commitPlacementRelocation(&state, "relocate-one", []Record{current}, key); err == nil {
				t.Fatal("invalid successor accepted")
			}
			if state.PlacementRelocation != "relocate-one" || len(state.CurrentPlacements) != 0 {
				t.Fatal("failed commit released fence")
			}
		})
	}
}
