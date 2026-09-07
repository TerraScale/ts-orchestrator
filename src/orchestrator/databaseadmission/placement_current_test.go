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
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/databaselifecycle"
	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

func successorFixture(t *testing.T) (journalState, Record, Record, ed25519.PublicKey) {
	t.Helper()
	old := journalFixture(t)
	old.State = "ready"
	old.PlacementTargets = slices.Clone(old.PlacementTargets)
	for i := range old.PlacementTargets {
		stage := new(pb.PlacementStageRequest)
		if err := proto.Unmarshal(old.PlacementTargets[i].Proposal, stage); err != nil {
			t.Fatal(err)
		}
		stage.Declarations = []*pb.PlacementDatabaseDeclaration{{Tenant: old.Request.TenantID, Project: old.Request.ProjectID, Database: old.DatabaseID, SelectedRegions: []string{"GRU"}}}
		encoded, err := proto.Marshal(stage)
		if err != nil {
			t.Fatal(err)
		}
		old.PlacementTargets[i].Proposal = encoded
		old.Targets[i].Proposal = encoded
	}

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
	state.PlacementRelocationStarted = true
	if err := commitPlacementRelocation(&state, "relocate-one", []Record{current}, key); err != nil {
		t.Fatal(err)
	}
	if state.PlacementRelocation != "relocate-one" {
		t.Fatal("commit released destructive-effect fence")
	}
	if !reflect.DeepEqual(state.Records[ScopeKey(old.Request)], old) || !reflect.DeepEqual(currentPlacementRecords(state), []Record{current}) {
		t.Fatal("history overwritten or successor missing")
	}
	state.PlacementRelocationStarted = true
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
			state.PlacementRelocationStarted = true
			if err := commitPlacementRelocation(&state, "relocate-one", []Record{current}, key); err == nil {
				t.Fatal("invalid successor accepted")
			}
			if state.PlacementRelocation != "relocate-one" || len(state.CurrentPlacements) != 0 {
				t.Fatal("failed commit released fence")
			}
		})
	}
}

func TestPlacementRelocationInactiveScopeRequiresCompletedEffects(t *testing.T) {
	state, old, _, _ := successorFixture(t)
	retired := old
	retired.Request.Name = "retired"
	retired.Request.OperationID = "create-retired"
	retired.DatabaseID = "01ARZ3NDEKTSV4RRFFQ69G5FB2"
	state.Records[ScopeKey(retired.Request)] = retired
	at := time.Now().UTC()
	resource := databaselifecycle.Resource{Identity: databaselifecycle.Identity{Environment: retired.Request.Environment, OrganizationID: retired.Request.TenantID, ProjectID: retired.Request.ProjectID, DatabaseID: retired.DatabaseID}, DeletedAt: at, UsageStoppedAt: at, AccessRevoked: true}
	key := databaselifecycle.Key(resource.Identity)
	state.Lifecycle.Resources[key] = resource
	state.Deletions["retired"] = Deletion{Targets: []DeletionTarget{{Stop: DeletionStop{Identity: resource.Identity}}}}
	if err := beginPlacementRelocation(&state, "relocate-one", []Record{old}); !errors.Is(err, ErrConflict) {
		t.Fatal("cleanup-active record omitted", err)
	}
	resource.EffectsCompletedAt = at.Add(time.Second)
	state.Lifecycle.Resources[key] = resource
	if err := beginPlacementRelocation(&state, "relocate-one", []Record{old}); err != nil {
		t.Fatal("completed inactive history blocked relocation", err)
	}
	if len(state.Records) != 2 || len(currentPlacementRecords(state)) != 2 {
		t.Fatal("retired admission history deleted")
	}
}

func TestRelocationReadinessBindsSuccessorOperation(t *testing.T) {
	_, _, record, _ := successorFixture(t)
	nonce := strings.Repeat("e", 64)
	receipts, keys, private := readinessFixture(t, record, nonce)
	if err := ValidateRelocationReadiness(record, "relocate-one", receipts, nonce, keys, time.Now()); err == nil {
		t.Fatal("original admission operation authorized relocation")
	}
	for i := range receipts {
		var proof Readiness
		if err := json.Unmarshal(receipts[i].Payload, &proof); err != nil {
			t.Fatal(err)
		}
		proof.OperationID = "relocate-one"
		receipts[i].Payload, _ = json.Marshal(proof)
		receipts[i].Signature = ed25519.Sign(private[proof.MemberIdentity], append([]byte("terrabase-database-readiness-v1\x00"), receipts[i].Payload...))
	}
	if err := ValidateRelocationReadiness(record, "relocate-one", receipts, nonce, keys, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRelocationReadiness(record, "relocate-one", receipts, nonce, nil, time.Now()); err == nil {
		t.Fatal("unpinned readiness accepted")
	}
}

func TestPlacementRelocationStreamAllocationFailureAndRetryRetainsFence(t *testing.T) {
	state, old, current, key := successorFixture(t)
	if err := databaselifecycle.Apply(&state.Lifecycle, admissionLifecycleEvent(old)); err != nil {
		t.Fatal(err)
	}
	if err := beginPlacementRelocation(&state, "relocate-one", []Record{old}); err != nil {
		t.Fatal(err)
	}
	state.PlacementRelocationStarted = true
	before := state.Lifecycle.Revision
	if err := allocateRelocationStreams(&state, "relocate-one", []Record{current}, key, time.Time{}); err == nil {
		t.Fatal("invalid stream timestamp accepted")
	}
	if state.Lifecycle.Revision != before || len(state.CurrentPlacements) != 0 || state.PlacementRelocation != "relocate-one" {
		t.Fatal("failed stream allocation changed authority")
	}
	now := time.Now().UTC()
	if err := allocateRelocationStreams(&state, "relocate-one", []Record{current}, key, now); err != nil {
		t.Fatal(err)
	}
	allocated := state.Lifecycle.Revision
	if allocated <= before {
		t.Fatal("streams not allocated")
	}
	if err := allocateRelocationStreams(&state, "relocate-one", []Record{current}, key, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if state.Lifecycle.Revision != allocated || len(state.CurrentPlacements) != 0 || len(state.CompletedRelocations) != 0 || state.PlacementRelocation != "relocate-one" {
		t.Fatal("allocation retry committed placement or released usage fence")
	}
}
