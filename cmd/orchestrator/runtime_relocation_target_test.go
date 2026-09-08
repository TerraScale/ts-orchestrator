package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/placementpublisher"
	"terrascale.tech/orchestrator/src/orchestrator/placementrelocation"
	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
	"testing"

	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/enrollment"
	"terrascale.tech/orchestrator/src/orchestrator/ocireconcile"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
)

func relocationEnrolledFixture(t *testing.T) (enrollment.Record, ed25519.PublicKey) {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]string{"receipt": base64.StdEncoding.EncodeToString(public)}
	for _, role := range []string{"placement", "database"} {
		pair, err := nkeys.CreateUser()
		if err != nil {
			t.Fatal(err)
		}
		keys[role], err = pair.PublicKey()
		pair.Wipe()
		if err != nil {
			t.Fatal(err)
		}
	}
	return enrollment.Record{NodeID: "gru-3", MemberID: "01ARZ3NDEKTSV4RRFFQ69G5FAB", Environment: "production", Cluster: "01ARZ3NDEKTSV4RRFFQ69G5FAK", Region: "gru", Slot: 3, Generation: 7, Public: &enrollment.PublicBootstrap{PublicKeys: keys}}, public
}

func TestRelocationTargetAdmitsNewSurvivorOnlyFromExactDurableIdentity(t *testing.T) {
	for _, scenario := range []string{"new survivor", "retired member", "wrong generation", "wrong provider incarnation", "foreign Region", "stopped exact resource", "duplicate slot", "missing principal", "invalid receipt key", "lost authority"} {
		t.Run(scenario, func(t *testing.T) {
			record, public := relocationEnrolledFixture(t)
			identity := enrollment.Identity(record, "member")
			state := enrollment.State{Records: map[string]enrollment.Record{"gru:3": record}}
			listed := ocireconcile.ObservedMember{ID: "oci-original", ETag: "etag", CompartmentID: "compartment", Region: "gru", Index: 3, LifecycleState: "RUNNING"}
			gateway := &autoscaleIdentityGateway{listed: []ocireconcile.ObservedMember{listed}, current: listed}
			gateway.current.Region, gateway.current.Index = "", 0
			ownership := &runtimeRemovalOwnership{record: provider.ProviderOwnershipRecord{ResourceId: provider.ProviderResourceId{Value: listed.ID}, CompartmentId: provider.ProviderCompartmentId{Value: listed.CompartmentID}, CellId: provider.ProviderCellId{Value: "gru"}, Generation: provider.ProviderGeneration{Value: 7}, MemberID: record.MemberID, ServerIdentity: identity}}
			checks := 0
			factory := &productionRelocationTargets{enrolled: func(context.Context) (enrollment.State, error) { return state, nil }, gateways: map[string]ocireconcile.ComputeGateway{"gru": gateway}, ownership: ownership, environment: record.Environment, cluster: record.Cluster, check: func(context.Context) error {
				checks++
				if scenario == "lost authority" && checks > 2 {
					return errors.New("lease lost")
				}
				return nil
			}}
			switch scenario {
			case "retired member":
				record.Retirement = &enrollment.Retirement{OperationID: "remove", ResourceID: listed.ID}
				state.Records["gru:3"] = record
			case "wrong generation":
				ownership.record.Generation.Value++
			case "wrong provider incarnation":
				gateway.current.ID = "oci-replacement"
			case "foreign Region":
				ownership.record.CellId.Value = "fra"
			case "stopped exact resource":
				gateway.current.LifecycleState = "STOPPED"
			case "duplicate slot":
				gateway.listed = append(gateway.listed, listed)
			case "missing principal":
				delete(record.Public.PublicKeys, "database")
			case "invalid receipt key":
				record.Public.PublicKeys["receipt"] = "unknown"
			}
			target, err := factory.admit(t.Context(), identity)
			if scenario != "new survivor" {
				if err == nil || target != nil {
					t.Fatalf("unsafe target admitted: %+v %v", target, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if target.Observed.ResourceID != listed.ID || target.Observed.Slot != 3 || target.Member.MemberID != record.MemberID || target.ReadinessKey.KeyID != identity || !target.ReadinessKey.PublicKey.Equal(public) {
				t.Fatalf("admitted target mismatch: %+v", target)
			}
		})
	}
}

func TestRelocationHistoricalReceiptKeySurvivesProviderRemoval(t *testing.T) {
	record, public := relocationEnrolledFixture(t)
	identity := enrollment.Identity(record, "member")
	record.Retirement = &enrollment.Retirement{OperationID: "remove-original", ResourceID: "oci-original"}
	state := enrollment.State{Retired: map[string]enrollment.Record{"remove-original": record}}
	factory := &productionRelocationTargets{enrolled: func(context.Context) (enrollment.State, error) { return state, nil }, environment: record.Environment, cluster: record.Cluster, check: func(context.Context) error { return nil }}
	key, err := factory.MemberKey(t.Context(), identity)
	if err != nil || !key.Equal(public) {
		t.Fatalf("durable key lost after provider removal: %v", err)
	}
	if _, err := factory.MemberKey(t.Context(), identity+"foreign"); err == nil {
		t.Fatal("receipt-supplied foreign identity trusted")
	}
	state.Records = map[string]enrollment.Record{"gru:3": record}
	if _, err := factory.MemberKey(t.Context(), identity); err == nil {
		t.Fatal("ambiguous enrollment key trusted")
	}
}

type relocationJoinIssuer struct {
	requests []placementtransition.JoinRequest
}

func (*relocationJoinIssuer) Prepare(context.Context, placementtransition.Request) (placementtransition.Signed, error) {
	return placementtransition.Signed{}, errors.New("unexpected prepare")
}
func (i *relocationJoinIssuer) IssueJoinCheckpoint(_ context.Context, request placementtransition.JoinRequest) (placementtransition.Signed, error) {
	i.requests = append(i.requests, request)
	return placementtransition.Signed{KeyID: "authority", Payload: []byte("checkpoint"), Signature: make([]byte, 64)}, nil
}

type relocationJoinJournal struct{ record placementpublisher.Record }

func (*relocationJoinJournal) Accept(context.Context, placementpublisher.Record) error {
	return errors.New("unexpected accept")
}
func (j *relocationJoinJournal) Load(context.Context, string) (placementpublisher.Record, error) {
	return j.record, nil
}
func (*relocationJoinJournal) Acknowledge(context.Context, placementpublisher.Record, *pb.PlacementProposalResponse) error {
	return errors.New("unexpected acknowledge")
}

func TestRelocationJoinUsesExactPersistedStageChallenge(t *testing.T) {
	for _, scenario := range []string{"replacement", "existing member", "existing revision", "wrong operation", "wrong identity", "wrong request", "missing receipt", "wrong receipt revision", "missing challenge", "malformed challenge"} {
		t.Run(scenario, func(t *testing.T) {
			record, _ := relocationEnrolledFixture(t)
			identity := enrollment.Identity(record, "member")
			stage := &pb.PlacementStageRequest{Proposal: &pb.PlacementProposal{Environment: record.Environment, Cluster: record.Cluster, Epoch: 2, Generation: 2, Regions: []*pb.PlacementRegionSeats{{Region: "GRU", Members: []string{"01ARZ3NDEKTSV4RRFFQ69G5FAA", record.MemberID}}}}}
			if scenario == "existing revision" {
				stage.ExpectedRevision = 4
			}
			request, err := (proto.MarshalOptions{Deterministic: true}).Marshal(stage)
			if err != nil {
				t.Fatal(err)
			}
			challenge := placementtransition.Signed{KeyID: identity, Payload: []byte("signed-nonce"), Signature: make([]byte, 64)}
			challengeBytes, err := json.Marshal(challenge)
			if err != nil {
				t.Fatal(err)
			}
			receipt := &pb.PlacementProposalResponse{Revision: stage.ExpectedRevision + 1, Status: pb.PlacementProposalStatus_PLACEMENT_PROPOSAL_STATUS_PENDING, Proposal: stage.Proposal, JoinChallenge: challengeBytes}
			plan := placementrelocation.Plan{OperationID: "relocate", ReplacementIdentity: identity, PriorProof: placementtransition.Signed{KeyID: "authority", Payload: []byte("prior")}}
			journal := &relocationJoinJournal{record: placementpublisher.Record{OperationID: plan.OperationID, ServerIdentity: identity, Request: request}}
			switch scenario {
			case "existing member":
				plan.ReplacementIdentity = "another-member"
			case "wrong operation":
				journal.record.OperationID = "different"
			case "wrong identity":
				journal.record.ServerIdentity = "different"
			case "wrong request":
				journal.record.Request = []byte("different")
			case "wrong receipt revision":
				receipt.Revision++
			case "missing challenge":
				receipt.JoinChallenge = nil
			case "malformed challenge":
				receipt.JoinChallenge = []byte("malformed")
			}
			journal.record.Receipt, err = proto.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "missing receipt" {
				journal.record.Receipt = nil
			}
			issuer := &relocationJoinIssuer{}
			factory := &productionRelocationTargets{Pending: journal, issuer: issuer}
			proof := placementtransition.Signed{KeyID: "authority", Payload: []byte("accepted")}
			envelope, err := factory.acceptanceEnvelope(t.Context(), plan, identity, stage.ExpectedRevision+1, stage, proof)
			switch scenario {
			case "replacement":
				if err != nil || envelope.JoinCheckpoint == nil || len(issuer.requests) != 1 {
					t.Fatalf("fresh join not issued: %+v %v", envelope, err)
				}
				actual := issuer.requests[0]
				if actual.OperationID != plan.OperationID || actual.MemberIdentity != identity || !bytes.Equal(actual.Challenge.Payload, challenge.Payload) || !bytes.Equal(actual.Prior.Payload, plan.PriorProof.Payload) || !bytes.Equal(actual.Successor.Payload, proof.Payload) {
					t.Fatalf("retained binding lost: %+v", actual)
				}
			case "existing member", "existing revision":
				if err != nil || envelope.JoinCheckpoint != nil || len(issuer.requests) != 0 {
					t.Fatalf("existing member received join: %+v %v", envelope, err)
				}
			default:
				if err == nil || len(issuer.requests) != 0 {
					t.Fatalf("invalid retained receipt signed: %v", err)
				}
			}
		})
	}
}
