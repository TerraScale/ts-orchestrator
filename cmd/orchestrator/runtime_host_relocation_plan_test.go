package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/hostremoval"
	"terrascale.tech/orchestrator/src/orchestrator/placementpublisher"
	"terrascale.tech/orchestrator/src/orchestrator/placementrelocation"
	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

type relocationPlanPending map[string]placementpublisher.Record

func (p relocationPlanPending) Load(_ context.Context, id string) (placementpublisher.Record, error) {
	r, ok := p[id]
	if !ok {
		return r, placementpublisher.ErrIntentMissing
	}
	return r, nil
}
func (relocationPlanPending) Accept(context.Context, placementpublisher.Record) error {
	return errors.New("unexpected mutation")
}
func (relocationPlanPending) Acknowledge(context.Context, placementpublisher.Record, *pb.PlacementProposalResponse) error {
	return errors.New("unexpected mutation")
}

func TestRelocationPlannerUnknownStageCannotBecomeFreshRevision(t *testing.T) {
	record, _ := transitionFixture(t)
	request, err := transitionRequest(record)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := placementtransition.RequestDigest(request)
	payload, _ := json.Marshal(placementtransition.Proof{Kind: "accepted_epoch", Request: request, RequestDigest: digest})
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed := placementtransition.Signed{KeyID: "issuer", Payload: payload, Signature: ed25519.Sign(private, append([]byte("terrabase-placement-transition-v1\x00"), payload...))}
	removed := record.PlacementTargets[0]
	stage := newPlacementStageRequest(removed.Proposal)
	replacement := placementrelocation.Target{MemberID: "01ARZ3NDEKTSV4RRFFQ69G5FAZ", Region: removed.Region}
	replacement.ServerIdentity = "spiffe://terrascale.tech/" + stage.Proposal.Environment + "/terrabase-member/" + stage.Proposal.Cluster + "/" + replacement.MemberID
	observation := hostremoval.MemberObservation{Identity: replacement.ServerIdentity, ResourceID: "instance-new", Region: removed.Region, Slot: 3, Generation: 7}
	removal := hostremoval.RemovalRequest{OperationID: "remove-unknown", Member: hostremoval.MemberObservation{Identity: removed.ServerIdentity, Region: removed.Region}, Survivors: []hostremoval.MemberObservation{observation}}
	resolve := func(_ context.Context, id string) (placementrelocation.Target, hostremoval.MemberObservation, error) {
		if id == replacement.ServerIdentity {
			return replacement, observation, nil
		}
		for _, target := range record.PlacementTargets {
			if target.ServerIdentity == id {
				return placementrelocation.Target{ServerIdentity: id, MemberID: target.MemberID, Region: target.Region}, hostremoval.MemberObservation{}, nil
			}
		}
		return placementrelocation.Target{}, hostremoval.MemberObservation{}, placementrelocation.ErrMissing
	}
	// Even a fully enrolled replacement is not fresh after an authorized Stage
	// has an unknown response. Planning must preserve that uncertainty.
	pending := relocationPlanPending{replacement.ServerIdentity: {ServerIdentity: replacement.ServerIdentity, OperationID: "earlier-stage", Request: removed.Proposal}}
	planner := productionRelocationPlanner(func(context.Context, string) (placementtransition.Signed, error) { return signed, nil }, public, pending, resolve)
	if _, err := planner(t.Context(), removal, []databaseadmission.Record{record}); err == nil {
		t.Fatal("unknown Stage response was treated as revision zero")
	}
	t.Run("provider replacement after observation", func(t *testing.T) {
		changed := observation
		changed.Generation++
		planner := productionRelocationPlanner(func(context.Context, string) (placementtransition.Signed, error) { return signed, nil }, public, pending, func(context.Context, string) (placementrelocation.Target, hostremoval.MemberObservation, error) {
			return replacement, changed, nil
		})
		if _, err := planner(t.Context(), removal, []databaseadmission.Record{record}); !errors.Is(err, placementrelocation.ErrConflict) {
			t.Fatalf("changed provider incarnation: %v", err)
		}
	})
	t.Run("unsigned head", func(t *testing.T) {
		unsigned := signed
		unsigned.Signature = nil
		planner := productionRelocationPlanner(func(context.Context, string) (placementtransition.Signed, error) { return unsigned, nil }, public, pending, resolve)
		if _, err := planner(t.Context(), removal, []databaseadmission.Record{record}); !errors.Is(err, placementrelocation.ErrInvalid) {
			t.Fatalf("unsigned authority head: %v", err)
		}
	})
}
