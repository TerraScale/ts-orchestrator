package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/placementpublisher"
	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

func transitionFixture(t *testing.T) (databaseadmission.Record, databasePlacementJournal) {
	t.Helper()
	config, record := databasePlanFixture()
	targets, err := config.plan(t.Context(), record, &databasePlanJournal{}, databasePlacementJournal{})
	if err != nil {
		t.Fatal(err)
	}
	record.Targets = targets.Members
	record.PlacementTargets = targets.Placements
	record.State = "placement_pending"
	pending := databasePlacementJournal{}
	for n := range record.Targets {
		record.Targets[n].Installed = true
	}
	for n := range record.PlacementTargets {
		target := &record.PlacementTargets[n]
		target.Proposed = true
		stage := new(pb.PlacementStageRequest)
		_ = proto.Unmarshal(target.Proposal, stage)
		receipt := &pb.PlacementProposalResponse{Revision: 1, Proposal: stage.Proposal, Status: pb.PlacementProposalStatus_PLACEMENT_PROPOSAL_STATUS_PENDING}
		data, err := proto.Marshal(receipt)
		if err != nil {
			t.Fatal(err)
		}
		pending[target.ServerIdentity] = placementpublisher.Record{OperationID: databaseadmission.PlacementOperationID(record.Request), Request: target.Proposal, Receipt: data}
	}
	return record, pending
}

type runtimeTestIssuer struct {
	proof  placementtransition.Signed
	issued int
}

func (i *runtimeTestIssuer) Load(context.Context, string) (placementtransition.Signed, error) {
	if len(i.proof.Payload) == 0 {
		return placementtransition.Signed{}, placementtransition.ErrMissing
	}
	return i.proof, nil
}
func (i *runtimeTestIssuer) Head(context.Context, string) (placementtransition.Signed, error) {
	return placementtransition.Signed{}, placementtransition.ErrMissing
}
func (i *runtimeTestIssuer) Issue(_ context.Context, r placementtransition.Request, g *placementtransition.Signed, _ []placementtransition.Signed) (placementtransition.Signed, error) {
	if g == nil {
		return placementtransition.Signed{}, errors.New("missing grant")
	}
	i.issued++
	d, _ := placementtransition.RequestDigest(r)
	b, _ := json.Marshal(placementtransition.Proof{Request: r, RequestDigest: d})
	i.proof = placementtransition.Signed{Payload: b}
	return i.proof, nil
}
func TestTransitionUsageFailureBlocksCompletionAndRetriesSameProof(t *testing.T) {
	record, pending := transitionFixture(t)
	issuer := &runtimeTestIssuer{}
	accepted, registered, completed := 0, 0, 0
	var firstDigest string
	worker := &productionPlacementTransition{
		issuer: issuer, pending: pending, check: func(context.Context) error { return nil },
		config: productionPlacementTransitionConfig{
			GenesisGrants: map[string]placementtransition.Signed{databaseadmission.PlacementOperationID(record.Request): {Payload: []byte("explicit")}},
			Deliver: func(context.Context, string, string, uint64, placementtransition.Signed) error {
				accepted++
				return nil
			},
		},
		registerUsage: func(_ context.Context, got databaseadmission.Record, digest string) error {
			registered++
			if accepted != registered*len(record.PlacementTargets) || got.DatabaseID != record.DatabaseID || len(digest) != 64 {
				t.Fatal("usage delivered before all accepted placements or with wrong identity")
			}
			if registered == 1 {
				firstDigest = digest
				return errors.New("usage unresolved")
			}
			if digest != firstDigest {
				t.Fatal("retry changed usage proof")
			}
			return nil
		},
		completion: func(_ context.Context, _, digest string, write bool) error {
			if registered != 2 || digest != firstDigest || !write {
				t.Fatal("premature completion")
			}
			completed++
			return nil
		},
	}
	if err := worker.Activate(t.Context(), record); err == nil || completed != 0 {
		t.Fatal("usage failure completed activation", err)
	}
	if err := worker.Activate(t.Context(), record); err != nil || completed != 1 || issuer.issued != 1 {
		t.Fatal("retry failed", err)
	}
	worker.registerUsage = nil
	if err := worker.Activate(t.Context(), record); err == nil {
		t.Fatal("missing usage authority accepted")
	}
}

func TestTransitionWorkerExplicitGenesisAndDeliveryRetry(t *testing.T) {
	record, pending := transitionFixture(t)
	issuer := &runtimeTestIssuer{}
	delivered := 0
	worker := &productionPlacementTransition{registerUsage: func(context.Context, databaseadmission.Record, string) error { return nil }, issuer: issuer, pending: pending, check: func(context.Context) error { return nil }, config: productionPlacementTransitionConfig{GenesisGrants: map[string]placementtransition.Signed{}, Deliver: func(_ context.Context, _, _ string, revision uint64, _ placementtransition.Signed) error {
		if revision != 1 {
			t.Fatal("wrong Stage revision")
		}
		delivered++
		if delivered == 1 {
			return errors.New("unknown delivery")
		}
		return nil
	}}}
	if err := worker.Activate(t.Context(), record); err == nil || issuer.issued != 0 {
		t.Fatal("implicit genesis issued")
	}
	worker.config.GenesisGrants[databaseadmission.PlacementOperationID(record.Request)] = placementtransition.Signed{Payload: []byte("explicit")}
	if err := worker.Activate(t.Context(), record); err == nil || issuer.issued != 1 {
		t.Fatal("unknown delivery lost", err)
	}
	if err := worker.Activate(t.Context(), record); err != nil || issuer.issued != 1 || delivered != 3 {
		t.Fatal("retry changed issued proof", err)
	}
	for host, entry := range pending {
		entry.Receipt = nil
		pending[host] = entry
		break
	}
	if err := worker.Activate(t.Context(), record); err == nil {
		t.Fatal("missing Stage receipt admitted")
	}
}
func TestTransitionRequestRejectsIncompletePlan(t *testing.T) {
	record, _ := transitionFixture(t)
	if _, err := transitionRequest(record); err != nil {
		t.Fatal(err)
	}
	record.PlacementTargets = record.PlacementTargets[:1]
	if _, err := transitionRequest(record); err == nil {
		t.Fatal("partial membership plan accepted")
	}
}
func TestTransitionConfigRejectsPublicPrivateKeyAndUnsignedGrant(t *testing.T) {
	dir := t.TempDir()
	seed := make([]byte, 32)
	key := ed25519.NewKeyFromSeed(seed)
	private := filepath.Join(dir, "key")
	public := filepath.Join(dir, "pub")
	if err := os.WriteFile(private, key, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(public, key.Public().(ed25519.PublicKey), 0644); err != nil {
		t.Fatal(err)
	}
	f := productionPlacementTransitionFile{ProofKeyID: "gru", ProofKeyFile: private, GenesisKeyFiles: map[string]string{"genesis": public}, MemberKeyFiles: map[string]string{"member": public}}
	if _, err := f.load(); err == nil {
		t.Fatal("public private key accepted")
	}
	if err := os.Chmod(private, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.load(); err != nil {
		t.Fatal(err)
	}
	f.GenesisGrants = map[string]placementtransition.Signed{"op": {KeyID: "genesis", Payload: []byte("{}")}}
	if _, err := f.load(); err == nil {
		t.Fatal("unsigned genesis accepted")
	}
}
