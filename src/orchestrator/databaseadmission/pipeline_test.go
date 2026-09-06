package databaseadmission

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/keylease"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

func pipelineConfig(t *testing.T, journal Journal) Config {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(home, ".admission-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	fixture := journalFixture(t)
	return Config{Journal: journal, CatalogPath: filepath.Join(dir, "keys.json"), Authorize: func(context.Context, Request) error { return nil }, CheckAuthority: func(context.Context) error { return nil }, Plan: func(_ context.Context, r Record) (Plan, error) {
		targets := make([]Target, len(fixture.Targets))
		for i, target := range fixture.Targets {
			target.Provision.Binding.DatabaseID = r.DatabaseID
			target.Provision.Binding.KeyVersion = r.KeyVersion
			target.Provision.Binding.TenantID = r.Request.TenantID
			target.Provision.Binding.ProjectID = r.Request.ProjectID
			stage := new(pb.PlacementStageRequest)
			if err := proto.Unmarshal(target.Proposal, stage); err != nil {
				return Plan{}, err
			}
			for _, a := range stage.Proposal.Assignments {
				a.Database = r.DatabaseID
				a.Tenant = r.Request.TenantID
				a.Project = r.Request.ProjectID
			}
			target.Proposal, err = proto.Marshal(stage)
			if err != nil {
				return Plan{}, err
			}
			targets[i] = target
		}
		placements := []PlacementTarget{}
		for _, target := range targets {
			placements = append(placements, PlacementTarget{ServerIdentity: target.ServerIdentity, MemberID: target.MemberID, Region: target.Region, Proposal: target.Proposal})
		}
		return Plan{Members: targets, Placements: placements}, nil
	}, Install: func(context.Context, Record, Target, []keylease.Entry) error { return nil }, AcceptPlacement: func(_ context.Context, _ string, _ string, request *pb.PlacementStageRequest) (*pb.PlacementProposalResponse, error) {
		return &pb.PlacementProposalResponse{Revision: 1, Proposal: request.Proposal, Status: pb.PlacementProposalStatus_PLACEMENT_PROPOSAL_STATUS_PENDING}, nil
	}, ActivatePlacement: func(context.Context, Record) error { return nil }}
}
func TestCreateAdmissionPreservesIdentityAndResumesUnknownEffects(t *testing.T) {
	journal := NewMemoryJournal()
	config := pipelineConfig(t, journal)
	request := journalFixture(t).Request
	pipeline, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := pipeline.Accept(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := pipeline.Accept(t.Context(), request)
	if err != nil || retry.DatabaseID != accepted.DatabaseID || retry.KeyVersion != accepted.KeyVersion {
		t.Fatal("retry changed identity", err)
	}
	changed := request
	changed.Residency = "br-only"
	if _, err = pipeline.Accept(t.Context(), changed); !errors.Is(err, ErrConflict) {
		t.Fatal("immutable residency changed", err)
	}
	// Simulate OCI's complete durable result, so reconciliation exercises its real
	// idempotent provisioning path without a provider credential or raw key.
	if err = keylease.WriteCatalog(config.CatalogPath, keylease.Catalog{Version: 1, Entries: journalWrapped(accepted)}); err != nil {
		t.Fatal(err)
	}
	installCalls := map[string]int{}
	lost := true
	config.Install = func(_ context.Context, r Record, target Target, entries []keylease.Entry) error {
		durable, ok, err := journal.Load(t.Context(), ScopeKey(request))
		if err != nil || !ok || len(durable.Wrapped) != 3 {
			t.Fatal("key delivered before durable ciphertext", err)
		}
		installCalls[target.MemberID]++
		if lost {
			lost = false
			return errors.New("response lost after durable host admission")
		}
		return nil
	}
	proposalCalls := map[string]int{}
	loseProposal := true
	config.AcceptPlacement = func(_ context.Context, host, operation string, request *pb.PlacementStageRequest) (*pb.PlacementProposalResponse, error) {
		durable, _, _ := journal.Load(t.Context(), ScopeKey(accepted.Request))
		for _, target := range durable.Targets {
			if !target.Installed {
				t.Fatal("proposal preceded member key admission")
			}
		}
		if operation != PlacementOperationID(accepted.Request) {
			t.Fatal("proposal retry ID changed")
		}
		proposalCalls[host]++
		if loseProposal {
			loseProposal = false
			return nil, errors.New("placement response lost")
		}
		return &pb.PlacementProposalResponse{Revision: 1, Proposal: request.Proposal, Status: pb.PlacementProposalStatus_PLACEMENT_PROPOSAL_STATUS_PENDING}, nil
	}
	pipeline, _ = New(config)
	if err = pipeline.Reconcile(t.Context()); err == nil {
		t.Fatal("lost host response resolved prematurely")
	}
	// Process restart retains accepted identity and repeats the unresolved exact
	// host operation; already durable progress cannot be skipped accidentally.
	pipeline, _ = New(config)
	if err = pipeline.Reconcile(t.Context()); err == nil {
		t.Fatal("lost proposal response resolved prematurely")
	}
	pipeline, _ = New(config)
	if err = pipeline.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	final, err := pipeline.Status(t.Context(), request)
	if err != nil || final.State != "placement_pending" {
		t.Fatal(final.State, err)
	}
	if installCalls[accepted.Targets[0].MemberID] != 3 || proposalCalls[accepted.Targets[0].ServerIdentity] != 2 {
		t.Fatal("unknown effects not retried with original identity")
	}
	if result(final).State != "pending" {
		t.Fatal("pending membership advertised ready")
	}
	if err = pipeline.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if installCalls[accepted.Targets[0].MemberID] != 4 {
		t.Fatal("pending operation did not recheck activated host publication")
	}
}
func TestAdmissionDeniedBeforeDurableIdentity(t *testing.T) {
	journal := NewMemoryJournal()
	config := pipelineConfig(t, journal)
	config.Authorize = func(context.Context, Request) error { return errors.New("card not verified") }
	pipeline, _ := New(config)
	request := journalFixture(t).Request
	if _, err := pipeline.Accept(t.Context(), request); err == nil {
		t.Fatal("unauthorized creation admitted")
	}
	if records, _ := journal.List(t.Context()); len(records) != 0 {
		t.Fatal("unauthorized intent persisted")
	}
	request.Residency = "eu-only"
	if err := ValidateRequest(request); err == nil {
		t.Fatal("residency widened")
	}
}
