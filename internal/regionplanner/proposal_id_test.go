package regionplanner

import (
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionlifecycle"
)

// TestProposalIDsCarryTheProposalGeneration pins the step-key-reuse finding:
// two attempts on one cell never share a proposal ID, even with the same
// evidence in the same planning window, because the target proposal
// generation is part of the ID.
func TestProposalIDsCarryTheProposalGeneration(t *testing.T) {
	t.Parallel()
	planner := Planner{Policy: testPolicy()}
	signals := []Signal{signal(SignalUnplaceableIntent, "sfo", "intent-1", time.Hour)}
	fresh, err := planner.Plan(signals, []regionlifecycle.Record{activeGRU()}, now)
	if err != nil || len(fresh) != 1 || !strings.HasPrefix(fresh[0].ID, "sfo-g1-") {
		t.Fatalf("first attempt = %+v, %v", fresh, err)
	}
	rejected := activeGRU()
	rejected.Cell, rejected.Phase, rejected.Generation = "sfo", regionlifecycle.Rejected, 7
	rejected.Proposal.Cell, rejected.Proposal.ID = "sfo", fresh[0].ID
	rejected.UpdatedAt = now.Add(-48 * time.Hour)
	again, err := planner.Plan(signals, []regionlifecycle.Record{activeGRU(), rejected}, now)
	if err != nil || len(again) != 1 || !strings.HasPrefix(again[0].ID, "sfo-g8-") || again[0].ID == fresh[0].ID {
		t.Fatalf("re-proposal after generation 7 = %+v, %v", again, err)
	}
	if err := again[0].Validate(); err != nil {
		t.Fatal(err)
	}
	// A cell and generation too long for the visible form still yield a
	// valid ID that differs per generation.
	long := strings.Repeat("a", 31)
	entry := CatalogEntry{Cell: long, OCIRegion: "xx-test-1", EstimatedMonthlyCents: 1}
	found := &candidate{kinds: map[SignalKind]int{SignalLatency: 1}, evidence: map[string]struct{}{digest("x"): {}}}
	left := planner.proposal(entry, found, 1<<62, now)
	right := planner.proposal(entry, found, 1<<62+1, now)
	if len(left.ID) > maxProposalID || left.ID == right.ID || left.Validate() != nil {
		t.Fatalf("long IDs = %q, %q (%v)", left.ID, right.ID, left.Validate())
	}
}
