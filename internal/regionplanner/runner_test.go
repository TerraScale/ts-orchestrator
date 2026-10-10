package regionplanner

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/identity"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/budget"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/globalcontrol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/globalview"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/nodescale"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionlifecycle"
)

type fakeLister struct{ regions []identity.Region }

func (lister fakeLister) ListRegions(context.Context) (identity.ListRegionsResponse, error) {
	return identity.ListRegionsResponse{Items: lister.regions}, nil
}

func oci(name, key string) identity.Region {
	return identity.Region{Name: &name, Key: &key}
}

func summary(cell string, status *nodescale.Status) globalview.Region {
	return globalview.Region{Cell: cell, Rollup: &globalview.Rollup{Cell: cell, Scale: status}}
}

// seedRecord stores a lifecycle record for cell in phase; the store only
// takes a Proposed record at first, so later phases are written as the next
// generation.
func seedRecord(t *testing.T, ctx context.Context, store *regionlifecycle.Store, cell, ociRegion string,
	phase regionlifecycle.Phase,
) {
	t.Helper()
	proposal := regionlifecycle.Proposal{ID: entityid.Derive("test-proposal", cell), Cell: cell, OCIRegion: ociRegion,
		Reason: "seeded for a test", EvidenceDigests: []string{strings.Repeat("a", 64)},
		EstimatedMonthlyCents: 27_000, ProposedAt: testNow}
	record, err := regionlifecycle.Machine{}.Propose(proposal, testNow)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := store.Create(ctx, 1, record)
	if err != nil {
		t.Fatal(err)
	}
	if phase != regionlifecycle.Proposed {
		next := record
		next.Phase, next.Generation = phase, record.Generation+1
		if _, err := store.Update(ctx, 1, record, next, revision); err != nil {
			t.Fatal(err)
		}
	}
}

// newTestRunner is a home at gru with the given summaries, an OCI region list
// of gru, sfo, fra and lhr, and no capacity document.
func newTestRunner(t *testing.T, summaries []globalview.Region) (*Runner, *regionlifecycle.Store) {
	t.Helper()
	ctx := t.Context()
	js := newTestJetStream(t)
	lifecycle, err := regionlifecycle.OpenStore(ctx, js, 1, fencer{})
	if err != nil {
		t.Fatal(err)
	}
	state, err := OpenStore(ctx, js, 1, fencer{})
	if err != nil {
		t.Fatal(err)
	}
	runner := &Runner{Home: regionlifecycle.Home{Cell: "gru"},
		Rollups: func() []globalview.Region { return summaries },
		Roster: func(context.Context) (globalcontrol.Roster, error) {
			return globalcontrol.Roster{}, globalcontrol.ErrNotFound
		},
		Capacity: func(context.Context) (budget.Capacity, bool, error) { return budget.Capacity{}, false, nil },
		OCIRegions: fakeLister{regions: []identity.Region{oci("sa-saopaulo-1", "GRU"), oci("us-sanjose-1", "SJC"),
			oci("eu-frankfurt-1", "FRA"), oci("uk-london-1", "LHR")}},
		State: state, Lifecycle: lifecycle, Machine: regionlifecycle.Machine{}}
	return runner, lifecycle
}

func TestPlanRetiresAnIdleRegionAndSavesTheDecision(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	runner, lifecycle := newTestRunner(t, []globalview.Region{summary("gru", statusBusy()),
		summary("sfo", statusIdle()), summary("fra", statusBusy())})
	seedRecord(t, ctx, lifecycle, "sfo", "us-sanjose-1", regionlifecycle.Active)
	idleSince := testNow.Add(-regionlifecycle.MinIdle - time.Hour)
	if _, err := runner.State.Save(ctx, 1, State{Memory: Memory{IdleSince: map[string]time.Time{"sfo": idleSince}}}, 0); err != nil {
		t.Fatal(err)
	}

	started, err := runner.Plan(ctx, 1, testNow)
	if err != nil || len(started) != 1 || started[0] != "sfo" {
		t.Fatalf("Plan = %v, %v; want the sfo retirement", started, err)
	}
	record, _, err := lifecycle.Get(ctx, "sfo")
	if err != nil || record.Phase != regionlifecycle.RetireApproved {
		t.Fatalf("sfo record = %s, %v; want retire-approved", record.Phase, err)
	}
	decision, ok, err := runner.State.Decision(ctx)
	if err != nil || !ok || decision.Action != ActionRemove || decision.Cell != "sfo" {
		t.Fatalf("saved decision = %+v, %v, %v", decision, ok, err)
	}
}

func TestPlanHoldsWhileARegionIsInFlight(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	runner, lifecycle := newTestRunner(t, []globalview.Region{summary("gru", statusSaturated()),
		summary("fra", statusBusy()), summary("sfo", statusBusy())})
	seedRecord(t, ctx, lifecycle, "lhr", "uk-london-1", regionlifecycle.Approved)

	started, err := runner.Plan(ctx, 1, testNow)
	if err != nil || started != nil {
		t.Fatalf("Plan = %v, %v; want no action while lhr is in flight", started, err)
	}
	decision, _, err := runner.State.Decision(ctx)
	if err != nil || decision.Action != ActionHold ||
		decision.Reason != "region lhr is still approved: one region action at a time" {
		t.Fatalf("saved decision = %+v, %v", decision, err)
	}
}

func TestAddProposesAndApprovesTheRegion(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	runner, lifecycle := newTestRunner(t, nil)
	decision := Decision{Action: ActionAdd, Cell: "lhr", OCIRegion: "uk-london-1", At: testNow,
		Reason: "gru has wanted more nodes for 1h0m0s; lhr is 150ms away"}
	if err := runner.add(ctx, 1, decision, testPrice, testNow); err != nil {
		t.Fatal(err)
	}
	record, _, err := lifecycle.Get(ctx, "lhr")
	if err != nil {
		t.Fatal(err)
	}
	if record.Phase != regionlifecycle.Approved || record.Proposal.Reason != decision.Reason ||
		record.Proposal.EstimatedMonthlyCents != testPrice || len(record.Proposal.EvidenceDigests) != 1 {
		t.Fatalf("lhr record = %+v", record)
	}
}

func TestAddReprosesOverATerminalRecordAndApprovesIt(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	runner, lifecycle := newTestRunner(t, nil)
	seedRecord(t, ctx, lifecycle, "lhr", "uk-london-1", regionlifecycle.Retired)
	prior, _, err := lifecycle.Get(ctx, "lhr")
	if err != nil {
		t.Fatal(err)
	}
	decision := Decision{Action: ActionAdd, Cell: "lhr", OCIRegion: "uk-london-1", At: testNow,
		Reason: "gru has wanted more nodes for 1h0m0s; lhr is 150ms away"}
	if err := runner.add(ctx, 1, decision, testPrice, testNow); err != nil {
		t.Fatal(err)
	}
	record, _, err := lifecycle.Get(ctx, "lhr")
	if err != nil {
		t.Fatal(err)
	}
	if record.Phase != regionlifecycle.Approved || record.Proposal.ID == prior.Proposal.ID ||
		record.Generation != prior.Generation+2 {
		t.Fatalf("reproposed lhr = %+v, prior %+v; want a new approved proposal", record, prior)
	}
}

func TestRegionsReadTheMeasuredRoundTrips(t *testing.T) {
	t.Parallel()

	status := statusIdle()
	status.RTTMillis = map[string]int{"us-sanjose-1": 171, "eu-frankfurt-1": 197}
	runner, _ := newTestRunner(t, []globalview.Region{summary("sfo", status)})
	regions, err := runner.regions(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, region := range regions {
		if region.Cell != "sfo" {
			continue
		}
		if len(region.RTT) != 2 || region.RTT["us-sanjose-1"] != 171*time.Millisecond ||
			region.RTT["eu-frankfurt-1"] != 197*time.Millisecond {
			t.Fatalf("sfo RTT = %v; want 171ms and 197ms", region.RTT)
		}
		return
	}
	t.Fatal("sfo is not in the regions")
}
