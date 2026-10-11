package regionsuggest

import (
	"context"
	"slices"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/budget"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/globalcontrol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/globalview"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/nodescale"
)

func summary(cell string, status *nodescale.Status) globalview.Region {
	return globalview.Region{Cell: cell, Rollup: &globalview.Rollup{Cell: cell, Scale: status}}
}

// newTestRunner is a home at gru with the given summaries and no capacity document.
func newTestRunner(t *testing.T, summaries []globalview.Region) *Runner {
	t.Helper()
	state, err := OpenStore(t.Context(), newTestJetStream(t), 1, fencer{})
	if err != nil {
		t.Fatal(err)
	}
	return &Runner{Home: "gru",
		Rollups: func() []globalview.Region { return summaries },
		Roster: func(context.Context) (globalcontrol.Roster, error) {
			return globalcontrol.Roster{}, globalcontrol.ErrNotFound
		},
		Capacity: func(context.Context) (budget.Capacity, bool, error) { return budget.Capacity{}, false, nil },
		State:    state}
}

func TestSuggestSavesTheAddSuggestion(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	saturated := statusSaturated()
	saturated.RTTMillis = map[string]int{"uk-london-1": 150}
	runner := newTestRunner(t, []globalview.Region{summary("gru", saturated),
		summary("fra", statusBusy()), summary("sfo", statusBusy())})
	saturatedSince := testNow.Add(-2 * time.Hour)
	if _, err := runner.State.Save(ctx, 1, State{Memory: Memory{SaturatedSince: map[string]time.Time{"gru": saturatedSince}}}, 0); err != nil {
		t.Fatal(err)
	}

	suggestion, err := runner.Suggest(ctx, 1, testNow)
	if err != nil || suggestion.Action != ActionAdd || suggestion.Cell != "lhr" || suggestion.OCIRegion != "uk-london-1" {
		t.Fatalf("Suggest = %+v, %v; want an add of lhr", suggestion, err)
	}
	saved, ok, err := runner.State.Suggestion(ctx)
	if err != nil || !ok || saved != suggestion {
		t.Fatalf("saved suggestion = %+v, %v, %v; want %+v", saved, ok, err, suggestion)
	}
}

func TestCandidatesAreTheCatalogRegionsThatServeNothing(t *testing.T) {
	t.Parallel()

	regions := []Region{{Cell: "gru", Home: true}, {Cell: "sfo"}, {Cell: "fra"}}
	var names []string
	for _, candidate := range candidates(regions) {
		names = append(names, candidate.Cell)
		if candidate.Cell == "gru" || candidate.Cell == "sfo" || candidate.Cell == "fra" {
			t.Fatalf("candidates = %v; a serving or bootstrap region is a candidate", names)
		}
	}
	if !slices.Contains(names, "lhr") || len(names) == 0 {
		t.Fatalf("candidates = %v; want lhr among the catalog's other regions", names)
	}
}

func TestRegionsReadTheMeasuredRoundTrips(t *testing.T) {
	t.Parallel()

	status := statusIdle()
	status.RTTMillis = map[string]int{"us-sanjose-1": 171, "eu-frankfurt-1": 197}
	runner := newTestRunner(t, []globalview.Region{summary("sfo", status)})
	regions, err := runner.regions(t.Context())
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
