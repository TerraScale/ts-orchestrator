package regionsuggest

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/budget"
	"github.com/TerraScale/ts-orchestrator/internal/globalcontrol"
	"github.com/TerraScale/ts-orchestrator/internal/globalview"
	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
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

	persist := func(t *testing.T, writer, reader *Store, want State, revision uint64) (State, uint64) {
		t.Helper()
		written, err := writer.Save(t.Context(), 1, want, revision)
		if err != nil || written <= revision {
			t.Fatalf("save revision = %d after %d, %v", written, revision, err)
		}
		loaded, found, err := reader.Load(t.Context())
		if err != nil || found != written {
			t.Fatalf("loaded revision = %d, %v; want %d", found, err, written)
		}
		if loaded.Suggestion != want.Suggestion {
			t.Fatalf("loaded suggestion = %+v; want %+v", loaded.Suggestion, want.Suggestion)
		}
		for _, clocks := range []struct {
			name      string
			got, want map[string]time.Time
		}{
			{name: "saturation", got: loaded.Memory.SaturatedSince, want: want.Memory.SaturatedSince},
			{name: "idle", got: loaded.Memory.IdleSince, want: want.Memory.IdleSince},
		} {
			if len(clocks.got) != len(clocks.want) {
				t.Fatalf("loaded %s clocks = %v; want %v", clocks.name, clocks.got, clocks.want)
			}
			for cell, wantAt := range clocks.want {
				if gotAt, ok := clocks.got[cell]; !ok || !gotAt.Equal(wantAt) {
					t.Fatalf("loaded %s clock for %s = %v, present=%v; want %v", clocks.name, cell, gotAt, ok, wantAt)
				}
			}
		}
		return loaded, found
	}

	t.Run("retainedSaturationClockAcrossStore", func(t *testing.T) {
		js := newTestJetStream(t)
		writer, err := OpenStore(t.Context(), js, 1, fencer{})
		if err != nil {
			t.Fatal(err)
		}
		reader, err := OpenStore(t.Context(), js, 1, fencer{})
		if err != nil {
			t.Fatal(err)
		}
		saturated := testRegions(statusSaturated(), statusBusy(), statusBusy())
		suggestion, memory := Suggest(saturated, lhrOnly, Memory{}, testBudget(testHeadroom, testPrice), testNow)
		state, revision := persist(t, writer, reader, State{Memory: memory, Suggestion: suggestion}, 0)
		if state.Suggestion.Action != ActionNone || !state.Memory.SaturatedSince["gru"].Equal(testNow) {
			t.Fatalf("first saturated round = %+v, %+v", state.Suggestion, state.Memory)
		}
		suggestion, memory = Suggest(saturated, lhrOnly, state.Memory, testBudget(testHeadroom, testPrice), testNow.Add(SaturatedFor))
		state, revision = persist(t, writer, reader, State{Memory: memory, Suggestion: suggestion}, revision)
		if state.Suggestion.Action != ActionAdd || state.Suggestion.Cell != "lhr" {
			t.Fatalf("saturated for an hour = %+v", state.Suggestion)
		}
		calm := testRegions(statusBusy(), statusBusy(), statusBusy())
		suggestion, memory = Suggest(calm, lhrOnly, state.Memory, testBudget(testHeadroom, testPrice), testNow.Add(2*SaturatedFor))
		state, _ = persist(t, writer, reader, State{Memory: memory, Suggestion: suggestion}, revision)
		if _, ok := state.Memory.SaturatedSince["gru"]; ok {
			t.Fatalf("a region that stopped wanting nodes kept its clock: %+v", state.Memory)
		}
	})

	t.Run("retainedIdleClockAcrossStore", func(t *testing.T) {
		js := newTestJetStream(t)
		writer, err := OpenStore(t.Context(), js, 1, fencer{})
		if err != nil {
			t.Fatal(err)
		}
		reader, err := OpenStore(t.Context(), js, 1, fencer{})
		if err != nil {
			t.Fatal(err)
		}
		regions := testRegions(statusBusy(), statusBusy(), statusIdle())
		suggestion, memory := Suggest(regions, nil, Memory{}, testBudget(0, 0), testNow)
		state, revision := persist(t, writer, reader, State{Memory: memory, Suggestion: suggestion}, 0)
		if state.Suggestion.Action != ActionNone {
			t.Fatalf("first idle round = %+v", state.Suggestion)
		}
		suggestion, memory = Suggest(regions, nil, state.Memory, testBudget(0, 0), testNow.Add(IdleFor-time.Minute))
		state, revision = persist(t, writer, reader, State{Memory: memory, Suggestion: suggestion}, revision)
		if state.Suggestion.Action != ActionNone {
			t.Fatalf("idle one minute short of IdleFor = %+v", state.Suggestion)
		}
		suggestion, memory = Suggest(regions, nil, state.Memory, testBudget(0, 0), testNow.Add(IdleFor))
		state, _ = persist(t, writer, reader, State{Memory: memory, Suggestion: suggestion}, revision)
		if state.Suggestion.Action != ActionRemove || state.Suggestion.Cell != "sfo" || state.Suggestion.OCIRegion != "us-sanjose-1" {
			t.Fatalf("idle for IdleFor = %+v", state.Suggestion)
		}
	})

	t.Run("retainedUnknownStatusClearsStoredIdleClock", func(t *testing.T) {
		js := newTestJetStream(t)
		writer, err := OpenStore(t.Context(), js, 1, fencer{})
		if err != nil {
			t.Fatal(err)
		}
		reader, err := OpenStore(t.Context(), js, 1, fencer{})
		if err != nil {
			t.Fatal(err)
		}
		state, revision := persist(t, writer, reader, State{
			Memory: Memory{IdleSince: map[string]time.Time{"sfo": testNow.Add(-time.Hour)}},
		}, 0)
		if at, ok := state.Memory.IdleSince["sfo"]; !ok || !at.Equal(testNow.Add(-time.Hour)) {
			t.Fatalf("initial idle clock = %v, present=%v", at, ok)
		}
		regions := testRegions(statusBusy(), statusBusy(), nil)
		suggestion, memory := Suggest(regions, nil, state.Memory, testBudget(0, 0), testNow)
		state, _ = persist(t, writer, reader, State{Memory: memory, Suggestion: suggestion}, revision)
		if _, ok := state.Memory.IdleSince["sfo"]; ok {
			t.Fatalf("an unknown status kept the idle clock: %+v", state.Memory)
		}
	})
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
