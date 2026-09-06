package databaselifecycle

import (
	"encoding/json/v2"
	"errors"
	"testing"
	"time"
)

func fixture() (State, Event) {
	state := NewState()
	event := Event{OperationID: "create", Kind: "create", Identity: Identity{Environment: "production", OrganizationID: "01ARZ3NDEKTSV4RRFFQ69G5FAY", ProjectID: "01ARZ3NDEKTSV4RRFFQ69G5FAZ", DatabaseID: "01ARZ3NDEKTSV4RRFFQ69G5FB0"}, At: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC), Regions: []string{"GRU", "FRA"}}
	return state, event
}
func applyOK(t *testing.T, state *State, e Event) {
	t.Helper()
	if err := Apply(state, e); err != nil {
		t.Fatal(err)
	}
}
func routing(e Event) Event {
	e.Kind = "streams"
	e.OperationID = "streams"
	e.Streams = []Stream{{Region: "FRA", Partition: "root", Epoch: 1, StartedAt: e.At}, {Region: "GRU", Partition: "root", Epoch: 1, StartedAt: e.At}}
	e.Regions = nil
	return e
}
func TestClosureRequiresRoutingAndPreservesImmutableReceipt(t *testing.T) {
	state, e := fixture()
	applyOK(t, &state, e)
	end := e.At.Add(24 * time.Hour)
	if _, err := Freeze(&state, e.OrganizationID, e.At, end); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("missing routing accepted: %v", err)
	}
	route := routing(e)
	applyOK(t, &state, route)
	first, err := Freeze(&state, e.OrganizationID, e.At, end)
	if err != nil {
		t.Fatal(err)
	}
	first.Resources[0].Regions[0] = "SFO"
	second, err := Freeze(&state, e.OrganizationID, e.At, end)
	if err != nil || second.Resources[0].Regions[0] != "FRA" {
		t.Fatalf("aliased snapshot: %+v %v", second, err)
	}
	late := e
	late.OperationID = "late-create"
	late.DatabaseID = "01ARZ3NDEKTSV4RRFFQ69G5FB2"
	late.At = e.At.Add(time.Hour)
	if err := Apply(&state, late); !errors.Is(err, ErrClosed) {
		t.Fatalf("late create accepted: %v", err)
	}
	route.OperationID = "late-route"
	route.At = end.Add(time.Hour)
	route.Streams = append(route.Streams, Stream{Region: "GRU", Partition: "hidden", Epoch: 2, StartedAt: e.At})
	if err := Apply(&state, route); !errors.Is(err, ErrClosed) {
		t.Fatalf("backdated stream accepted: %v", err)
	}
	if err := Apply(&state, e); err != nil {
		t.Fatalf("original retry rejected by close: %v", err)
	}
}
func TestEpochHistoryAndDeletionStopReceipts(t *testing.T) {
	state, e := fixture()
	applyOK(t, &state, e)
	route := routing(e)
	applyOK(t, &state, route)
	cutoff := e.At.Add(12 * time.Hour)
	route.OperationID = "rollover"
	route.At = cutoff
	route.Streams[0].StoppedAt = cutoff
	route.Streams = append(route.Streams, Stream{Region: "FRA", Partition: "root", Epoch: 2, StartedAt: cutoff})
	applyOK(t, &state, route)
	deletion := e
	deletion.OperationID = "delete"
	deletion.Kind = "delete"
	deletion.Regions = nil
	deletion.At = e.At.Add(20 * time.Hour)
	deletion.RetainUntil = deletion.At.Add(30 * 24 * time.Hour)
	applyOK(t, &state, deletion)
	r := state.Resources[Key(e.Identity)]
	if !r.AccessRevoked || !r.UsageStoppedAt.Equal(deletion.At) || !r.EffectsCompletedAt.IsZero() {
		t.Fatal("delete intent confused physical cleanup")
	}
	end := e.At.Add(24 * time.Hour)
	if _, err := Freeze(&state, e.OrganizationID, e.At, end); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("unconfirmed stop sealed: %v", err)
	}
	route.OperationID = "native-stop"
	route.At = deletion.At.Add(time.Minute)
	for i := range route.Streams {
		if route.Streams[i].StoppedAt.IsZero() {
			route.Streams[i].StoppedAt = deletion.At
		}
	}
	applyOK(t, &state, route)
	closed, err := Freeze(&state, e.OrganizationID, e.At, end)
	if err != nil || len(closed.Resources) != 1 || len(closed.Resources[0].Streams) != 3 {
		t.Fatalf("deleted epoch history lost: %+v %v", closed, err)
	}
	// Completion can be received after closure without altering that receipt.
	completion := deletion
	completion.Kind = "effects_completed"
	completion.OperationID = "cleanup"
	completion.At = end.Add(time.Hour)
	applyOK(t, &state, completion)
	replay, err := Freeze(&state, e.OrganizationID, e.At, end)
	if err != nil || replay.Digest != closed.Digest || !replay.Resources[0].EffectsCompletedAt.IsZero() {
		t.Fatal("closure changed on cleanup")
	}
}
func TestBranchIdentityRegionsCascadeAndRestart(t *testing.T) {
	state, e := fixture()
	applyOK(t, &state, e)
	branch := e
	branch.Kind = "branch_create"
	branch.OperationID = "branch"
	branch.ParentDatabaseID = e.DatabaseID
	branch.DatabaseID = "01ARZ3NDEKTSV4RRFFQ69G5FB2"
	branch.At = e.At.Add(time.Hour)
	wrong := branch
	wrong.Regions = []string{"GRU"}
	if err := Apply(&state, wrong); !errors.Is(err, ErrConflict) {
		t.Fatalf("branch changed residency: %v", err)
	}
	applyOK(t, &state, branch)
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	var restarted State
	if err := json.Unmarshal(data, &restarted); err != nil {
		t.Fatal(err)
	}
	if err := Validate(restarted); err != nil {
		t.Fatal(err)
	}
	applyOK(t, &restarted, branch)
	deletion := e
	deletion.Kind = "delete"
	deletion.OperationID = "delete"
	deletion.At = branch.At.Add(time.Hour)
	deletion.Regions = nil
	applyOK(t, &restarted, deletion)
	for _, r := range restarted.Resources {
		if !r.AccessRevoked || !r.DeletedAt.Equal(deletion.At) {
			t.Fatal("parent left live branch")
		}
	}
	branch.OperationID = "after-delete"
	branch.DatabaseID = "01ARZ3NDEKTSV4RRFFQ69G5FB3"
	branch.At = deletion.At.Add(time.Hour)
	if err := Apply(&restarted, branch); !errors.Is(err, ErrConflict) {
		t.Fatalf("branch resurrected deleted parent: %v", err)
	}
}

func TestEnvironmentBindingAndEmptyInventory(t *testing.T) {
	state, e := fixture()
	empty, err := FreezeEnvironment(&state, "production", e.OrganizationID, e.At, e.At.Add(time.Hour))
	if err != nil || empty.Environment != "production" || len(empty.Resources) != 0 || empty.Digest == "" {
		t.Fatalf("unbound empty cycle: %+v %v", empty, err)
	}
	if _, err := FreezeEnvironment(&state, "staging", e.OrganizationID, e.At, e.At.Add(time.Hour)); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed environment on closed cycle: %v", err)
	}
	state, e = fixture()
	applyOK(t, &state, e)
	if _, err := FreezeEnvironment(&state, "staging", e.OrganizationID, e.At, e.At.Add(time.Hour)); !errors.Is(err, ErrConflict) {
		t.Fatalf("mixed environment accepted: %v", err)
	}
}
