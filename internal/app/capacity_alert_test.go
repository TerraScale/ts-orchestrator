package app

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/budget"
	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/globalview"
	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
)

const testWarningID = "5d3c9a8e-1f2b-4c6d-8e7f-9a0b1c2d3e4f"

// statusRecorder stands in for ts-status's operator API: it opens every incident as testWarningID and records each request.
type statusRecorder struct {
	mu       sync.Mutex
	requests []string
}

func startStatusRecorder(t *testing.T) (*statusRecorder, budget.StatusPage) {
	t.Helper()
	recorder := &statusRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder.mu.Lock()
		recorder.requests = append(recorder.requests, r.Method+" "+r.URL.Path)
		recorder.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"id":"`+testWarningID+`","url":"/incidents/x"}`)
	}))
	t.Cleanup(srv.Close)
	return recorder, budget.StatusPage{URL: srv.URL + "/api/operator", HTTP: srv.Client(),
		Token: func(context.Context) (string, error) { return "test-token", nil }}
}

// take returns the requests seen since the last call.
func (r *statusRecorder) take() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	requests := r.requests
	r.requests = nil
	return requests
}

// alertRegions reports one region whose projected spend is projected cents against a 50000-cent cap.
func alertRegions(at time.Time, projected uint64) []globalview.Region {
	return []globalview.Region{{Cell: "gru", Rollup: &globalview.Rollup{Cell: "gru", Scale: &nodescale.Status{
		Schema: nodescale.StatusSchema, Cell: "gru", At: at, Nodes: 3, Want: 3, Pressure: 0.4,
		NodeMonthlyCents: 4100, ProjectedCents: projected, Currency: "BRL", CostAt: at}}}}
}

func TestCapacityAlertOpensAtWarnResolvesBelowClearAndSurvivesLeaderChange(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	global, _, js := startGlobalHome(t, ctx)
	now := time.Now().UTC()
	epoch := global.authority.Current().Epoch
	if err := budget.WriteBudget(ctx, global.writer, epoch, budget.Budget{Schema: budget.Schema, ID: entityid.New(),
		MonthlyCapCents: 50000, Currency: "BRL", SetBy: "ops@terrascale.tech", SetAt: now}); err != nil {
		t.Fatal(err)
	}
	recorder, status := startStatusRecorder(t)
	var rollups []globalview.Region
	newAllocator := func() *capacityAllocator {
		return &capacityAllocator{global: global, regions: func() []globalview.Region { return rollups },
			alert: budgetAlert{js: js, replicas: 1, status: status}}
	}
	allocator := newAllocator()
	tick := func(a *capacityAllocator, projected uint64) {
		t.Helper()
		rollups = alertRegions(now, projected)
		if err := a.tick(ctx, now); err != nil {
			t.Fatal(err)
		}
	}
	openWarning := []string{"POST /api/operator/incidents"}
	resolveWarning := []string{"POST /api/operator/incidents/" + testWarningID + "/updates"}

	// At 80% of the cap the warning opens.
	tick(allocator, 40000)
	if got := recorder.take(); !slices.Equal(got, openWarning) {
		t.Fatalf("requests at 80%% = %v, want %v", got, openWarning)
	}

	// At 77% it stays open and sends nothing.
	tick(allocator, 38500)
	if got := recorder.take(); len(got) != 0 {
		t.Fatalf("requests at 77%% = %v, want none", got)
	}

	// At 74% it resolves.
	tick(allocator, 37000)
	if got := recorder.take(); !slices.Equal(got, resolveWarning) {
		t.Fatalf("requests at 74%% = %v, want %v", got, resolveWarning)
	}
	stored := budgetAlert{js: js, replicas: 1}
	if record, err := stored.load(ctx); err != nil || record.Open {
		t.Fatalf("stored alert after resolve = %+v, %v; want closed", record, err)
	}

	// Reopen at 80%, then a new leader reads the record: it neither reopens at 80% nor drops the warning at 77%.
	tick(allocator, 40000)
	if got := recorder.take(); !slices.Equal(got, openWarning) {
		t.Fatalf("reopen requests = %v, want %v", got, openWarning)
	}
	leader := newAllocator()
	tick(leader, 38500)
	tick(leader, 40000)
	if got := recorder.take(); len(got) != 0 {
		t.Fatalf("new leader sent %v, want no requests", got)
	}
	if record, err := stored.load(ctx); err != nil || !record.Open || record.Incident != testWarningID {
		t.Fatalf("stored alert = %+v, %v; want open with incident %s", record, err, testWarningID)
	}
}

func TestCapacityAlertJournalsMissingTokenOnce(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	global, _, js := startGlobalHome(t, ctx)
	now := time.Now().UTC()
	epoch := global.authority.Current().Epoch
	if err := budget.WriteBudget(ctx, global.writer, epoch, budget.Budget{Schema: budget.Schema, ID: entityid.New(),
		MonthlyCapCents: 50000, Currency: "BRL", SetBy: "ops@terrascale.tech", SetAt: now}); err != nil {
		t.Fatal(err)
	}
	recorder, status := startStatusRecorder(t)
	status.Token = func(context.Context) (string, error) { return "", budget.ErrNoStatusToken }
	journal := &recordedDecisions{}
	restore := decisionlog.SetDefault(journal)
	t.Cleanup(restore)
	rollups := alertRegions(now, 40000)
	allocator := &capacityAllocator{global: global, regions: func() []globalview.Region { return rollups },
		alert: budgetAlert{js: js, replicas: 1, status: status}}

	// Three ticks at 80% with no token: nothing is sent and the missing token is journaled once.
	for range 3 {
		if err := allocator.tick(ctx, now); err != nil {
			t.Fatal(err)
		}
	}
	if got := recorder.take(); len(got) != 0 {
		t.Fatalf("requests without a token = %v, want none", got)
	}
	held := 0
	for _, decision := range journal.decisions {
		if decision.Summary == "ts-status warning not sent" {
			held++
			if decision.Kind != decisionlog.KindHeld || decision.Actor.Slice != "budget" {
				t.Fatalf("decision = %+v, want a held budget decision", decision)
			}
		}
	}
	if held != 1 {
		t.Fatalf("journaled %d missing-token decisions, want 1", held)
	}
}
