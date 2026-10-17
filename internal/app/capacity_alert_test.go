package app

import (
	"context"
	"errors"
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
		Schema: nodescale.StatusSchema, Cell: "gru", At: at, Nodes: 3, Want: 4, Pressure: 0.4,
		NodeMonthlyCents: 4100, ProjectedCents: projected, Currency: "BRL", CostAt: at}}}}
}

// Alert inputs exercise HTTP and durable state; complete priced allocator evidence remains unavailable.
func alertCapacity(at time.Time, projected uint64) budget.Capacity {
	capacity := budget.Capacity{Schema: budget.Schema, At: at, State: budget.StateOK,
		CapCents: 50000, ProjectedCents: projected, Currency: "BRL", Ratio: float64(projected) / 50000}
	if capacity.Ratio >= budget.WarnRatio {
		capacity.State = budget.StateWarn
	}
	return capacity
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
	rollups := alertRegions(now, 40000)
	newAllocator := func() *capacityAllocator {
		return &capacityAllocator{global: global, regions: func() []globalview.Region { return rollups },
			alert: budgetAlert{js: js, replicas: 1, status: status}}
	}
	allocator := newAllocator()
	if err := allocator.tick(ctx, now); !errors.Is(err, nodescale.ErrCapacityPending) {
		t.Fatalf("allocator without spending authority = %v, want capacity pending", err)
	}
	if capacity, found, err := budget.ReadCapacity(ctx, global.reader); err != nil || !found || capacity.State != budget.StateNone || capacity.ProjectedCents != 0 ||
		len(capacity.Regions) != 1 || capacity.Regions[0].Nodes != 3 || capacity.Regions[0].Want != 4 || capacity.Regions[0].Allowance != 3 {
		t.Fatalf("allocator without spending authority stored %+v, found=%v, err=%v; want held capacity without rollup spend", capacity, found, err)
	}
	if got := recorder.take(); len(got) != 0 {
		t.Fatalf("requests without spending authority = %v, want none", got)
	}
	alert := func(a *capacityAllocator, projected uint64) {
		a.alertBudget(ctx, now, epoch, alertCapacity(now, projected))
	}
	openWarning := []string{"POST /api/operator/incidents"}
	resolveWarning := []string{"POST /api/operator/incidents/" + testWarningID + "/updates"}

	// At 80% of the cap the warning opens.
	alert(allocator, 40000)
	if got := recorder.take(); !slices.Equal(got, openWarning) {
		t.Fatalf("requests at 80%% = %v, want %v", got, openWarning)
	}

	// At 77% it stays open and sends nothing.
	alert(allocator, 38500)
	if got := recorder.take(); len(got) != 0 {
		t.Fatalf("requests at 77%% = %v, want none", got)
	}

	// At 74% it resolves.
	alert(allocator, 37000)
	if got := recorder.take(); !slices.Equal(got, resolveWarning) {
		t.Fatalf("requests at 74%% = %v, want %v", got, resolveWarning)
	}
	stored := budgetAlert{js: js, replicas: 1}
	if record, err := stored.load(ctx); err != nil || record.Open {
		t.Fatalf("stored alert after resolve = %+v, %v; want closed", record, err)
	}

	// Reopen at 80%, then a new leader reads the record: it neither reopens at 80% nor drops the warning at 77%.
	alert(allocator, 40000)
	if got := recorder.take(); !slices.Equal(got, openWarning) {
		t.Fatalf("reopen requests = %v, want %v", got, openWarning)
	}
	leader := newAllocator()
	alert(leader, 38500)
	alert(leader, 40000)
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
	recorder, status := startStatusRecorder(t)
	status.Token = func(context.Context) (string, error) { return "", budget.ErrNoStatusToken }
	journal := &recordedDecisions{}
	restore := decisionlog.SetDefault(journal)
	t.Cleanup(restore)
	allocator := &capacityAllocator{global: global, alert: budgetAlert{js: js, replicas: 1, status: status}}

	// Three alert attempts at 80% with no token: nothing is sent and the missing token is journaled once.
	for range 3 {
		allocator.alertBudget(ctx, now, epoch, alertCapacity(now, 40000))
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
