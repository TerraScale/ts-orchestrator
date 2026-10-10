package app

import (
	"context"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/budget"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/globalcontrol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/globalview"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/nodescale"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

func TestCapacityRegionsMapRollupStatuses(t *testing.T) {
	at := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	status := &nodescale.Status{Schema: nodescale.StatusSchema, Cell: "gru", At: at, Nodes: 4, Want: 5, Pressure: 0.82,
		NodeMonthlyCents: 4100, ProjectedCents: 21000, Currency: "BRL", CostAt: at}
	got := capacityRegions([]globalview.Region{
		{Cell: "gru", Rollup: &globalview.Rollup{Cell: "gru", Scale: status}},
		{Cell: "sfo", Rollup: &globalview.Rollup{Cell: "sfo"}},
		{Cell: "fra"},
	})
	want := []budget.Region{
		{Cell: "gru", Nodes: 4, Want: 5, Pressure: 0.82, NodeMonthlyCents: 4100, ProjectedCents: 21000, Currency: "BRL", At: at},
		{Cell: "sfo"},
		{Cell: "fra"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("capacity regions = %+v, want %+v", got, want)
	}
}

func TestRosterCellsWithoutAViewHoldGrowth(t *testing.T) {
	roster := globalcontrol.Roster{Regions: []globalcontrol.RosterEntry{{Cell: "gru"}, {Cell: "fra"}}}
	got := addRosterCells([]budget.Region{{Cell: "gru", Nodes: 3}}, roster)
	want := []budget.Region{{Cell: "gru", Nodes: 3}, {Cell: "fra"}}
	if !slices.Equal(got, want) {
		t.Fatalf("roster regions = %+v, want %+v", got, want)
	}
}

// recordedDecisions keeps every decision recorded through the process recorder.
type recordedDecisions struct {
	mu        sync.Mutex
	decisions []decisionlog.Decision
}

func (r *recordedDecisions) Record(_ context.Context, decision decisionlog.Decision) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.decisions = append(r.decisions, decision)
	return decision.ID
}

// startGlobalHome runs an embedded NATS and makes this member the global leader of a
// home region, returning its global control.
func startGlobalHome(t *testing.T, ctx context.Context) *globalControl {
	t.Helper()
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true,
		StoreDir: filepath.Join(t.TempDir(), "jetstream")})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	control, err := authority.Start(ctx, js, authority.Config{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Scope: protocol.GlobalScope, CandidateID: "0000000000F2D374M7NMRHJJQT", Replicas: 1,
		LeaseDuration: 5 * time.Second, RenewInterval: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	for !control.Current().CanMutate() {
		if ctx.Err() != nil {
			t.Fatal("global authority never became leader")
		}
		time.Sleep(20 * time.Millisecond)
	}
	writer, err := globalcontrol.OpenHome(ctx, js, "gru", nil, 1, control)
	if err != nil {
		t.Fatal(err)
	}
	return &globalControl{authority: control, writer: writer, reader: &writer.Reader}
}

func TestCapacityAllocatorWritesAndJournalsOnChange(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	global := startGlobalHome(t, ctx)
	now := time.Now().UTC()
	epoch := global.authority.Current().Epoch
	if err := budget.WriteBudget(ctx, global.writer, epoch, budget.Budget{Schema: budget.Schema, ID: entityid.New(),
		MonthlyCapCents: 50000, Currency: "BRL", SetBy: "ops@terrascale.tech", SetAt: now}); err != nil {
		t.Fatal(err)
	}
	var rollups []globalview.Region
	allocator := &capacityAllocator{global: global, regions: func() []globalview.Region { return rollups }}
	journal := &recordedDecisions{}
	restore := decisionlog.SetDefault(journal)
	t.Cleanup(restore)

	// Without a status the spend is unknown: growth is held, and the hold is journaled once.
	rollups = []globalview.Region{{Cell: "gru", Rollup: &globalview.Rollup{Cell: "gru"}}}
	for range 2 {
		if err := allocator.tick(ctx, now); err != nil {
			t.Fatal(err)
		}
	}
	if capacity, found := allocator.Capacity(); !found || capacity.State != budget.StateUnknown {
		t.Fatalf("capacity without status = %+v, %v; want unknown", capacity, found)
	}

	// A fresh status priced in BRL lets gru grow by one node, which is journaled as the hold clearing.
	rollups = []globalview.Region{{Cell: "gru", Rollup: &globalview.Rollup{Cell: "gru", Scale: &nodescale.Status{
		Schema: nodescale.StatusSchema, Cell: "gru", At: now, Nodes: 3, Want: 4, Pressure: 0.9,
		NodeMonthlyCents: 4100, ProjectedCents: 20000, Currency: "BRL", CostAt: now}}}}
	if err := allocator.tick(ctx, now); err != nil {
		t.Fatal(err)
	}
	capacity, found := allocator.Capacity()
	if !found || capacity.State != budget.StateOK || capacity.Regions[0].Allowance != 4 {
		t.Fatalf("capacity with status = %+v, %v; want ok with gru at 4", capacity, found)
	}
	stored, found, err := budget.ReadCapacity(ctx, global.reader)
	if err != nil || !found || stored.State != budget.StateOK || stored.Regions[0].Allowance != 4 {
		t.Fatalf("stored capacity = %+v, %v, %v; want the same allocation", stored, found, err)
	}
	if len(journal.decisions) != 2 || journal.decisions[0].Kind != decisionlog.KindHeld ||
		journal.decisions[1].Kind != decisionlog.KindHoldCleared {
		t.Fatalf("journaled %d decisions, want held then hold_cleared", len(journal.decisions))
	}
	for _, decision := range journal.decisions {
		if decision.Actor.Slice != "budget" || decision.Region != "global" || decision.Subject.ID != "monthly" {
			t.Fatalf("decision = %+v, want the budget slice in the global region", decision)
		}
	}
}

func TestCapacityBudgetsShowOnlyKnownSpend(t *testing.T) {
	home := &globalControl{writer: &globalcontrol.Writer{}}
	for _, tc := range []struct {
		state budget.State
		shown bool
	}{
		{budget.StateNone, false},
		{budget.StateUnknown, false},
		{budget.StateOK, true},
		{budget.StateWarn, true},
		{budget.StateOver, true},
	} {
		allocator := &capacityAllocator{found: true, capacity: budget.Capacity{Schema: budget.Schema,
			At: time.Now(), Reason: "test", State: tc.state, CapCents: 50000, ProjectedCents: 42000, Currency: "BRL"}}
		got, err := capacityBudgets{global: home, allocator: allocator}.Budgets(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if !tc.shown {
			if got != nil {
				t.Fatalf("state %s shows budgets %+v, want none", tc.state, got)
			}
			continue
		}
		if len(got) != 1 || got[0].Used != 420 || got[0].Ceiling != 500 || got[0].Unit != "BRL" {
			t.Fatalf("state %s budgets = %+v, want 420 of 500 BRL", tc.state, got)
		}
	}
}
