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

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/budget"
	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/globalcontrol"
	"github.com/TerraScale/ts-orchestrator/internal/globalview"
	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

func TestCapacityRegionsMapRollupStatuses(t *testing.T) {
	at := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	status := &nodescale.Status{Schema: nodescale.StatusSchema, Cell: "gru", At: at, Nodes: 4, Want: 5, Pressure: 0.82,
		NodeMonthlyCents: 4100, ProjectedCents: 21000, Currency: "BRL", CostAt: at}
	got := capacityRegions([]globalview.Region{
		{Cell: "gru", Rollup: &globalview.Rollup{Cell: "gru", Scale: status}},
		{Cell: "sjc", Rollup: &globalview.Rollup{Cell: "sjc"}},
		{Cell: "fra"},
	})
	want := []budget.Region{
		{Cell: "gru", Nodes: 4, Want: 5, Pressure: 0.82, At: at},
		{Cell: "sjc"},
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

// startEmbeddedNATS runs an embedded JetStream server and connects to it.
func startEmbeddedNATS(t *testing.T) *nats.Conn {
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
	return conn
}

// startGlobalHome runs an embedded NATS and makes this member the global leader of a
// home region, returning its global control, the connection it runs on and its JetStream.
func startGlobalHome(t *testing.T, ctx context.Context) (*globalControl, *nats.Conn, jetstream.JetStream) {
	t.Helper()
	conn := startEmbeddedNATS(t)
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
	return &globalControl{authority: control, writer: writer, reader: &writer.Reader}, conn, js
}

func TestCapacityAllocatorWritesAndJournalsOnChange(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	global, _, js := startGlobalHome(t, ctx)
	now := time.Now().UTC()
	epoch := global.authority.Current().Epoch
	if err := budget.WriteBudget(ctx, global.writer, epoch, budget.Budget{Schema: budget.Schema, ID: entityid.New(),
		MonthlyCapCents: 50000, Currency: "BRL", SetBy: "ops@terrascale.tech", SetAt: now}); err != nil {
		t.Fatal(err)
	}
	var rollups []globalview.Region
	allocator := &capacityAllocator{global: global, regions: func() []globalview.Region { return rollups },
		alert: budgetAlert{js: js, replicas: 1}}
	journal := &recordedDecisions{}
	restore := decisionlog.SetDefault(journal)
	t.Cleanup(restore)

	// Cheap fresh status never substitutes for signed complete infrastructure facts.
	rollups = []globalview.Region{{Cell: "gru", Rollup: &globalview.Rollup{Cell: "gru", Scale: &nodescale.Status{
		Schema: nodescale.StatusSchema, Cell: "gru", At: now, Nodes: 3, Want: 4, Pressure: .9,
		NodeMonthlyCents: 1, ProjectedCents: 1, Currency: "BRL", CostAt: now}}}}
	prior := budget.Capacity{Schema: budget.Schema, At: now, State: budget.StateOK, Reason: "previous provisional plan", CapCents: 50000, Currency: "BRL",
		Regions: []budget.RegionAllowance{{Cell: "gru", Nodes: 3, Want: 4, Allowance: 4, Pressure: .9, GrantedAt: now}}}
	if err := budget.WriteCapacity(ctx, global.writer, epoch, prior); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := allocator.tick(ctx, now); err == nil {
			t.Fatal("missing signed complete facts were accepted")
		}
	}
	capacity, found := allocator.Capacity()
	if !found || capacity.State != budget.StateNone || len(capacity.Regions) != 1 || capacity.Regions[0].Allowance != 3 {
		t.Fatalf("missing infrastructure authority retained growth: %+v found=%v", capacity, found)
	}
	stored, found, err := budget.ReadCapacity(ctx, global.reader)
	if err != nil || !found || stored.State != budget.StateNone || stored.Regions[0].Allowance != 3 {
		t.Fatalf("held plan not durable: %+v found=%v err=%v", stored, found, err)
	}
	if len(journal.decisions) != 1 || journal.decisions[0].Kind != decisionlog.KindHeld {
		t.Fatalf("repeated hold journaled %d decisions", len(journal.decisions))
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
