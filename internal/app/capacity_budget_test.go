package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/budget"
	"github.com/TerraScale/ts-orchestrator/internal/dashboard"
	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/globalcontrol"
	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/regionsuggest"
)

// followerLeader is a global authority that is not the leader.
type followerLeader struct{}

func (followerLeader) Current() authority.Snapshot { return authority.Snapshot{} }
func (followerLeader) Guard(context.Context, uint64) error {
	return authority.ErrFenced
}

func testBudget(cents uint64) budget.Budget {
	return budget.Budget{Schema: budget.Schema, ID: entityid.New(), MonthlyCapCents: cents, Currency: "BRL",
		SetBy: "dashboard 192.0.2.7", SetAt: time.Now().UTC()}
}

func TestBudgetSetWritesJournalsAndAnswers(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	global, conn, _ := startGlobalHome(t, ctx)
	if err := serveBudgetSet(ctx, conn, global.authority, global.writer); err != nil {
		t.Fatal(err)
	}
	journal := &recordedDecisions{}
	restore := decisionlog.SetDefault(journal)
	t.Cleanup(restore)

	next := testBudget(50000)
	page := &capacityPage{conn: conn, global: global}
	if err := page.SetBudget(ctx, next); err != nil {
		t.Fatal(err)
	}
	stored, found, err := budget.ReadBudget(ctx, global.reader)
	if err != nil || !found || stored.ID != next.ID || stored.MonthlyCapCents != 50000 {
		t.Fatalf("stored budget = %+v, %v, %v; want the request", stored, found, err)
	}
	if len(journal.decisions) != 1 {
		t.Fatalf("journaled %d decisions, want 1", len(journal.decisions))
	}
	decision := journal.decisions[0]
	if decision.Actor.Slice != "budget" || decision.Region != "global" || decision.Kind != decisionlog.KindHoldCleared ||
		decision.Summary != "set the monthly budget to BRL 500.00" {
		t.Fatalf("decision = %+v, want the budget change in the global region", decision)
	}
}

func TestBudgetSetRefusesAnInvalidPayloadAndWritesNothing(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	global, conn, _ := startGlobalHome(t, ctx)
	if err := serveBudgetSet(ctx, conn, global.authority, global.writer); err != nil {
		t.Fatal(err)
	}
	page := &capacityPage{conn: conn, global: global}
	err := page.SetBudget(ctx, testBudget(0))
	if err == nil || !strings.Contains(err.Error(), "monthly cap") {
		t.Fatalf("SetBudget(zero cap) = %v, want the leader to refuse the cap", err)
	}
	if _, found, err := budget.ReadBudget(ctx, global.reader); err != nil || found {
		t.Fatalf("a refused budget was stored: found %v, err %v", found, err)
	}
}

func TestBudgetSetIsSilentOnAFollower(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	conn := startEmbeddedNATS(t)
	if err := serveBudgetSet(ctx, conn, followerLeader{}, nil); err != nil {
		t.Fatal(err)
	}
	page := &capacityPage{conn: conn, global: &globalControl{writer: &globalcontrol.Writer{}}}
	askCtx, cancelAsk := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancelAsk()
	if err := page.SetBudget(askCtx, testBudget(50000)); err == nil {
		t.Fatal("a follower answered a budget request")
	}
}

func TestBudgetSetOutsideTheHomeIsRefused(t *testing.T) {
	page := &capacityPage{global: &globalControl{}}
	if err := page.SetBudget(t.Context(), testBudget(50000)); !errors.Is(err, dashboard.ErrBudgetNotHome) {
		t.Fatalf("SetBudget outside the home = %v, want ErrBudgetNotHome", err)
	}
}

func TestCapacityPageReadsBudgetCapacityAndSuggestionAtHome(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	global, conn, _ := startGlobalHome(t, ctx)
	epoch := global.authority.Current().Epoch
	now := time.Now().UTC()
	monthly := testBudget(50000)
	if err := budget.WriteBudget(ctx, global.writer, epoch, monthly); err != nil {
		t.Fatal(err)
	}
	capacity := budget.Allocate(&monthly, []budget.Region{{Cell: "gru", Nodes: 3, Want: 4, NodeMonthlyCents: 4100,
		ProjectedCents: 20000, Currency: "BRL", At: now}}, nil, now)
	if err := budget.WriteCapacity(ctx, global.writer, epoch, capacity); err != nil {
		t.Fatal(err)
	}
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	store, err := regionsuggest.OpenStore(ctx, js, 1, global.authority)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Save(ctx, epoch, regionsuggest.State{Suggestion: regionsuggest.Suggestion{Action: "none",
		Reason: "no region is saturated", At: now}}, 0); err != nil {
		t.Fatal(err)
	}
	scale := func() *nodescale.Status {
		return &nodescale.Status{Schema: nodescale.StatusSchema, Cell: "gru", At: now, Reason: "steady"}
	}
	page := &capacityPage{conn: conn, global: global, scale: scale}
	page.suggestions.Store(store)

	data := page.Capacity(ctx)
	if !data.Home || data.Budget == nil || data.Budget.MonthlyCapCents != 50000 || data.Capacity == nil ||
		data.Scale == nil || data.Suggestion == nil || data.Suggestion.Reason != "no region is saturated" ||
		len(data.Unavailable) != 0 {
		t.Fatalf("home capacity page = %+v, want the budget, capacity, scale and suggestion", data)
	}

	// A region that only mirrors the global control reads the budget and capacity, never the suggestion.
	mirror := &capacityPage{conn: conn, global: &globalControl{reader: global.reader}, scale: scale}
	mirror.suggestions.Store(store)
	data = mirror.Capacity(ctx)
	if data.Home || data.Suggestion != nil || data.Budget == nil || data.Capacity == nil {
		t.Fatalf("mirror capacity page = %+v, want the budget and capacity without the suggestion", data)
	}
}
