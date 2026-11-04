package app

import (
	"context"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/budget"
	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

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
