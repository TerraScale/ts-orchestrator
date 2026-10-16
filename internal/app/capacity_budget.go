package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/budget"
	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/globalcontrol"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

// maxBudgetSetBytes bounds one budget request. A budget is a few hundred bytes.
const maxBudgetSetBytes = 4 << 10

// budgetSetTimeout bounds one budget write on the global leader.
const budgetSetTimeout = 5 * time.Second

// budgetLeader is the global authority: whether this member may write, and under which epoch.
type budgetLeader interface {
	Current() authority.Snapshot
	Guard(ctx context.Context, epoch uint64) error
}

// budgetSetResponse answers a budget request. Error is empty once the budget is written.
type budgetSetResponse struct {
	Error string `json:"error,omitempty"`
}

// startBudgetSet answers budget requests on the home's global leader. Other
// regions have no global writer and start nothing.
func startBudgetSet(ctx context.Context, conn *nats.Conn, global *globalControl) error {
	if global.writer == nil {
		return nil
	}
	return serveBudgetSet(ctx, conn, global.authority, global.writer)
}

// serveBudgetSet subscribes every home controller to budget requests. Only the
// leader answers; a follower stays silent so the requester's deadline decides.
func serveBudgetSet(ctx context.Context, conn *nats.Conn, leader budgetLeader, writer *globalcontrol.Writer) error {
	subscription, err := conn.Subscribe(protocol.GlobalBudgetSetSubject(), func(message *nats.Msg) {
		snapshot := leader.Current()
		if !snapshot.CanMutate() {
			return
		}
		requestCtx, cancel := context.WithTimeout(ctx, budgetSetTimeout)
		defer cancel()
		err := applyBudgetSet(requestCtx, leader, writer, snapshot.Epoch, message.Data)
		if errors.Is(err, authority.ErrFenced) || errors.Is(err, authority.ErrNotLeader) {
			return
		}
		response := budgetSetResponse{}
		if err != nil {
			response.Error = err.Error()
		}
		if wire, err := json.Marshal(response); err == nil {
			_ = message.Respond(wire)
		}
	})
	if err != nil {
		return fmt.Errorf("subscribe to budget requests: %w", err)
	}
	go func() {
		<-ctx.Done()
		_ = subscription.Unsubscribe()
	}()
	return nil
}

// applyBudgetSet validates one budget request, writes it under epoch and
// journals the change.
func applyBudgetSet(ctx context.Context, leader budgetLeader, writer *globalcontrol.Writer, epoch uint64, wire []byte) error {
	var next budget.Budget
	if err := protocol.DecodeStrict(wire, &next, maxBudgetSetBytes); err != nil {
		return fmt.Errorf("decode budget request: %w", err)
	}
	if err := next.Validate(); err != nil {
		return err
	}
	if err := leader.Guard(ctx, epoch); err != nil {
		return err
	}
	if err := budget.WriteBudget(ctx, writer, epoch, next); err != nil {
		return fmt.Errorf("write monthly budget: %w", err)
	}
	decisionlog.Record(ctx, decisionlog.Decision{Time: time.Now(), Region: "global", Epoch: epoch,
		Actor: decisionlog.Actor{Slice: "budget"}, Kind: decisionlog.KindHoldCleared,
		Subject: decisionlog.Subject{Kind: "budget", ID: "monthly"},
		Summary: "set the monthly budget to " + budget.Money(next.MonthlyCapCents, next.Currency),
		Reason:  "set by " + next.SetBy})
	return nil
}
