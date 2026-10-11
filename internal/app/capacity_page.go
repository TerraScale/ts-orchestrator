package app

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/nats-io/nats.go"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/budget"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/dashboard"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/nodescale"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionsuggest"
)

// capacityPage is the capacity page's source. Every region reads the budget and
// capacity document it mirrors and its own scaling status. The home also sends
// budget changes to its global leader and reads the region suggestion.
type capacityPage struct {
	conn   *nats.Conn
	global *globalControl
	scale  func() *nodescale.Status
	// suggestions is set once the home opens the suggester's store.
	suggestions atomic.Pointer[regionsuggest.Store]
}

// Capacity reads everything the page shows. A failed read is named, not fatal.
func (page *capacityPage) Capacity(ctx context.Context) dashboard.CapacityView {
	data := dashboard.CapacityView{Home: page.global.writer != nil}
	if next, found, err := budget.ReadBudget(ctx, page.global.reader); err != nil {
		data.Unavailable = append(data.Unavailable, "monthly budget")
	} else if found {
		data.Budget = &next
	}
	if capacity, found, err := budget.ReadCapacity(ctx, page.global.reader); err != nil {
		data.Unavailable = append(data.Unavailable, "capacity document")
	} else if found {
		data.Capacity = &capacity
	}
	if page.scale != nil {
		data.Scale = page.scale()
	}
	if store := page.suggestions.Load(); data.Home && store != nil {
		suggestion, found, err := store.Suggestion(ctx)
		switch {
		case err != nil:
			data.Unavailable = append(data.Unavailable, "region suggestion")
		case found:
			data.Suggestion = &suggestion
		}
	}
	return data
}

// SetBudget asks the home's global leader to write next. Only the home has a
// global writer; the leader answers within ctx's deadline.
func (page *capacityPage) SetBudget(ctx context.Context, next budget.Budget) error {
	if page.global.writer == nil {
		return dashboard.ErrBudgetNotHome
	}
	wire, err := protocol.EncodeJSON(next)
	if err != nil {
		return err
	}
	reply, err := page.conn.RequestWithContext(ctx, protocol.GlobalBudgetSetSubject(), wire)
	if err != nil {
		return fmt.Errorf("ask the global leader: %w", err)
	}
	var response budgetSetResponse
	if err := protocol.DecodeStrict(reply.Data, &response, maxBudgetSetBytes); err != nil {
		return fmt.Errorf("read the global leader's answer: %w", err)
	}
	if response.Error != "" {
		return errors.New(response.Error)
	}
	return nil
}

var _ dashboard.CapacitySource = (*capacityPage)(nil)
