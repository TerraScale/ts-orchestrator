package delivery

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/nats-io/nats.go"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
)

func TestUnpreparedIntentProducesDurableRefusalWithoutDesiredChanges(t *testing.T) {
	writer := &testWriter{}
	service, ctx := testService(t, writer)
	intent := testIntent(t, service, ctx)
	service.config.Planner = diagnosticPlanner{err: fmt.Errorf("native selection missing: %w", ErrInvalid)}
	wire := mustJSON(intent)
	for delivered := uint64(1); delivered <= 2; delivered++ {
		if terminal, err := service.processDelivery(ctx, wire, delivered); !terminal || err != nil {
			t.Fatalf("delivery %d: terminal=%t err=%v", delivered, terminal, err)
		}
	}
	receipt, err := service.StatusFor(ctx, intent)
	if err != nil || receipt.Status != "rejected" || receipt.Error == "" || writer.count() != 0 {
		t.Fatalf("receipt=%+v err=%v writes=%d", receipt, err, writer.count())
	}

	transient, ctx := testService(t, &testWriter{})
	other := testIntent(t, transient, ctx)
	transient.config.Planner = diagnosticPlanner{err: fmt.Errorf("selection read: %w", nats.ErrTimeout)}
	if terminal, err := transient.processDelivery(ctx, mustJSON(other), 100); terminal || !errors.Is(err, nats.ErrTimeout) {
		t.Fatalf("transient lookup refused permanently: terminal=%t err=%v", terminal, err)
	}
	if _, err := transient.StatusFor(ctx, other); !errors.Is(err, ErrPending) {
		t.Fatalf("transient receipt: %v", err)
	}
}

type revokedDesiredWriter struct{ calls int }

func (w *revokedDesiredWriter) ApplyDesired(context.Context, host.Desired) (host.Receipt, error) {
	w.calls++
	return host.Receipt{}, fmt.Errorf("forward selection expired: %w", ErrInvalid)
}

func TestPersistedPlanStopsWhenDesiredAuthorizationExpires(t *testing.T) {
	service, ctx := testService(t, &testWriter{})
	intent := testIntent(t, service, ctx)
	writer := &revokedDesiredWriter{}
	service.config.Writer = writer
	wire := mustJSON(intent)
	for delivered := uint64(1); delivered <= 2; delivered++ {
		if terminal, err := service.processDelivery(ctx, wire, delivered); !terminal || err != nil {
			t.Fatalf("delivery %d: terminal=%t err=%v", delivered, terminal, err)
		}
	}
	receipt, err := service.StatusFor(ctx, intent)
	if err != nil || receipt.Status != "held" || receipt.Error == "" || writer.calls != 1 {
		t.Fatalf("receipt=%+v err=%v apply attempts=%d", receipt, err, writer.calls)
	}
}
