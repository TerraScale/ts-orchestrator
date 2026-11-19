package plannedstop

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

const DrainWindow = 20 * time.Second
const EdgeShare = DrainWindow + 5*time.Second
const Limit = EdgeShare + 5*time.Second

type budgetKey struct{}

type budget struct {
	once      sync.Once
	ctx       context.Context
	cancel    context.CancelFunc
	started   chan struct{}
	abandoned sync.Map
}

func WithBudget(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Value(budgetKey{}).(*budget); ok {
		return ctx, func() {}
	}
	b := &budget{started: make(chan struct{})}
	return context.WithValue(ctx, budgetKey{}, b), func() {
		b.once.Do(func() {
			b.ctx, b.cancel = context.WithCancel(context.WithoutCancel(ctx))
			close(b.started)
		})
		b.cancel()
	}
}

func Started(ctx context.Context) <-chan struct{} {
	return ctx.Value(budgetKey{}).(*budget).started
}

func Begin(ctx context.Context) context.Context {
	b, ok := ctx.Value(budgetKey{}).(*budget)
	if !ok {
		panic("shutdown budget missing")
	}
	started := false
	b.once.Do(func() {
		b.ctx, b.cancel = context.WithTimeout(context.WithoutCancel(ctx), Limit)
		close(b.started)
		started = true
	})
	if started {
		slog.Info("node shutdown started", "deadline", deadline(b.ctx))
	}
	return b.ctx
}

func Share(ctx context.Context, share time.Duration) (context.Context, context.CancelFunc) {
	stop := Begin(ctx)
	end, ok := stop.Deadline()
	if !ok {
		return context.WithCancel(stop)
	}
	return context.WithDeadline(stop, end.Add(share-Limit))
}

func deadline(ctx context.Context) time.Time {
	value, _ := ctx.Deadline()
	return value
}

func Abandon(ctx context.Context, component string, err error) {
	b := ctx.Value(budgetKey{}).(*budget)
	if _, loaded := b.abandoned.LoadOrStore(component, struct{}{}); !loaded {
		slog.Warn("shutdown wait abandoned", "component", component, "error", err)
	}
}

func Join(ctx context.Context, component string, done <-chan struct{}) {
	select {
	case <-done:
	case <-ctx.Done():
		Wait(ctx, component, done)
	}
}

func Wait(ctx context.Context, component string, done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
	}
	stop := Begin(ctx)
	select {
	case <-done:
		return true
	case <-stop.Done():
		select {
		case <-done:
			return true
		default:
			Abandon(ctx, component, stop.Err())
			return false
		}
	}
}
