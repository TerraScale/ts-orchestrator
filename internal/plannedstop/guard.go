package plannedstop

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

type key struct{}

type guard struct {
	mu      sync.Mutex
	prepare func(context.Context) error
}

func withGuard(ctx context.Context) context.Context {
	return context.WithValue(ctx, key{}, &guard{})
}

func Register(ctx context.Context, prepare func(context.Context) error) {
	if guard, ok := ctx.Value(key{}).(*guard); ok {
		guard.mu.Lock()
		guard.prepare = prepare
		guard.mu.Unlock()
	}
}

func prepare(ctx context.Context) error {
	guard, ok := ctx.Value(key{}).(*guard)
	if !ok {
		return nil
	}
	guard.mu.Lock()
	prepare := guard.prepare
	guard.mu.Unlock()
	if prepare == nil {
		return nil
	}
	return prepare(ctx)
}

func NotifyContext(parent context.Context) (context.Context, context.CancelFunc) {
	parent = withGuard(parent)
	signalContext, stopSignals := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(parent)
	stopForwarding := context.AfterFunc(signalContext, func() {
		stopSignals()
		if err := prepare(ctx); err != nil {
			slog.Warn("planned stop refused; still serving until a second signal or the service manager forces termination", "error", err)
			return
		}
		cancel()
	})
	return ctx, func() {
		stopForwarding()
		stopSignals()
		cancel()
	}
}
