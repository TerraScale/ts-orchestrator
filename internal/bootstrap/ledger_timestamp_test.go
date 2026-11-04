package bootstrap

import (
	"context"
	"sync"
	"sync/atomic"
)

type cancelAtHelperContext struct {
	context.Context
	calls atomic.Int32
	once  sync.Once
	done  chan struct{}
}

func (ctx *cancelAtHelperContext) Err() error {
	if ctx.calls.Add(1) < 2 {
		return nil
	}
	ctx.once.Do(func() { close(ctx.done) })
	return context.Canceled
}

func (ctx *cancelAtHelperContext) Done() <-chan struct{} {
	return ctx.done
}
