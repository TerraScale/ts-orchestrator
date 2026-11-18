package handoff

import (
	"context"
	"sync"
	"sync/atomic"
)

type taskDrainer func(context.Context, string) error

var regionalDrainer atomic.Pointer[taskDrainer]
var regionalReady = make(chan struct{})
var regionalAttached sync.Once

func SetTaskDrainer(drain func(context.Context, string) error) {
	fn := taskDrainer(drain)
	regionalDrainer.Store(&fn)
	regionalAttached.Do(func() { close(regionalReady) })
}

func DrainTask(ctx context.Context, task string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-regionalReady:
	}
	drain := regionalDrainer.Load()
	return (*drain)(ctx, task)
}
