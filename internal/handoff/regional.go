package handoff

import (
	"context"
	"sync"
	"sync/atomic"
)

type taskDrainer func(context.Context, string) error

type RegionalDrain struct {
	drainer  atomic.Pointer[taskDrainer]
	ready    chan struct{}
	attached sync.Once
}

func NewRegionalDrain() *RegionalDrain {
	return &RegionalDrain{ready: make(chan struct{})}
}

func (d *RegionalDrain) SetTaskDrainer(drain func(context.Context, string) error) {
	fn := taskDrainer(drain)
	d.drainer.Store(&fn)
	d.attached.Do(func() { close(d.ready) })
}

func (d *RegionalDrain) DrainTask(ctx context.Context, task string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-d.ready:
	}
	drain := d.drainer.Load()
	return (*drain)(ctx, task)
}
