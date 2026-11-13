package handoff

import (
	"context"
	"errors"
	"sync/atomic"
)

type taskDrainer func(context.Context, string) error

var regionalDrainer atomic.Pointer[taskDrainer]

// SetTaskDrainer attaches this host's authenticated regional drain exchange.
func SetTaskDrainer(drain func(context.Context, string) error) {
	fn := taskDrainer(drain)
	regionalDrainer.Store(&fn)
}

// DrainTask returns only after ingress has drained the task and proven its peer.
// Losing the mesh never authorizes a stop.
func DrainTask(ctx context.Context, task string) error {
	drain := regionalDrainer.Load()
	if drain == nil {
		return errors.New("regional TerraBase drain is unavailable")
	}
	return (*drain)(ctx, task)
}

var regionalPeerProbe atomic.Pointer[taskDrainer]

func SetTaskPeerProbe(probe func(context.Context, string) error) {
	fn := taskDrainer(probe)
	regionalPeerProbe.Store(&fn)
}

func TaskPeerReady(ctx context.Context, task string) error {
	probe := regionalPeerProbe.Load()
	if probe == nil {
		return errors.New("regional task peer readiness is unavailable")
	}
	return (*probe)(ctx, task)
}
