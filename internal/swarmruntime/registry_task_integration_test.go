package swarmruntime

import (
	"context"

	"github.com/moby/swarmkit/v2/agent/exec"
	"github.com/moby/swarmkit/v2/api"
)

// The new revision remains in Prepare while the real upstream manager retains
// its old assignment during the start-first update.
type registryAssignmentExecutor struct {
	serviceExecutor
	shutdown <-chan struct{}
}

func (e registryAssignmentExecutor) Controller(task *api.Task) (exec.Controller, error) {
	spec, err := DecodeContainer(task)
	if err != nil {
		return nil, err
	}
	if len(spec.Args) > 0 && spec.Args[0] == "pending" {
		return &registryPendingController{serviceController: serviceController{done: make(chan struct{})}}, nil
	}
	controller, err := e.serviceExecutor.Controller(task)
	if err != nil || e.shutdown == nil {
		return controller, err
	}
	return &registryStoppingController{serviceController: controller.(*serviceController), shutdown: e.shutdown}, nil
}

type registryStoppingController struct {
	*serviceController
	shutdown <-chan struct{}
}

func (c *registryStoppingController) Shutdown(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.shutdown:
		return c.serviceController.Shutdown(ctx)
	}
}

func (c *registryStoppingController) Terminate(ctx context.Context) error { return c.Shutdown(ctx) }

type registryPendingController struct{ serviceController }

func (*registryPendingController) Prepare(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
