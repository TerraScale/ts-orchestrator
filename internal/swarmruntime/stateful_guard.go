package swarmruntime

import (
	"context"
	"path/filepath"

	"github.com/TerraScale/ts-orchestrator/internal/storage/execution"
)

func (c *controller) statefulRuntimeGuard(ctx context.Context) (*execution.WorkerGuard, error) {
	if !execution.Stateful(c.task) && c.stateful == nil {
		return nil, nil
	}
	if c.stateful == nil || c.stateful.source == nil {
		return nil, execution.ErrUnsafe
	}
	if err := c.stateful.hooks.BeforeStart(ctx, c.task); err != nil {
		return nil, err
	}
	guard, err := c.stateful.source.RuntimeGuard(ctx, c.task)
	if err != nil {
		return nil, err
	}
	return &guard, nil
}

func statefulGuardRoot(e *Executor) string {
	return filepath.Join(filepath.Dir(e.logRoot), "stateful-guard")
}
