package swarmruntime

import (
	"context"
	"path/filepath"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/storage/execution"
)

type StatefulRuntimeGuard = execution.WorkerGuard

func verifyStatefulRuntimeGuard(guard StatefulRuntimeGuard, revision uint64, deadline time.Time) (time.Time, uint64, error) {
	return execution.VerifyWorkerGuard(guard, revision, deadline)
}

func (c *controller) statefulRuntimeGuard(ctx context.Context) (*StatefulRuntimeGuard, error) {
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
