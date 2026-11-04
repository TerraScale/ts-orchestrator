package host

import (
	"context"
)

type wanObserveRunner struct {
	Runner
	observe func(context.Context, string) (Observation, error)
}

func (r *wanObserveRunner) Observe(ctx context.Context, role string) (Observation, error) {
	return r.observe(ctx, role)
}
