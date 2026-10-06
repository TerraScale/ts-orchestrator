package ociresource

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
)

// Pass is one reconcile step run at an authority epoch: a Controller, or a
// publisher that refreshes desired state (for example NLB backends from
// placement) before the controllers run.
type Pass struct {
	Name string
	Run  func(ctx context.Context, epoch uint64) error
}

// ControllerPass adapts a Controller to a Pass.
func ControllerPass[S, O any](controller *Controller[S, O]) Pass {
	return Pass{Name: controller.Resource.Kind(), Run: func(ctx context.Context, epoch uint64) error {
		result, err := controller.Reconcile(ctx, epoch)
		if result.Observed > 0 {
			slog.Debug("OCI resources reconciled", "kind", controller.Resource.Kind(), "observed", result.Observed,
				"in_sync", result.InSync, "drifted", result.Drifted, "applied", result.Applied,
				"deleted", result.Deleted, "foreign", result.Foreign, "failed", result.Failed)
		}
		return err
	}}
}

// Runner runs passes on a jittered interval while this controller is the
// ready authority leader. Followers observe nothing and mutate nothing.
type Runner struct {
	Authority authority.Fencer
	Passes    []Pass
	Interval  time.Duration
	// Jitter returns a value in [0, 1) that spreads ticks across controllers.
	Jitter func() float64
	// Wake, when set, starts the next tick at once, for a caller that just
	// changed desired state it needs applied soon. Nil waits the interval.
	Wake <-chan struct{}
}

const defaultInterval = time.Minute

// Run blocks until ctx ends. A failing pass is logged and retried next tick;
// it never stops the other passes or the runner.
func (r Runner) Run(ctx context.Context) error {
	if r.Authority == nil || len(r.Passes) == 0 {
		return errors.New("OCI resource runner requires authority and at least one pass")
	}
	interval := r.Interval
	if interval <= 0 {
		interval = defaultInterval
	}
	for {
		r.Tick(ctx)
		delay := interval
		if r.Jitter != nil {
			delay += time.Duration(r.Jitter() * float64(interval) / 10)
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		case <-r.Wake:
			timer.Stop()
		}
	}
}

// Tick runs every pass once if this controller currently leads.
func (r Runner) Tick(ctx context.Context) {
	snapshot := r.Authority.Current()
	if !snapshot.Leader || !snapshot.Ready || snapshot.Epoch == 0 {
		return
	}
	for _, pass := range r.Passes {
		if ctx.Err() != nil {
			return
		}
		if err := pass.Run(ctx, snapshot.Epoch); err != nil {
			if errors.Is(err, ErrFenced) {
				slog.Warn("OCI resource reconcile lost authority", "pass", pass.Name, "error", err)
				return
			}
			slog.Warn("OCI resource reconcile pass failed", "pass", pass.Name, "error", err)
		}
	}
}
