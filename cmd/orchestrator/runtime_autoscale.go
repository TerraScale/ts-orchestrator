package main

import (
	"context"
	"errors"
	"terrascale.tech/orchestrator/src/orchestrator/autoscale"
)

type sessionAuthority struct{ check func(context.Context) error }

func (a sessionAuthority) Check(ctx context.Context) error {
	if a.check == nil {
		return errors.New("autoscale: authority unavailable")
	}
	return a.check(ctx)
}

type productionAutoscale struct {
	controller *autoscale.Controller
	regions    []string
	apply      func(string, int) error
}

func (a *productionAutoscale) Reconcile(ctx context.Context) error {
	if a == nil || a.controller == nil || a.apply == nil {
		return errors.New("autoscale: runtime is unavailable")
	}
	for _, region := range a.regions {
		plan, created, err := a.controller.Evaluate(ctx, region)
		if err != nil {
			return err
		}
		if created {
			if err := a.apply(plan.Region, plan.DesiredMembers); err != nil {
				return err
			}
			continue
		}
		// Re-apply the durable target after restart (or takeover). The
		// authority journal is the source of truth; a new pressure sample is
		// not required to resume an already admitted capacity decision.
		target, found, err := a.controller.Target(ctx, region)
		if err != nil {
			return err
		}
		if found {
			if err := a.apply(target.Region, target.Members); err != nil {
				return err
			}
		}
	}
	return nil
}
