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
	// remove hands the retained target intent to the placement/removal owner.
	// It is deliberately separate from apply: OCI target projection rejects
	// decreases until the durable drain workflow has completed.
	remove func(context.Context, autoscale.Plan) error
}

// Hydrate restores admitted targets without depending on fresh telemetry.
func (a *productionAutoscale) Hydrate(ctx context.Context) error {
	if a == nil || a.controller == nil || a.apply == nil {
		return errors.New("autoscale: runtime is unavailable")
	}
	for _, region := range a.regions {
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

func (a *productionAutoscale) Reconcile(ctx context.Context) error {
	if err := a.Hydrate(ctx); err != nil {
		return err
	}
	for _, region := range a.regions {
		plan, created, err := a.controller.Evaluate(ctx, region)
		if err != nil {
			return err
		}
		if created {
			if plan.RemovalPhase != "" {
				if a.remove == nil {
					return errors.New("autoscale: scale-down removal owner is unavailable")
				}
				if err := a.remove(ctx, plan); err != nil {
					return err
				}
			} else {
				if err := a.apply(plan.Region, plan.DesiredMembers); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
