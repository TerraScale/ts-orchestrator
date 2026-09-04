package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/reconcile"
)

// dryRunFlag prints the plan and exits without applying. The add-region
// runbook (I-5) is this output; do not build add-region here.
const dryRunFlag = "--dry-run"

// reconcileInterval is the steady-state reconcile cadence. Drift is repaired
// within minutes, never on the reactive path.
const reconcileInterval = time.Minute

// runReconcile drives the observed estate to the declared estate (D-67).
// With --dry-run it prints the plan derived from an empty observation — the
// greenfield/bootstrap plan — and exits.
func runReconcile(ctx context.Context, args []string, output io.Writer) error {
	if len(args) == 2 && args[1] == dryRunFlag {
		return printReconcilePlan(output)
	}
	loop, err := reconcile.NewLoop(reconcile.LoopConfig{
		Spec:         estate.Default(),
		Interval:     reconcileInterval,
		AllowDeletes: true,
	})
	if err != nil {
		return err
	}
	return loop.Run(ctx)
}

// printReconcilePlan derives the plan against an empty observation: with no
// provider adapters wired (they land with I-2), the plan is everything the
// declared estate says must exist — the bootstrap and add-region runbook.
func printReconcilePlan(output io.Writer) error {
	if output == nil {
		return errors.New("reconcile: plan output is nil")
	}
	declared, err := reconcile.Declared(estate.Default())
	if err != nil {
		return err
	}
	plan, err := reconcile.Diff(declared, reconcile.State{})
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(struct {
		EstateVersion uint32             `json:"estateVersion"`
		Actions       []reconcile.Action `json:"actions"`
	}{
		EstateVersion: estate.SchemaVersion,
		Actions:       plan.Actions,
	})
}
