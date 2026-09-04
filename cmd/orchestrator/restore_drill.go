package main

// Restore-drill command composition is intentionally separate from command
// registration. The parent command dispatcher can call ComposeRestoreDrill
// when its CLI surface is ready without creating a second production path.

import (
	"context"
	"errors"

	"terrascale.tech/orchestrator/src/orchestrator/restoredrill"
)

// ComposeRestoreDrill is the command-level integration hook. It performs all
// fail-closed admission in restoredrill.NewProductionComposition and performs
// no provider or network calls itself.
func ComposeRestoreDrill(config restoredrill.ProductionConfig) (*restoredrill.ProductionComposition, error) {
	return restoredrill.NewProductionComposition(config)
}

// RunRestoreDrill starts the daily scheduler. A scheduler callback records
// failures and pages through the composed drill; returning from Start means
// the scheduler context was cancelled or its own timing boundary failed.
func RunRestoreDrill(ctx context.Context, config restoredrill.ProductionConfig) error {
	if ctx == nil {
		return errors.New("restore drill: context is required")
	}
	composition, err := ComposeRestoreDrill(config)
	if err != nil {
		return err
	}
	return composition.Drill.Start(ctx)
}

// Lowercase aliases keep the hook convenient for the package's existing
// command tests while the exported functions are available to parent wiring.
func composeRestoreDrill(config restoredrill.ProductionConfig) (*restoredrill.ProductionComposition, error) {
	return ComposeRestoreDrill(config)
}

func runRestoreDrill(ctx context.Context, config restoredrill.ProductionConfig) error {
	return RunRestoreDrill(ctx, config)
}
