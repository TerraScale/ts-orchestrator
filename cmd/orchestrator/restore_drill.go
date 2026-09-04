package main

// Restore-drill composition is called by the production runtime lifecycle.
// Keeping this tiny adapter here makes the command's dependency boundary
// explicit without creating a second scheduler or provider path.

import "terrascale.tech/orchestrator/src/orchestrator/restoredrill"

// ComposeRestoreDrill is the command-level integration hook. It performs all
// fail-closed admission in restoredrill.NewProductionComposition and performs
// no provider or network calls itself.
func ComposeRestoreDrill(config restoredrill.ProductionConfig) (*restoredrill.ProductionComposition, error) {
	return restoredrill.NewProductionComposition(config)
}
