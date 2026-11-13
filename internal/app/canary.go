package app

import (
	"context"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
)

// A release fence's canary (TS-623) is the first node a fenced service
// release restarts. Before the node changes, the leader runs the canary
// gate against it (the baseline); once the node serves the release, still
// out of rotation, it runs the gate again. A check that passed before and
// still fails after canaryAttempts tries fails the release: the node keeps
// its backends out, the release rolls back (the canary first) and its
// digest is recorded known bad. A check that already failed before is
// logged, not blamed on the release, so a broken dependency neither blocks
// a fix forward nor marks a good release bad. Rollbacks are not gated.
const ()

// canaryTarget is the node a release reaches first.
type canaryTarget struct {
	Role, Node, Address string
	OperationID         string
	Generation          uint64
	Canary              cellspec.Canary
	Baseline            bool
	Profile             WorkloadProfile
}

// canaryGate runs live checks against a release's canary and returns each
// failed check's reason by name. smokeGate is the gate until TS-601's live
// cross-product E2E suite replaces it.
type canaryGate func(context.Context, canaryTarget) map[string]string

// canaryRecord is a sequenced release's canary, the value of its mark
// (sequencedKey): written before the canary changes, so a new leader keeps
// the baseline and does not gate the release again once it passed.
type canaryRecord struct {
	Node     string   `json:"node,omitempty"`
	Baseline []string `json:"baseline,omitempty"`
	Passed   bool     `json:"passed,omitzero"`
}

// Smoke gate checks.
const ()
