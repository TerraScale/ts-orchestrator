package reconcile

import (
	"context"

	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

// Reconciler is the provider seam of the reconcile loop (D-67): one
// implementation per provider domain (OCI compute, OCI storage, Cloudflare
// zone, ...), owning a disjoint set of estate resource kinds.
//
// Observe returns the currently observed resources of the owned kinds, in the
// normalized State form. For every owned kind, the observation must report
// the attribute names the Declared renderer documents for that kind; the loop
// diffs attribute multisets, so extra or renamed provider-native attributes
// read as drift.
//
// Apply drives the observed estate toward the plan. It receives the complete
// plan filtered to the kinds returned by Kinds, must be idempotent, and must
// tolerate re-entry after a partially applied plan: the loop re-observes
// after every apply and re-plans on the next pass.
type Reconciler interface {
	// Kinds names the estate resource kinds this reconciler owns.
	Kinds() []estate.ResourceKind
	// Observe reports the current state of the owned kinds.
	Observe(ctx context.Context) (State, error)
	// Apply drives the owned kinds toward the plan.
	Apply(ctx context.Context, plan Plan) error
}
