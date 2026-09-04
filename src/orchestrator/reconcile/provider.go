package reconcile

import (
	"context"
	"errors"

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

// ApplyWithKey is an optional extension implemented by providers whose API
// supports idempotency keys. The key is stable across retries and process
// restarts for one logical plan, so an uncertain provider response can be
// safely replayed only when the provider itself guarantees idempotency.
type ApplyWithKey interface {
	ApplyWithKey(ctx context.Context, key string, plan Plan) error
}

// DeleteAuthorizer is an optional ownership boundary. Providers should use it
// to re-check ownership immediately before a destructive request. Returning
// an error fails closed and no delete is submitted.
type DeleteAuthorizer interface {
	AuthorizeDelete(ctx context.Context, action Action) error
}

// RetryableError is an optional provider classification. Unclassified errors
// are retried only when LoopConfig explicitly enables retries; context errors
// and unknown outcomes are never retried.
type RetryableError interface{ Retryable() bool }

// UnknownOutcomeError marks a request whose result cannot be proven (for
// example a lost work-request poll). It is deliberately terminal, especially
// for deletes, until a fresh observation resolves it.
type UnknownOutcomeError struct{ Err error }

func (e *UnknownOutcomeError) Error() string {
	if e == nil || e.Err == nil {
		return "reconcile: provider outcome is unknown"
	}
	return "reconcile: provider outcome is unknown: " + e.Err.Error()
}
func (e *UnknownOutcomeError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}
func IsUnknownOutcome(err error) bool {
	var unknown *UnknownOutcomeError
	return errors.As(err, &unknown)
}
