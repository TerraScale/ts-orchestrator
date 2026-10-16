// Package ociresource is the declarative OCI reconcile framework for regional
// resources other than member hosts and their data volumes (which keep the
// journaled internal/oci fleet).
//
// Desired state is a signed-off spec stored in the replicated NATS KV bucket
// TS_OCI_DESIRED. A Controller observes each desired resource, diffs it
// against OCI, records drift in TS_OCI_OBSERVED, and, under the enforce
// policy and only while the caller still holds mutation authority, applies
// the plan. Ownership is proved by tags on the OCI resource (freeform today,
// or a defined-tag namespace when configured); a resource without matching
// ownership is foreign and is never mutated or deleted. Deletion is two-phase:
// the desired record is tombstoned first, and the controller deletes the
// owned cloud resource only after the tombstone's not-before instant, then
// purges the record with a compare-and-set.
package ociresource

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

var tokenPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// Key names one desired resource: a catalog cell, a resource kind, and a
// logical name unique within the kind.
type Key struct {
	Region string `json:"region"`
	Kind   string `json:"kind"`
	Name   string `json:"name"`
}

// Validate requires a catalog cell and DNS-label kind and name tokens.
func (k Key) Validate() error {
	if !catalog.IsCell(k.Region) || !tokenPattern.MatchString(k.Kind) || !tokenPattern.MatchString(k.Name) {
		return fmt.Errorf("OCI resource key %q is invalid", k.String())
	}
	return nil
}

// String is the stable resource key used in ownership tags.
func (k Key) String() string { return k.Region + "/" + k.Kind + "/" + k.Name }

// subject is the NATS KV key. Every token is restricted to [A-Za-z0-9-].
func (k Key) subject() string { return k.Region + "." + k.Kind + "." + k.Name }

// DriftPolicy decides what a controller does with a non-empty plan.
type DriftPolicy string

const (
	// PolicyEnforce applies the plan to converge OCI to the desired spec.
	PolicyEnforce DriftPolicy = "enforce"
)

func (p DriftPolicy) valid() bool { return p == PolicyEnforce }

// Change is one human-readable step of a plan.
type Change struct {
	Op     string `json:"op"`
	Detail string `json:"detail"`
}

// Plan is the difference between desired and observed state. An empty plan
// means the resource is in sync.
type Plan struct {
	Changes []Change `json:"changes,omitempty"`
}

// Empty reports whether there is no drift.
func (p Plan) Empty() bool { return len(p.Changes) == 0 }

// Add appends one change.
func (p *Plan) Add(op, format string, args ...any) {
	p.Changes = append(p.Changes, Change{Op: op, Detail: fmt.Sprintf(format, args...)})
}

func (p Plan) String() string {
	parts := make([]string, 0, len(p.Changes))
	for _, change := range p.Changes {
		parts = append(parts, change.Op+" "+change.Detail)
	}
	return strings.Join(parts, "; ")
}

// Target is what a Resource is asked to act on: the key, the ownership proof
// it must stamp or check, and the decoded spec.
type Target[S any] struct {
	Key        Key
	Generation uint64
	SpecDigest string
	Ownership  Ownership
	Spec       S
	// OperationID is durable before Apply/Delete and retained until OCI
	// observation confirms convergence, including after a leader restart.
	OperationID string
	// Deleting is set when the desired record is tombstoned. A resource that
	// is part of a larger object (rules of an NSG, backends of an NLB) reports
	// found=false once none of its managed parts remain.
	Deleting bool
	// Guard re-checks mutation authority. The controller sets it; Apply and
	// Delete call Fence before every individual mutation, so a controller
	// that loses leadership mid-pass stops instead of finishing its plan.
	Guard func(context.Context) error
}

// Fence re-checks mutation authority immediately before one mutation.
func (t Target[S]) Fence(ctx context.Context) error {
	if t.Guard == nil {
		return ErrFenced
	}
	return t.Guard(ctx)
}

// Resource is one reconcilable OCI resource kind.
//
// Observe must return ErrForeign when the cloud object exists but does not
// carry the target's ownership tags, and found=false when it does not exist.
// Diff must be pure. Apply and Delete run only after the controller has
// checked authority and ownership; they must be idempotent because a lost
// response is retried on the next pass.
type Resource[S, O any] interface {
	Kind() string
	Observe(ctx context.Context, target Target[S]) (observed O, found bool, err error)
	Diff(target Target[S], observed O, found bool) Plan
	Apply(ctx context.Context, target Target[S], observed O, found bool, plan Plan) error
	Delete(ctx context.Context, target Target[S], observed O) error
}

var (
	// ErrForeign marks a cloud object that exists without matching ownership.
	ErrForeign = errors.New("OCI resource is not owned by this controller")
	// ErrFenced marks a mutation refused because authority was lost.
	ErrFenced = errors.New("OCI resource mutation authority was fenced")
	// ErrGone marks a cloud object that OCI reports as not found (404). A
	// tombstoned record whose containing object is gone has nothing left to
	// delete, so reconcilers report found=false and the record is purged.
	ErrGone = errors.New("OCI resource does not exist")
	// ErrWorkRequestFailed marks a terminal failed mutation. Its effects are
	// observed before any new operation; transient polling errors retain it.
	ErrWorkRequestFailed = errors.New("OCI work request failed")
)
