package ociresource

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// Authority is the mutation fence. The authority package's Fencer satisfies it.
// Guard must fail once epoch is no longer the current leader epoch.
type Authority interface {
	Guard(ctx context.Context, epoch uint64) error
}

// Controller reconciles every desired record of one kind in one region.
type Controller[S, O any] struct {
	Region    string
	Resource  Resource[S, O]
	Store     Store
	Ownership Ownership
	Authority Authority
	Now       func() time.Time
}

// Result summarizes one pass.
type Result struct {
	Observed, InSync, Drifted, Applied, Deleted, Foreign, Failed int
}

func (c *Controller[S, O]) now() time.Time {
	if c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
}

func (c *Controller[S, O]) validate() error {
	if c.Resource == nil || c.Store == nil || c.Authority == nil {
		return errors.New("OCI resource controller requires a resource, store, and authority")
	}
	if err := (Key{Region: c.Region, Kind: c.Resource.Kind(), Name: "x"}).Validate(); err != nil {
		return err
	}
	return c.Ownership.Validate()
}

// Reconcile runs one pass at authority epoch. Each record is handled
// independently: a failure is recorded in its status and does not stop the
// other records. Context and fencing errors abort the pass.
func (c *Controller[S, O]) Reconcile(ctx context.Context, epoch uint64) (Result, error) {
	if err := c.validate(); err != nil {
		return Result{}, err
	}
	records, err := c.Store.List(ctx, c.Region, c.Resource.Kind())
	if err != nil {
		return Result{}, err
	}
	var result Result
	var failures []error
	for _, desired := range records {
		status, err := c.reconcileOne(ctx, epoch, desired)
		result.Observed++
		switch {
		case status.Deleted:
			result.Deleted++
		case status.Foreign:
			result.Foreign++
		case status.InSync:
			result.InSync++
		default:
			result.Drifted++
		}
		if status.Applied {
			result.Applied++
		}
		if err != nil {
			result.Failed++
			status.Error = err.Error()
			if errors.Is(err, ErrFenced) || ctx.Err() != nil {
				return result, err
			}
			failures = append(failures, fmt.Errorf("%s: %w", desired.Key, err))
		}
		if !status.Deleted {
			if err := c.Store.PutStatus(ctx, status); err != nil {
				return result, err
			}
		}
	}
	return result, errors.Join(failures...)
}

func (c *Controller[S, O]) guard(ctx context.Context, epoch uint64) error {
	if err := c.Authority.Guard(ctx, epoch); err != nil {
		return fmt.Errorf("%w: %w", ErrFenced, err)
	}
	return nil
}

func (c *Controller[S, O]) reconcileOne(ctx context.Context, epoch uint64, desired Desired) (Status, error) {
	status := Status{Key: desired.Key, Generation: desired.Generation, SpecDigest: desired.SpecDigest, ObservedAt: c.now()}
	if desired.Key.Region != c.Region || desired.Key.Kind != c.Resource.Kind() {
		return status, errors.New("OCI desired record is outside this controller's scope")
	}
	var spec S
	if err := json.Unmarshal(desired.Spec, &spec, json.RejectUnknownMembers(true)); err != nil {
		return status, fmt.Errorf("decode OCI desired spec: %w", err)
	}
	target := Target[S]{Key: desired.Key, Generation: desired.Generation, SpecDigest: desired.SpecDigest,
		Ownership: c.Ownership, Spec: spec}
	observed, found, err := c.Resource.Observe(ctx, target)
	if errors.Is(err, ErrForeign) {
		// Never adopt, mutate, or delete an object this controller cannot prove
		// it owns; surface it for an operator instead.
		status.Found, status.Foreign = true, true
		slog.Warn("withholding foreign OCI resource", "key", desired.Key.String())
		return status, nil
	}
	if err != nil {
		return status, fmt.Errorf("observe: %w", err)
	}
	status.Found = found

	if desired.Tombstone != nil {
		return c.deleteOne(ctx, epoch, desired, target, observed, found, status)
	}

	plan := c.Resource.Diff(target, observed, found)
	status.Drift = plan.Changes
	status.InSync = plan.Empty()
	if plan.Empty() || desired.Policy != PolicyEnforce {
		if !plan.Empty() {
			slog.Info("OCI resource drift reported", "key", desired.Key.String(), "plan", plan.String())
		}
		return status, nil
	}
	if err := c.guard(ctx, epoch); err != nil {
		return status, err
	}
	if err := c.Resource.Apply(ctx, target, observed, found, plan); err != nil {
		return status, fmt.Errorf("apply: %w", err)
	}
	status.Applied = true
	slog.Info("OCI resource drift corrected", "key", desired.Key.String(), "plan", plan.String())
	return status, nil
}

func (c *Controller[S, O]) deleteOne(ctx context.Context, epoch uint64, desired Desired, target Target[S], observed O,
	found bool, status Status,
) (Status, error) {
	if c.now().Before(desired.Tombstone.NotBefore) {
		status.Drift = []Change{{Op: "delete", Detail: "waiting for tombstone not-before " + desired.Tombstone.NotBefore.Format(time.RFC3339)}}
		return status, nil
	}
	if err := c.guard(ctx, epoch); err != nil {
		return status, err
	}
	if found {
		if err := c.Resource.Delete(ctx, target, observed); err != nil {
			return status, fmt.Errorf("delete: %w", err)
		}
		status.Applied = true
		// Re-observe on the next pass before purging, so a delete whose
		// response was lost is confirmed rather than assumed.
		status.Drift = []Change{{Op: "delete", Detail: "awaiting confirmation"}}
		return status, nil
	}
	if err := c.Store.Purge(ctx, desired); err != nil {
		return status, fmt.Errorf("purge desired record: %w", err)
	}
	status.Deleted = true
	return status, nil
}
