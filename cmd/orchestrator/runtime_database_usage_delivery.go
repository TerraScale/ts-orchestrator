package main

import (
	"context"
	"errors"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/databaselifecycle"
)

type databaseUsageSource interface {
	List(context.Context) ([]databaseadmission.Record, error)
	LifecycleResources(context.Context) (uint64, []databaselifecycle.Resource, error)
}

// Database usage registration uses committed lifecycle authority. It cannot
// allocate a partition or infer a stream from a placement proposal.
func deliverDatabaseUsage(ctx context.Context, source databaseUsageSource, check func(context.Context) error, send func(context.Context, databaseadmission.Target, databaseadmission.UsageRegistration) error, record databaseadmission.Record, digest string) error {
	if source == nil || check == nil || send == nil {
		return errors.New("runtime usage: durable source and authenticated delivery required")
	}
	if err := check(ctx); err != nil {
		return err
	}
	records, err := source.List(ctx)
	if err != nil {
		return err
	}
	revision, resources, err := source.LifecycleResources(ctx)
	if err != nil {
		return err
	}
	plan, err := planDatabaseUsage(record, records, resources, digest, time.Now())
	if err != nil {
		return err
	}
	for _, delivery := range plan {
		if err := check(ctx); err != nil {
			return err
		}
		// Replanning on the next retry prevents continuing a batch after a
		// concurrent stream change or deletion. Registration itself never grants
		// serving authority; member activation still applies deletion fences.
		current, _, err := source.LifecycleResources(ctx)
		if err != nil {
			return err
		}
		if current != revision {
			return errors.New("runtime usage: lifecycle changed during delivery")
		}
		if err := send(ctx, delivery.Target, delivery.Registration); err != nil {
			return err
		}
	}
	return nil
}
