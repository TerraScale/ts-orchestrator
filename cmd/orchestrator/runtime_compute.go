package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/lifecycle"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
)

// productionComputeWorker is the lease-owned mutation boundary for OCI
// compute. The callback is constructed with the already admitted controller;
// no standalone provider connection or journal is permitted.
type productionComputeWorker struct {
	service *lifecycle.Service
}

func newProductionOCIComputeWorker(
	session globalWorkerSession,
	journalBucket string,
	apply func(context.Context, provider.ProviderMutationJournal) error,
) (*productionComputeWorker, error) {
	if session.Connection == nil || apply == nil || journalBucket == "" {
		return nil, errors.New("runtime compute: lease session, journal bucket and apply callback are required")
	}
	js, err := jetstream.New(session.Connection)
	if err != nil {
		return nil, fmt.Errorf("runtime compute: provider journal jetstream: %w", err)
	}
	kv, err := js.KeyValue(context.Background(), journalBucket)
	if err != nil {
		return nil, fmt.Errorf("runtime compute: provider journal KV: %w", err)
	}
	stream, err := js.Stream(context.Background(), "KV_"+journalBucket)
	if err != nil {
		return nil, fmt.Errorf("runtime compute: provider journal stream: %w", err)
	}
	info, err := stream.Info(context.Background())
	if err != nil {
		return nil, fmt.Errorf("runtime compute: provider journal stream info: %w", err)
	}
	c := info.Config
	if c.Storage != jetstream.FileStorage || c.Replicas != 3 || c.MaxAge != 0 || c.MaxMsgsPerSubject != 1 || c.Mirror != nil || len(c.Sources) != 0 || !c.AllowRollup || !c.DenyDelete || c.DenyPurge || c.Discard != jetstream.DiscardNew {
		return nil, errors.New("runtime compute: provider journal is not an authoritative non-expiring R3 KV stream")
	}
	cas, err := provider.NewNatsOwnershipCASStore(kv)
	if err != nil {
		return nil, err
	}
	journal, err := provider.NewCASProviderMutationJournal(cas)
	if err != nil {
		return nil, err
	}
	worker := &productionComputeWorker{}
	worker.service = lifecycle.NewScheduledService("OCI compute", time.Minute, func(ctx context.Context, _ time.Time) error {
		if err := session.CheckEffectAuthority(ctx); err != nil {
			return err
		}
		return apply(ctx, journal)
	})
	return worker, nil
}
