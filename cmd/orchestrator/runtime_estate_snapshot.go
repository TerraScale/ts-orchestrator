package main

import (
	"context"
	"errors"

	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/estatepublisher"
)

// deferredProductionEstateSnapshot binds the estate observation to the
// database owner that the composition root creates after the publisher. The
// closure therefore cannot observe a second journal or fabricate inventory
// while the database owner is absent.
func deferredProductionEstateSnapshot(spec estate.Spec, healthFile string, database **productionDatabase) estatepublisher.SnapshotSource {
	return func(ctx context.Context) (estate.Snapshot, error) {
		if database == nil || *database == nil || (*database).lifecycleJournal == nil {
			return estate.Snapshot{}, errors.New("production estate: admitted database journal is unavailable")
		}
		source, err := constructProductionEstateSource(spec, healthFile, (*database).currentJournal)
		if err != nil {
			return estate.Snapshot{}, err
		}
		return source.Snapshot(ctx)
	}
}
