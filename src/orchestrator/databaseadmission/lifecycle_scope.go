package databaseadmission

import (
	"context"
	"terrascale.tech/orchestrator/src/orchestrator/databaselifecycle"
	"time"
)

func freezeEnvironmentInventory(state *journalState, environment, org string, start, end time.Time) (databaselifecycle.Snapshot, error) {
	if !environmentName.MatchString(environment) || end.After(time.Now()) {
		return databaselifecycle.Snapshot{}, ErrInvalid
	}
	if deletionBlocksFreeze(state, org, end) {
		return databaselifecycle.Snapshot{}, databaselifecycle.ErrIncomplete
	}
	snapshot, err := databaselifecycle.FreezeEnvironment(&state.Lifecycle, environment, org, start, end)
	if err != nil {
		return databaselifecycle.Snapshot{}, err
	}
	if err := validateReservedCapacity(*state); err != nil {
		return databaselifecycle.Snapshot{}, err
	}
	return snapshot, nil
}
func (journal *NATSJournal) FreezeEnvironmentInventory(ctx context.Context, environment, org string, start, end time.Time) (out databaselifecycle.Snapshot, err error) {
	if journal == nil || journal.journal == nil {
		return out, ErrJournalUnavailable
	}
	err = journal.journal.Transact(ctx, true, func(state *journalState) error {
		var inner error
		out, inner = freezeEnvironmentInventory(state, environment, org, start, end)
		return inner
	})
	if err != nil {
		return databaselifecycle.Snapshot{}, err
	}
	return out, nil
}
func (journal *MemoryJournal) FreezeEnvironmentInventory(ctx context.Context, environment, org string, start, end time.Time) (out databaselifecycle.Snapshot, err error) {
	err = journal.lifecycleTransact(ctx, func(state *journalState) error {
		var inner error
		out, inner = freezeEnvironmentInventory(state, environment, org, start, end)
		return inner
	})
	if err != nil {
		return databaselifecycle.Snapshot{}, err
	}
	return out, nil
}
