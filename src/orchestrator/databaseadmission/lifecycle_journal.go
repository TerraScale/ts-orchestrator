package databaseadmission

import (
	"cmp"
	"context"
	"slices"
	"terrascale.tech/orchestrator/src/orchestrator/databaselifecycle"
	"time"
)

type LifecycleJournal interface {
	ApplyLifecycle(context.Context, databaselifecycle.Event) error
	FreezeInventory(context.Context, string, time.Time, time.Time) (databaselifecycle.Snapshot, error)
	LifecycleResources(context.Context) (uint64, []databaselifecycle.Resource, error)
}

func (journal *NATSJournal) ApplyLifecycle(ctx context.Context, event databaselifecycle.Event) error {
	if journal == nil || journal.journal == nil {
		return ErrJournalUnavailable
	}
	// Database creates must enter through admission and its immutable placement.
	if event.Kind == "create" {
		return ErrInvalid
	}
	return journal.journal.Transact(ctx, true, func(state *journalState) error { return databaselifecycle.Apply(&state.Lifecycle, event) })
}
func (journal *NATSJournal) FreezeInventory(ctx context.Context, org string, start, end time.Time) (out databaselifecycle.Snapshot, err error) {
	if journal == nil || journal.journal == nil {
		return out, ErrJournalUnavailable
	}
	if end.After(time.Now()) {
		return out, ErrInvalid
	}
	err = journal.journal.Transact(ctx, true, func(state *journalState) error {
		var inner error
		out, inner = databaselifecycle.Freeze(&state.Lifecycle, org, start, end)
		return inner
	})
	if err != nil {
		return databaselifecycle.Snapshot{}, err
	}
	return out, nil
}
func lifecycleResources(state journalState) (uint64, []databaselifecycle.Resource, error) {
	out := make([]databaselifecycle.Resource, 0, len(state.Lifecycle.Resources))
	for _, r := range state.Lifecycle.Resources {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b databaselifecycle.Resource) int {
		return cmp.Compare(databaselifecycle.Key(a.Identity), databaselifecycle.Key(b.Identity))
	})
	return state.Lifecycle.Revision, out, nil
}
func (journal *NATSJournal) LifecycleResources(ctx context.Context) (revision uint64, out []databaselifecycle.Resource, err error) {
	if journal == nil || journal.journal == nil {
		return 0, nil, ErrJournalUnavailable
	}
	err = journal.journal.Transact(ctx, false, func(state *journalState) error { revision, out, _ = lifecycleResources(*state); return nil })
	if err != nil {
		return 0, nil, err
	}
	return revision, out, nil
}
func (journal *MemoryJournal) lifecycleTransact(ctx context.Context, action func(*journalState) error) error {
	if ctx == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	journal.mutex.Lock()
	defer journal.mutex.Unlock()
	state, err := cloneState(journal.state)
	if err != nil {
		return err
	}
	if err = action(&state); err != nil {
		return err
	}
	state, err = cloneState(state)
	if err != nil {
		return err
	}
	journal.state = state
	return nil
}
func (journal *MemoryJournal) ApplyLifecycle(ctx context.Context, event databaselifecycle.Event) error {
	if event.Kind == "create" {
		return ErrInvalid
	}
	return journal.lifecycleTransact(ctx, func(state *journalState) error { return databaselifecycle.Apply(&state.Lifecycle, event) })
}
func (journal *MemoryJournal) FreezeInventory(ctx context.Context, org string, start, end time.Time) (out databaselifecycle.Snapshot, err error) {
	if end.After(time.Now()) {
		return out, ErrInvalid
	}
	err = journal.lifecycleTransact(ctx, func(state *journalState) error {
		var inner error
		out, inner = databaselifecycle.Freeze(&state.Lifecycle, org, start, end)
		return inner
	})
	if err != nil {
		return databaselifecycle.Snapshot{}, err
	}
	return out, nil
}
func (journal *MemoryJournal) LifecycleResources(ctx context.Context) (uint64, []databaselifecycle.Resource, error) {
	state, err := journal.snapshot(ctx)
	if err != nil {
		return 0, nil, err
	}
	return lifecycleResources(state)
}

var _ LifecycleJournal = (*NATSJournal)(nil)
var _ LifecycleJournal = (*MemoryJournal)(nil)
