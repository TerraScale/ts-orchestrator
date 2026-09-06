package databaseadmission

import (
	"context"
	"encoding/json/v2"
	"sync"
)

// MemoryJournal is a process-local journal for tests. Production admission must
// use NATSJournal so accepted intent survives restart and authority failover.
type MemoryJournal struct {
	mutex sync.Mutex
	state journalState
}

func NewMemoryJournal() *MemoryJournal {
	return &MemoryJournal{state: newJournalState()}
}
func cloneState(state journalState) (journalState, error) {
	data, err := json.Marshal(state)
	if err != nil {
		return journalState{}, err
	}
	var cloned journalState
	err = json.Unmarshal(data, &cloned)
	return cloned, err
}
func (journal *MemoryJournal) snapshot(ctx context.Context) (journalState, error) {
	if ctx == nil {
		return journalState{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return journalState{}, err
	}
	journal.mutex.Lock()
	defer journal.mutex.Unlock()
	return cloneState(journal.state)
}
func (journal *MemoryJournal) Load(ctx context.Context, key string) (Record, bool, error) {
	state, err := journal.snapshot(ctx)
	if err != nil {
		return Record{}, false, err
	}
	record, found := state.Records[key]
	return record, found, nil
}
func (journal *MemoryJournal) List(ctx context.Context) ([]Record, error) {
	state, err := journal.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	records := make([]Record, 0, len(state.Records))
	for _, record := range state.Records {
		records = append(records, record)
	}
	return records, nil
}
func (journal *MemoryJournal) Save(ctx context.Context, key string, expected uint64, record Record) (uint64, error) {
	if ctx == nil {
		return 0, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	journal.mutex.Lock()
	defer journal.mutex.Unlock()
	state, err := cloneState(journal.state)
	if err != nil {
		return 0, err
	}
	if state.Records == nil {
		state.Records = map[string]Record{}
	}
	revision, err := saveRecord(&state, key, expected, record)
	if err != nil {
		return 0, err
	}
	state, err = cloneState(state)
	if err != nil {
		return 0, err
	}
	journal.state = state
	return revision, nil
}

var _ Journal = (*MemoryJournal)(nil)
