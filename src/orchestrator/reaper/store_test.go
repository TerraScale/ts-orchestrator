package reaper

import (
	"context"
	"sync"
)

// MemoryStore is a small durable-store test double. It clones state at both
// boundaries, which catches accidental mutation after Save and is safe to use
// by concurrent test goroutines.
type MemoryStore struct {
	mu    sync.Mutex
	state State
	set   bool
}

func (s *MemoryStore) Load(ctx context.Context) (State, error) {
	if err := ctx.Err(); err != nil {
		return State{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.set {
		return State{Entries: make(map[string]Entry)}, nil
	}
	return cloneState(s.state), nil
}

func (s *MemoryStore) Save(ctx context.Context, state State) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	s.state, s.set = cloneState(state), true
	s.mu.Unlock()
	return nil
}

// Snapshot returns a copy for assertions and administrative inspection.
func (s *MemoryStore) Snapshot() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneState(s.state)
}

func cloneState(source State) State {
	result := State{Version: source.Version, Cursor: source.Cursor, Entries: make(map[string]Entry, len(source.Entries))}
	for id, sourceEntry := range source.Entries {
		entry := sourceEntry
		entry.Operations = make(map[string]Operation, len(sourceEntry.Operations))
		for key, operation := range sourceEntry.Operations {
			entry.Operations[key] = operation
		}
		entry.Audits = make(map[string]bool, len(sourceEntry.Audits))
		for key, audited := range sourceEntry.Audits {
			entry.Audits[key] = audited
		}
		result.Entries[id] = entry
	}
	return result
}
