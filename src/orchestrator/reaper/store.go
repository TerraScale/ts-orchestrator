package reaper

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
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

// FileStore persists only reaper metadata. Save uses a same-directory temp
// file, fsync, restrictive permissions, and rename, so a crash exposes either
// the old complete checkpoint or the new complete checkpoint.
type FileStore struct {
	Path string
	mu   sync.Mutex
}

func NewFileStore(path string) (*FileStore, error) {
	if filepath.Clean(path) == "." || path == "" {
		return nil, errors.New("reaper: state path is required")
	}
	return &FileStore{Path: path}, nil
}

func (s *FileStore) Load(ctx context.Context) (State, error) {
	if err := ctx.Err(); err != nil {
		return State{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	file, err := os.Open(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return State{Entries: make(map[string]Entry)}, nil
	}
	if err != nil {
		return State{}, err
	}
	defer file.Close()
	var state State
	if err := json.NewDecoder(file).Decode(&state); err != nil {
		if errors.Is(err, io.EOF) {
			return State{Entries: make(map[string]Entry)}, nil
		}
		return State{}, err
	}
	if state.Entries == nil {
		state.Entries = make(map[string]Entry)
	}
	return state, nil
}

func (s *FileStore) Save(ctx context.Context, state State) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if dir := filepath.Dir(s.Path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	temporary, err := os.CreateTemp(filepath.Dir(s.Path), ".reaper-state-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	keep := false
	defer func() {
		_ = temporary.Close()
		if !keep {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	encoder := json.NewEncoder(temporary)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(state); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, s.Path); err != nil {
		return err
	}
	keep = true
	// Syncing the directory makes the rename durable on filesystems that
	// otherwise acknowledge it before the directory entry reaches storage.
	directory, err := os.Open(filepath.Dir(s.Path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
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
