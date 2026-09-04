package security

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

// FileStateStore is the restart persistence adapter for rotation state. It
// uses a same-directory temporary file followed by rename, so a crash cannot
// leave a partially-written journal. PersistedState contains references and
// IDs only; this adapter has no API that can write secret bytes.
type FileStateStore struct {
	path string
	mu   sync.Mutex
}

func NewFileStateStore(path string) (*FileStateStore, error) {
	if path == "" || filepath.IsAbs(path) && filepath.Clean(path) == string(filepath.Separator) {
		return nil, errors.New("security: state path is required")
	}
	return &FileStateStore{path: filepath.Clean(path)}, nil
}

// JSONStateStore is a descriptive compatibility alias.
type JSONStateStore = FileStateStore

func (s *FileStateStore) Load(ctx context.Context) (PersistedState, error) {
	if s == nil || s.path == "" {
		return PersistedState{}, ErrNoState
	}
	if err := ctx.Err(); err != nil {
		return PersistedState{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return PersistedState{}, ErrNoState
	}
	if err != nil {
		return PersistedState{}, errors.New("security: state read failed")
	}
	var state PersistedState
	if err := json.Unmarshal(data, &state); err != nil {
		return PersistedState{}, errors.New("security: state decode failed")
	}
	return state, nil
}

func (s *FileStateStore) Save(ctx context.Context, state PersistedState) error {
	if s == nil || s.path == "" {
		return errors.New("security: state path is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	data, err := json.Marshal(state)
	if err != nil {
		return errors.New("security: state encode failed")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return errors.New("security: state directory unavailable")
	}
	tmp, err := os.CreateTemp(dir, ".rotation-state-*")
	if err != nil {
		return errors.New("security: state temporary file unavailable")
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return errors.New("security: state permissions failed")
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return errors.New("security: state write failed")
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return errors.New("security: state sync failed")
	}
	if err := tmp.Close(); err != nil {
		return errors.New("security: state close failed")
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return errors.New("security: state commit failed")
	}
	return nil
}
