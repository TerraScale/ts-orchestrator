package vmqual

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type fixtureStoreRegistrarKey struct{}
type fixtureStoreRegistrar func(string) error

type fixtureStoreOwnership struct {
	RunID string `json:"runId"`
	Path  string `json:"path"`
}

// PrepareNATSFixtureStore records the cleanup obligation before creating the
// qualification transport's file store. It never adopts an existing directory.
func PrepareNATSFixtureStore(ctx context.Context, stateRoot, runID string) (string, error) {
	if ctx == nil || !CanonicalAbsolute(stateRoot) || stateRoot == "/" || !validRunID(runID) {
		return "", errors.New("vmqual: invalid fixture store identity")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	path := filepath.Join(stateRoot, "nats-fixture-"+runID)
	if err := mkdirAllNoSymlinks(stateRoot, 0700); err != nil {
		return "", err
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return "", errors.New("vmqual: fixture store path already exists or cannot be inspected")
	}
	if bound, ok := RunIDFromContext(ctx); ok {
		register, present := ctx.Value(fixtureStoreRegistrarKey{}).(fixtureStoreRegistrar)
		if bound != runID || !present {
			return "", errors.New("vmqual: fixture store requires matching cleanup journal")
		}
		if err := register(path); err != nil {
			return "", err
		}
	}
	if err := os.Mkdir(path, 0700); err != nil {
		return "", err
	}
	if err := SyncDirectory(stateRoot); err != nil {
		return "", err
	}
	if err := writeExclusiveJSON(filepath.Join(path, ".vmqual-owner.json"), fixtureStoreOwnership{runID, path}); err != nil {
		return "", err
	}
	return path, nil
}

func (s *Stack) fixtureStoreContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, fixtureStoreRegistrarKey{}, fixtureStoreRegistrar(func(path string) error {
		if s.config.JournalPath == "" {
			return errors.New("vmqual: fixture store cleanup journal is required")
		}
		return s.updateJournal(func(journal *Journal) error {
			if path != filepath.Join(journal.StateRoot, "nats-fixture-"+journal.RunID) || journal.NATSFixtureStore != "" {
				return errors.New("vmqual: fixture store cleanup identity conflicts")
			}
			journal.NATSFixtureStore = path
			return nil
		})
	}))
}

func cleanupNATSFixtureStore(journal Journal) error {
	path := journal.NATSFixtureStore
	if path == "" {
		return nil
	}
	if path != filepath.Join(journal.StateRoot, "nats-fixture-"+journal.RunID) {
		return errors.New("vmqual: fixture store escapes run ownership")
	}
	if err := mkdirAllNoSymlinks(journal.StateRoot, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return SyncDirectory(journal.StateRoot)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("vmqual: invalid fixture store directory")
	}
	var owner fixtureStoreOwnership
	err = readStrictJSONFile(filepath.Join(path, ".vmqual-owner.json"), &owner)
	if errors.Is(err, os.ErrNotExist) {
		// Before ownership publication, only the exclusive marker writer's
		// temporary file can exist. Never remove service data without a marker.
		entries, err := os.ReadDir(path)
		if err != nil {
			return err
		}
		if len(entries) > 1 {
			return errors.New("vmqual: unclaimed fixture store contains unexpected files")
		}
		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 1024 || !strings.HasPrefix(entry.Name(), ".vmqual-new-") || !strings.HasSuffix(entry.Name(), ".tmp") {
				return errors.New("vmqual: unclaimed fixture store contains unexpected files")
			}
			if err := RemoveFileAndSync(filepath.Join(path, entry.Name())); err != nil {
				return err
			}
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("vmqual: unclaimed fixture store is not empty: %w", err)
		}
		return SyncDirectory(journal.StateRoot)
	}
	if err != nil || owner.RunID != journal.RunID || owner.Path != path {
		return errors.New("vmqual: fixture store ownership mismatch")
	}
	return removeMarkedFixtureStore(path, (*os.Root).RemoveAll)
}

// RemoveNATSFixtureStore is called only after the fixture server has stopped.
// The marker survives interrupted child deletion so crash cleanup can resume.
func RemoveNATSFixtureStore(stateRoot, runID string) error {
	if !CanonicalAbsolute(stateRoot) || stateRoot == "/" || !validRunID(runID) {
		return errors.New("vmqual: invalid fixture store cleanup identity")
	}
	return cleanupNATSFixtureStore(Journal{StateRoot: stateRoot, RunID: runID, NATSFixtureStore: filepath.Join(stateRoot, "nats-fixture-"+runID)})
}

func removeMarkedFixtureStore(path string, removeChild func(*os.Root, string) error) error {
	root, err := os.OpenRoot(path)
	if err != nil {
		return err
	}
	defer root.Close()
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() == ".vmqual-owner.json" {
			continue
		}
		if err := removeChild(root, entry.Name()); err != nil {
			return err
		}
	}
	if err := dir.Sync(); err != nil {
		return err
	}
	if err := root.Remove(".vmqual-owner.json"); err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return SyncDirectory(filepath.Dir(path))
}

func (s *Stack) verifyFixtureStoreRemoved() error {
	s.journalMu.Lock()
	defer s.journalMu.Unlock()
	if s.journal == nil || s.journal.NATSFixtureStore == "" {
		return nil
	}
	if _, err := os.Lstat(s.journal.NATSFixtureStore); !errors.Is(err, os.ErrNotExist) {
		return errors.New("vmqual: fixture store remains after service shutdown")
	}
	return nil
}
