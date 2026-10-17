package foundation

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type testStoreLifecycle struct {
	recovery bool
	genesis  int
	denied   error
}

func (s *testStoreLifecycle) Check(context.Context) error { return s.denied }
func (s *testStoreLifecycle) RecoveryRequired() bool      { return s.recovery }
func (s *testStoreLifecycle) ClaimGenesis(context.Context) error {
	s.genesis++
	s.recovery = true
	return nil
}

func TestPrepareStoreNeverInfersGenesisFromMissingBackup(t *testing.T) {
	for _, scenario := range []string{"authorized-genesis", "required-restore", "authority-lost", "partial-local-store"} {
		t.Run(scenario, func(t *testing.T) {
			directory := t.TempDir()
			source := &testStoreLifecycle{recovery: scenario != "authorized-genesis"}
			if scenario == "authority-lost" {
				source.denied = context.Canceled
			}
			if scenario == "partial-local-store" {
				if err := os.Mkdir(filepath.Join(directory, "data"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			err := PrepareStore(t.Context(), directory, source, func(context.Context) ([2]BackupTarget, error) { return [2]BackupTarget{}, ErrNoBackup })
			if scenario == "authorized-genesis" {
				if err != nil || source.genesis != 1 {
					t.Fatalf("signed genesis failed: %v", err)
				}
				if info, err := os.Stat(filepath.Join(directory, "data", "foundation-tls")); err != nil || info.Mode().Perm() != 0700 {
					t.Fatal("genesis data directory not protected")
				}
			} else {
				if err == nil || source.genesis != 0 {
					t.Fatalf("missing backup inferred genesis: claims=%d error=%v", source.genesis, err)
				}
				if scenario == "required-restore" && !errors.Is(err, ErrNoBackup) {
					t.Fatalf("backup error hidden: %v", err)
				}
			}
		})
	}
}
