package foundation

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
)

// StoreLifecycle is the current source-sealed singleton and one-use genesis authority.
type StoreLifecycle interface {
	Check(context.Context) error
	RecoveryRequired() bool
	ClaimGenesis(context.Context) error
}

// PrepareStore runs under the supervisor snapshot lock before any upstream writer.
func PrepareStore(ctx context.Context, directory string, admission StoreLifecycle, destinations func(context.Context) ([2]BackupTarget, error)) error {
	if admission == nil || destinations == nil {
		return errors.New("NetBird store preparation requires current lifecycle and protected backup discovery")
	}
	if err := admission.Check(ctx); err != nil {
		return err
	}
	data := directory + "/data"
	info, err := os.Lstat(data)
	if err == nil {
		if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
			return errors.New("NetBird existing store directory is not protected")
		}
		if !admission.RecoveryRequired() {
			return errors.New("NetBird existing store has no consumed genesis or restore authority")
		}
		store, err := os.Lstat(filepath.Join(data, "store.db"))
		if err != nil || !store.Mode().IsRegular() {
			return errors.New("NetBird partial store requires authenticated recovery; refusing fresh genesis")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if !admission.RecoveryRequired() {
		if err := admission.ClaimGenesis(ctx); err != nil {
			return err
		}
		return os.MkdirAll(filepath.Join(data, "foundation-tls"), 0700)
	}
	targets, err := destinations(ctx)
	if err != nil {
		return err
	}
	var failures []error
	for _, target := range targets {
		latest, err := LatestBackup(ctx, target)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		stage, err := os.MkdirTemp(directory, ".recovery-*")
		if err != nil {
			return err
		}
		if err := os.Remove(stage); err != nil {
			return err
		}
		_, restoreErr := Restore(ctx, target, latest.Object, stage)
		if restoreErr == nil {
			restoreErr = admission.Check(ctx)
		}
		if restoreErr == nil {
			restoreErr = unix.Renameat2(unix.AT_FDCWD, filepath.Join(stage, "data"), unix.AT_FDCWD, data, unix.RENAME_NOREPLACE)
		}
		if restoreErr == nil {
			parent, err := os.Open(directory)
			if err != nil {
				restoreErr = err
			} else {
				restoreErr = errors.Join(parent.Sync(), parent.Close())
			}
		}
		cleanupErr := os.RemoveAll(stage)
		if restoreErr == nil {
			return cleanupErr
		}
		failures = append(failures, errors.Join(restoreErr, cleanupErr))
	}
	return errors.Join(append([]error{errors.New("NetBird store restoration requires an authenticated protected backup")}, failures...)...)
}
