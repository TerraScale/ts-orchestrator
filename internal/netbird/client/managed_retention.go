package client

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// The watchdog is ts-orch, whose release artifact bound is 512 MiB.
const maxRollbackExecutableBytes int64 = 512 << 20

func (m managedClient) rollbackExecutable(transaction managedTransaction) string {
	return filepath.Join(m.backupDirectory(transaction), "rollback-"+transaction.RollbackSHA256)
}

func (m managedClient) rollbackExecutableReady(transaction managedTransaction) error {
	if _, err := secureManagedDirectory(m.root, managedDirectory+"/transactions/"+transaction.TransactionID, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(m.rollbackExecutable(transaction))
	if err != nil || !SHA256Pattern.MatchString(transaction.RollbackSHA256) || !info.Mode().IsRegular() ||
		info.Mode().Perm() != 0700 || info.Size() < 64 || info.Size() > maxRollbackExecutableBytes {
		return errors.New("retained NetBird rollback executable is not ready")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("retained NetBird rollback executable has an unexpected owner")
	}
	return nil
}

func (m managedClient) retainRollbackExecutable(ctx context.Context, transaction *managedTransaction) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if transaction.RollbackSHA256 != "" {
		return m.rollbackExecutableReady(*transaction)
	}
	if _, err := secureManagedDirectory(m.root, managedDirectory+"/transactions/"+transaction.TransactionID, 0700); err != nil {
		return err
	}
	flags := syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NONBLOCK | syscall.O_NOFOLLOW
	// This kernel-owned link opens the executing inode even after its release
	// directory is pruned. All ordinary sources must remain direct files.
	if m.executable == "/proc/self/exe" {
		flags &^= syscall.O_NOFOLLOW
	}
	fd, err := syscall.Open(m.executable, flags, 0)
	if err != nil {
		return errors.New("cannot open executing NetBird rollback binary")
	}
	source := os.NewFile(uintptr(fd), m.executable)
	defer source.Close()
	info, err := source.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0111 == 0 ||
		info.Size() < 64 || info.Size() > maxRollbackExecutableBytes {
		return errors.New("NetBird rollback source must be a bounded protected executable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("NetBird rollback source has an unexpected owner")
	}
	copy, err := os.CreateTemp(m.backupDirectory(*transaction), ".rollback-")
	if err != nil {
		return err
	}
	defer os.Remove(copy.Name())
	defer copy.Close()
	hash := sha256.New()
	size, err := io.Copy(io.MultiWriter(copy, hash), io.LimitReader(source, maxRollbackExecutableBytes+1))
	if err != nil || size != info.Size() || size > maxRollbackExecutableBytes {
		return errors.New("cannot retain bounded NetBird rollback executable")
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	if err := verifyBinaryLimit(copy.Name(), digest, transaction.Architecture, maxRollbackExecutableBytes); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := copy.Chmod(0700); err != nil {
		return err
	}
	if err := errors.Join(copy.Sync(), copy.Close()); err != nil {
		return err
	}
	next := *transaction
	next.RollbackSHA256 = digest
	if err := os.Rename(copy.Name(), m.rollbackExecutable(next)); err != nil {
		return err
	}
	if err := syncManagedDirectory(m.backupDirectory(next)); err != nil {
		return err
	}
	// Snapshot files sync their directory; persist its entry in transactions/
	// too before pending.json can make this the sole rollback history.
	if err := syncManagedDirectory(m.path(managedDirectory + "/transactions")); err != nil {
		return err
	}
	*transaction = next
	return nil
}

// Caller holds managed.lock. Sync the journal parent before reclaiming history
// so a prior rename whose directory sync failed cannot authorize deletion.
func (m managedClient) pruneTransactions(transaction managedTransaction) error {
	if err := syncManagedDirectory(m.path(managedDirectory)); err != nil {
		return err
	}
	directory, err := secureManagedDirectory(m.root, managedDirectory+"/transactions", 0700)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() != transaction.TransactionID {
			if err := os.RemoveAll(filepath.Join(directory, entry.Name())); err != nil {
				return err
			}
		}
	}
	return syncManagedDirectory(directory)
}
