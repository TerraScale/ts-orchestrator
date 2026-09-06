package hostagent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
)

// Retention owns only the newly created temporary file. It never replaces a
// preexisting plan. All directory traversal uses descriptors and the final
// no-replace rename is followed by directory fsync and protected readback.
func retainStorageTransitionPlan(ctx context.Context, path string, raw []byte, live func() error) error {
	bad := errors.New("hostagent: unsafe or conflicting retained plan")
	if ctx == nil || live == nil || os.Geteuid() != 0 || !hostmanifest.SafeAbsolutePath(path) || len(raw) == 0 || len(raw) > controltransition.MaximumBytes {
		return bad
	}
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return live()
	}
	if err := check(); err != nil {
		return err
	}
	dir, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return bad
	}
	defer func() { unix.Close(dir) }()
	parts := strings.Split(strings.TrimPrefix(filepath.Dir(path), "/"), "/")
	for i := 0; ; i++ {
		var st unix.Stat_t
		if unix.Fstat(dir, &st) != nil || st.Uid != 0 || st.Mode&0022 != 0 {
			return bad
		}
		if i == len(parts) || parts[i] == "" {
			break
		}
		next, err := unix.Openat(dir, parts[i], unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return bad
		}
		unix.Close(dir)
		dir = next
	}
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return err
	}
	temporary := ".storage-plan-" + hex.EncodeToString(token[:])
	fd, err := unix.Openat(dir, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return bad
	}
	defer unix.Unlinkat(dir, temporary, 0)
	file := os.NewFile(uintptr(fd), temporary)
	n, writeErr := file.Write(raw)
	if writeErr == nil && n != len(raw) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return err
	}
	if err := check(); err != nil {
		return err
	}
	if err := unix.Renameat2(dir, temporary, dir, filepath.Base(path), unix.RENAME_NOREPLACE); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	if err := unix.Fsync(dir); err != nil {
		return err
	}
	retained, err := bootstrapcredentials.ReadFile(path, true, controltransition.MaximumBytes)
	if err != nil || !bytes.Equal(retained, raw) {
		return bad
	}
	return check()
}
