package candidatesync

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarytransfer"
)

func temporaryName(name, prefix string) bool {
	suffix, found := strings.CutPrefix(name, prefix)
	raw, e := hex.DecodeString(suffix)
	return found && e == nil && len(raw) == 16 && hex.EncodeToString(raw) == suffix
}
func recoverTemporary(ctx context.Context, s *stage, name string) error {
	if !temporaryName(name, ".staging-") {
		return errors.New("candidatesync: unknown temporary entry")
	}
	f, e := s.openFile(name, unix.O_RDONLY)
	if e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = s.mutationCheck(ctx); e != nil {
		return e
	}
	if e = unix.Unlinkat(int(s.dir.Fd()), name, 0); e != nil {
		return e
	}
	return s.dir.Sync()
}
func newReference(ctx context.Context, s *stage, pin []byte) (string, error) {
	var nonce [16]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return "", e
	}
	name := ".reference-" + hex.EncodeToString(nonce[:])
	if e := s.mutationCheck(ctx); e != nil {
		return "", e
	}
	if e := unix.Mkdirat(int(s.dir.Fd()), name, 0700); e != nil {
		return "", e
	}
	path := fmt.Sprintf("/proc/self/fd/%d/%s", s.dir.Fd(), name)
	d, e := os.Open(path)
	if e != nil {
		return "", e
	}
	// Publish the scope atomically before a broker can create any data. A crash
	// during the write leaves only a recognizable temporary file for recovery.
	reference := &stage{dir: d, check: s.check}
	e = errors.Join(reference.publish(ctx, "scope.json", pin), d.Close(), s.dir.Sync())
	return path, e
}
func recoverReference(ctx context.Context, s *stage, name string, pin []byte) error {
	if !temporaryName(name, ".reference-") {
		return errors.New("candidatesync: unknown reference directory")
	}
	path := fmt.Sprintf("/proc/self/fd/%d/%s", s.dir.Fd(), name)
	if e := inspectTree(path, false); e != nil {
		return e
	}
	entries, e := os.ReadDir(path)
	if e != nil {
		return e
	}
	if len(entries) > 0 {
		f, e := os.Open(filepath.Join(path, "scope.json"))
		if errors.Is(e, os.ErrNotExist) {
			// Only an interrupted scope publication may precede the scope pin.
			// A directory containing broker data without that pin is retained.
			d, openErr := os.Open(path)
			if openErr != nil {
				return openErr
			}
			defer d.Close()
			reference := &stage{dir: d, check: s.check}
			for _, entry := range entries {
				if !temporaryName(entry.Name(), ".staging-") {
					return errors.New("candidatesync: unpinned reference state retained")
				}
				file, err := reference.openFile(entry.Name(), unix.O_RDONLY)
				if err != nil {
					return err
				}
				if err = file.Close(); err != nil {
					return err
				}
			}
		} else {
			if e != nil {
				return errors.New("candidatesync: unpinned reference state retained")
			}
			raw, e := io.ReadAll(io.LimitReader(f, preliminarytransfer.MaximumBytes+1))
			e = errors.Join(e, f.Close())
			if e != nil || !bytes.Equal(raw, pin) {
				return errors.New("candidatesync: conflicting reference scope retained")
			}
		}
	}
	if e = s.mutationCheck(ctx); e != nil {
		return e
	}
	if e = os.RemoveAll(path); e != nil {
		return e
	}
	return s.dir.Sync()
}

// Existing validated allocated blocks count toward the admitted volume budget.
// The second broker budget remains reserved for the new reference restore.
func allocatedStageBytes(s *stage) (uint64, error) {
	root := fmt.Sprintf("/proc/self/fd/%d/.", s.dir.Fd())
	if e := inspectTree(root, false); e != nil {
		return 0, e
	}
	var total uint64
	e := filepath.WalkDir(root, func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		var st unix.Stat_t
		if e = unix.Lstat(path, &st); e != nil {
			return e
		}
		if st.Blocks < 0 {
			return errors.New("candidatesync: invalid staged allocation")
		}
		total += uint64(st.Blocks) * 512
		return nil
	})
	return total, e
}
