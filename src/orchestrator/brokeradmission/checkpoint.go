package brokeradmission

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
)

func checkpointDirectory(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) == "." || filepath.Base(path) == "/" {
		return nil, ErrInvalid
	}
	return bootstrapcredentials.OpenProtectedDirectory(filepath.Dir(path), true)
}
func checkpointLeaf(directory *os.File, name string) (bool, error) {
	var stat unix.Stat_t
	err := unix.Fstatat(int(directory.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || stat.Mode&0077 != 0 || stat.Mode&(unix.S_ISUID|unix.S_ISGID|unix.S_ISVTX) != 0 {
		return false, ErrInvalid
	}
	return true, nil
}

// ReadCheckpoint captures the bounded signed state through the shared protected
// descriptor reader. An untrusted ancestor or swapped symlink fails closed.
func ReadCheckpoint(path string, v *Verifier) ([]byte, Desired, error) {
	parent, err := checkpointDirectory(path)
	if err != nil {
		return nil, Desired{}, err
	}
	defer parent.Close()
	found, err := checkpointLeaf(parent, filepath.Base(path))
	if err != nil || !found {
		return nil, Desired{}, err
	}
	wire, err := bootstrapcredentials.ReadFile(path, true, MaximumBytes)
	if err != nil {
		return nil, Desired{}, err
	}
	desired, err := v.Verify(wire)
	return wire, desired, err
}

// PersistCheckpoint writes and renames relative to the protected parent
// descriptor, then fsyncs the directory before native broker reload.
func PersistCheckpoint(path string, wire []byte) error {
	if len(wire) == 0 || len(wire) > MaximumBytes {
		return ErrInvalid
	}
	parent, err := checkpointDirectory(path)
	if err != nil {
		return err
	}
	defer parent.Close()
	if _, err := checkpointLeaf(parent, filepath.Base(path)); err != nil {
		return err
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	temporary := ".broker-grants-" + hex.EncodeToString(random)
	fd, err := unix.Openat(int(parent.Fd()), temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	defer unix.Unlinkat(int(parent.Fd()), temporary, 0)
	file := os.NewFile(uintptr(fd), temporary)
	if _, err = file.Write(wire); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := unix.Renameat(int(parent.Fd()), temporary, int(parent.Fd()), filepath.Base(path)); err != nil {
		return err
	}
	return parent.Sync()
}

// ClaimInitialBootstrap consumes the explicit first-start exception once. Its
// marker shares checkpoint ancestry protection and descriptor-relative writes.
func ClaimInitialBootstrap(path string) error {
	parent, err := checkpointDirectory(path)
	if err != nil {
		return err
	}
	defer parent.Close()
	if found, err := checkpointLeaf(parent, filepath.Base(path)); err != nil || found {
		if err != nil {
			return err
		}
		return ErrInvalid
	}
	fd, err := unix.Openat(int(parent.Fd()), filepath.Base(path)+".initialized", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "broker-bootstrap-marker")
	if _, err = file.WriteString("initial broker admission consumed\n"); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return parent.Sync()
}
