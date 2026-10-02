// Package selfupdate performs binary-only A/B updates of the orchestrator.
// A verified binary is staged under <root>/releases/<sha256>, the "current"
// symlink that the systemd units execute is flipped atomically, and a
// root-run watchdog rolls the link back when no fresh signed version proof
// from the new process arrives before the activation deadline.
package selfupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

const (
	// DefaultRoot is the release root referenced by the systemd drop-ins.
	DefaultRoot = "/var/lib/terrascale-orchestrator"
	// DefaultBakedBinary is the image-installed binary used as the first
	// release and the last-resort fallback.
	DefaultBakedBinary = "/usr/local/bin/terrascale-orchestrator"
	// BinaryName is the executable file name inside every release directory.
	BinaryName = "terrascale-orchestrator"
	// MaxBinaryBytes matches the release receipt and delivery artifact bound.
	MaxBinaryBytes int64 = 512 << 20

	releasesDir     = "releases"
	currentLink     = "current"
	activationFile  = "activation.json"
	knownBadFile    = "known-bad.json"
	receiptFile     = "receipt.json"
	delegationFile  = "delegation.json"
	bakedMarkerFile = "baked"
	maxStateBytes   = 64 << 10
)

var (
	ErrInvalid  = errors.New("self-update input is invalid")
	ErrUnsafe   = errors.New("self-update path is not exclusively owned")
	ErrKnownBad = errors.New("release digest is known bad on this node")
	digestRE    = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Layout is one node's release root. Owner is the uid that must own every
// directory and file in it; production uses root (0), so the unprivileged
// controller can execute but never replace its own binary.
type Layout struct {
	Root  string
	Owner int
}

// NewLayout returns the production layout owned by root.
func NewLayout(root string) Layout { return Layout{Root: root, Owner: 0} }

func (layout Layout) validate() error {
	if !filepath.IsAbs(layout.Root) || filepath.Clean(layout.Root) != layout.Root || layout.Owner < 0 {
		return fmt.Errorf("%w: release root must be a clean absolute path", ErrInvalid)
	}
	return nil
}

func (layout Layout) releasesPath() string { return filepath.Join(layout.Root, releasesDir) }
func (layout Layout) currentPath() string  { return filepath.Join(layout.Root, currentLink) }
func (layout Layout) activationPath() string {
	return filepath.Join(layout.Root, activationFile)
}
func (layout Layout) knownBadPath() string { return filepath.Join(layout.Root, knownBadFile) }

// ReleaseDir is the directory of one staged release.
func (layout Layout) ReleaseDir(digest string) string {
	return filepath.Join(layout.releasesPath(), digest)
}

// BinaryPath is the executable of one staged release.
func (layout Layout) BinaryPath(digest string) string {
	return filepath.Join(layout.ReleaseDir(digest), BinaryName)
}

// CurrentExecutable is the path the systemd ExecStart line runs.
func (layout Layout) CurrentExecutable() string {
	return filepath.Join(layout.currentPath(), BinaryName)
}

// ensureDirs creates the root and releases directories with exclusive
// ownership and verifies existing ones.
func (layout Layout) ensureDirs() error {
	if err := layout.validate(); err != nil {
		return err
	}
	for _, path := range []string{layout.Root, layout.releasesPath()} {
		if err := os.Mkdir(path, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		if err := layout.checkOwned(path, true); err != nil {
			return err
		}
	}
	return nil
}

// checkOwned rejects symlinks, foreign owners and group or world write.
func (layout Layout) checkOwned(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != layout.Owner || info.Mode().Perm()&0o022 != 0 ||
		directory && !info.IsDir() || !directory && !info.Mode().IsRegular() {
		return fmt.Errorf("%w: %s", ErrUnsafe, path)
	}
	return nil
}

// Current returns the digest the current link points at, or "" when the
// link is absent.
func (layout Layout) Current() (string, error) {
	if err := layout.validate(); err != nil {
		return "", err
	}
	target, err := os.Readlink(layout.currentPath())
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	digest, ok := strings.CutPrefix(target, releasesDir+"/")
	if !ok || !digestRE.MatchString(digest) {
		return "", fmt.Errorf("%w: current link target %q", ErrUnsafe, target)
	}
	return digest, nil
}

// VerifyRelease checks that a staged release is exclusively owned,
// read-only and that its bytes still hash to its directory name.
func (layout Layout) VerifyRelease(digest string) error {
	if !digestRE.MatchString(digest) {
		return fmt.Errorf("%w: release digest", ErrInvalid)
	}
	for _, path := range []string{layout.Root, layout.releasesPath(), layout.ReleaseDir(digest)} {
		if err := layout.checkOwned(path, true); err != nil {
			return err
		}
	}
	path := layout.BinaryPath(digest)
	if err := layout.checkOwned(path, false); err != nil {
		return err
	}
	observed, _, err := hashFile(path)
	if err != nil {
		return err
	}
	if observed != digest {
		return fmt.Errorf("%w: release %s bytes changed", ErrUnsafe, digest)
	}
	return nil
}

// flipCurrent atomically repoints the current link at digest.
func (layout Layout) flipCurrent(digest string) error {
	temporary := filepath.Join(layout.Root, ".current-"+digest[:16])
	_ = os.Remove(temporary)
	if err := os.Symlink(releasesDir+"/"+digest, temporary); err != nil {
		return err
	}
	if err := os.Rename(temporary, layout.currentPath()); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return syncDir(layout.Root)
}

func hashFile(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(file, MaxBinaryBytes+1))
	if err != nil {
		return "", 0, err
	}
	if size > MaxBinaryBytes {
		return "", 0, fmt.Errorf("%w: binary exceeds %d bytes", ErrInvalid, MaxBinaryBytes)
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

func syncDir(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

// writeFileAtomic replaces path with data through a synced temporary file.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Chmod(mode); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return syncDir(directory)
}

// readBounded reads a small state file without following a final symlink.
func readBounded(path string, maximum int64) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("%w: %s is too large", ErrInvalid, path)
	}
	return data, nil
}
