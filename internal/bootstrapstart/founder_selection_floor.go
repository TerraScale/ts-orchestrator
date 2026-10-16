package bootstrapstart

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"golang.org/x/sys/unix"
)

const (
	FounderSelectionFloorDirectory = "/var/lib/terrascale-orchestrator-controller"
	founderSelectionFloorName      = "founder-selection-floor.json"
	founderSelectionLockName       = ".founder-selection-floor.lock"
	founderSelectionFloorMax       = 256
)

var ErrFounderSelectionFloor = errors.New("durable founder selection floor is missing or invalid")

type founderSelectionFloor struct {
	SchemaVersion   int    `json:"schemaVersion"`
	Generation      uint64 `json:"generation"`
	SelectionSHA256 string `json:"selectionSha256"`
}

// FounderSelectionFloorStore is the seed's durable observed-generation fence.
// A replacement seed must receive this file through an explicit handoff; an
// absent file never silently initializes from a possibly rolled-back selector.
type FounderSelectionFloorStore struct {
	directory            string
	ownerUID             uint32
	allowUnsafeAncestors bool
}

func NewFounderSelectionFloorStore() *FounderSelectionFloorStore {
	return &FounderSelectionFloorStore{directory: FounderSelectionFloorDirectory, ownerUID: uint32(os.Geteuid())}
}

// Initialize is an explicit provisioning operation. The caller must verify
// that the starting selection generation and digest are the intended handoff.
// Existing state is never replaced. Runtime reads only Check and Observe.
func (store *FounderSelectionFloorStore) Initialize(generation uint64, selectionSHA256 string) error {
	if generation == 0 || !validFounderDigest(selectionSHA256) {
		return ErrFounderSelectionFloor
	}
	dir, err := store.openDirectory()
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	if err := store.withLock(dir, func() error {
		return store.writeNew(dir, founderSelectionFloor{SchemaVersion: 1,
			Generation: generation, SelectionSHA256: selectionSHA256}, true, nil)
	}); err != nil {
		return err
	}
	return nil
}

// InitializeForService is the initial root admission's one-time publication.
// It writes the file with the service directory's exact owner before fsyncing
// either the file or directory, so a crash cannot expose a durable root-owned
// floor that the unprivileged seed cannot replay.
func (store *FounderSelectionFloorStore) InitializeForService(generation uint64, selectionSHA256 string,
	serviceGID uint32,
) error {
	if store == nil || store.ownerUID == 0 || serviceGID == 0 || generation != 1 ||
		!validFounderDigest(selectionSHA256) {
		return ErrFounderSelectionFloor
	}
	return store.initializeForService(generation, selectionSHA256, serviceGID, false)
}

// InitializePeerForService records the root-verified selector seen at first
// managed-peer admission. A prior floor can replay an interrupted install,
// but it can never move backward or change digest at the same generation.
func (store *FounderSelectionFloorStore) InitializePeerForService(generation uint64, selectionSHA256 string,
	serviceGID uint32,
) error {
	if store == nil || store.ownerUID == 0 || serviceGID == 0 || generation == 0 ||
		!validFounderDigest(selectionSHA256) {
		return ErrFounderSelectionFloor
	}
	return store.initializeForService(generation, selectionSHA256, serviceGID, true)
}

func (store *FounderSelectionFloorStore) initializeForService(generation uint64, selectionSHA256 string,
	serviceGID uint32, allowReplay bool,
) error {
	dir, err := store.openDirectory()
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	var stat unix.Stat_t
	if err := unix.Fstat(dir, &stat); err != nil || stat.Gid != serviceGID {
		return ErrFounderSelectionFloor
	}
	owner := struct{ uid, gid uint32 }{store.ownerUID, serviceGID}
	return store.withLock(dir, func() error {
		if allowReplay {
			current, readErr := store.read(dir)
			if readErr == nil {
				if generation < current.Generation ||
					generation == current.Generation && selectionSHA256 != current.SelectionSHA256 {
					return ErrFounderSelectionFloor
				}
				if generation == current.Generation {
					return unix.Fsync(dir)
				}
				return store.writeNew(dir, founderSelectionFloor{SchemaVersion: 1,
					Generation: generation, SelectionSHA256: selectionSHA256}, false, &owner)
			}
			if !errors.Is(readErr, os.ErrNotExist) {
				return readErr
			}
		}
		return store.writeNew(dir, founderSelectionFloor{SchemaVersion: 1,
			Generation: generation, SelectionSHA256: selectionSHA256}, true, &owner)
	})
}

// Check refuses rollback before any payload reads. Observe repeats this check
// under the file lock and fsyncs the higher generation before an OCI effect.
func (store *FounderSelectionFloorStore) Check(generation uint64, selectionSHA256 string) error {
	return store.inspect(generation, selectionSHA256, false)
}

func (store *FounderSelectionFloorStore) Observe(generation uint64, selectionSHA256 string) error {
	return store.inspect(generation, selectionSHA256, true)
}

func (store *FounderSelectionFloorStore) inspect(generation uint64, selectionSHA256 string, advance bool) error {
	if generation == 0 || !validFounderDigest(selectionSHA256) {
		return ErrFounderSelectionFloor
	}
	dir, err := store.openDirectory()
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	return store.withLock(dir, func() error {
		current, err := store.read(dir)
		if err != nil {
			return err
		}
		if generation < current.Generation || generation == current.Generation && selectionSHA256 != current.SelectionSHA256 {
			return ErrFounderSelectionFloor
		}
		if advance && generation > current.Generation {
			return store.writeNew(dir, founderSelectionFloor{SchemaVersion: 1,
				Generation: generation, SelectionSHA256: selectionSHA256}, false, nil)
		}
		if advance {
			// A prior Renameat may have succeeded while its directory fsync
			// failed. Never treat a visible equal-generation floor as durable
			// until a directory fsync succeeds before this effect.
			return unix.Fsync(dir)
		}
		return nil
	})
}

func (store *FounderSelectionFloorStore) openDirectory() (int, error) {
	if store == nil || !filepath.IsAbs(store.directory) || filepath.Clean(store.directory) != store.directory {
		return -1, ErrFounderSelectionFloor
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for component := range strings.SplitSeq(strings.TrimPrefix(store.directory, "/"), "/") {
		if component == "" || component == "." || component == ".." {
			unix.Close(fd)
			return -1, ErrFounderSelectionFloor
		}
		next, err := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		unix.Close(fd)
		if err != nil {
			return -1, err
		}
		fd = next
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil ||
			!store.allowUnsafeAncestors && stat.Uid != 0 && stat.Uid != store.ownerUID ||
			!store.allowUnsafeAncestors && stat.Mode&0o022 != 0 {
			unix.Close(fd)
			return -1, ErrFounderSelectionFloor
		}
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Uid != store.ownerUID || stat.Mode&0o777 != 0o700 {
		unix.Close(fd)
		return -1, ErrFounderSelectionFloor
	}
	return fd, nil
}

func (store *FounderSelectionFloorStore) withLock(dir int, work func() error) error {
	fd, err := unix.Openat(dir, founderSelectionLockName, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Mode&0o777 != 0o600 || stat.Uid != store.ownerUID || stat.Nlink != 1 {
		return ErrFounderSelectionFloor
	}
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		return err
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	return work()
}

func (store *FounderSelectionFloorStore) read(dir int) (founderSelectionFloor, error) {
	fd, err := unix.Openat(dir, founderSelectionFloorName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return founderSelectionFloor{}, fmt.Errorf("%w: %w", ErrFounderSelectionFloor, err)
	}
	file := os.NewFile(uintptr(fd), founderSelectionFloorName)
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Mode&0o777 != 0o600 || stat.Uid != store.ownerUID || stat.Nlink != 1 ||
		stat.Size < 1 || stat.Size > founderSelectionFloorMax {
		return founderSelectionFloor{}, ErrFounderSelectionFloor
	}
	wire, err := io.ReadAll(io.LimitReader(file, founderSelectionFloorMax+1))
	if err != nil || len(wire) != int(stat.Size) {
		return founderSelectionFloor{}, ErrFounderSelectionFloor
	}
	var floor founderSelectionFloor
	if protocol.DecodeStrict(wire, &floor, founderSelectionFloorMax) != nil || floor.SchemaVersion != 1 ||
		floor.Generation == 0 || !validFounderDigest(floor.SelectionSHA256) {
		return founderSelectionFloor{}, ErrFounderSelectionFloor
	}
	canonical, err := protocol.EncodeJSON(floor)
	if err != nil || !bytes.Equal(canonical, wire) {
		return founderSelectionFloor{}, ErrFounderSelectionFloor
	}
	return floor, nil
}

func (store *FounderSelectionFloorStore) writeNew(dir int, floor founderSelectionFloor, initialize bool,
	owner *struct{ uid, gid uint32 },
) error {
	wire, err := encodeFounderSelectionFloor(floor.Generation, floor.SelectionSHA256)
	if err != nil || floor.SchemaVersion != 1 {
		return ErrFounderSelectionFloor
	}
	if initialize {
		var nonce [12]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return err
		}
		temporary := ".founder-selection-initial." + hex.EncodeToString(nonce[:])
		fd, err := unix.Openat(dir, temporary,
			unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		if err != nil {
			return err
		}
		remove := true
		defer func() {
			if remove {
				_ = unix.Unlinkat(dir, temporary, 0)
			}
		}()
		file := os.NewFile(uintptr(fd), temporary)
		if owner != nil {
			var stat unix.Stat_t
			if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
				stat.Mode&0o777 != 0o600 || stat.Nlink != 1 {
				_ = file.Close()
				return ErrFounderSelectionFloor
			}
			if stat.Uid != owner.uid || stat.Gid != owner.gid {
				if err := unix.Fchown(fd, int(owner.uid), int(owner.gid)); err != nil {
					_ = file.Close()
					return err
				}
			}
		}
		written, writeErr := file.Write(wire)
		if written != len(wire) && writeErr == nil {
			writeErr = io.ErrShortWrite
		}
		syncErr := file.Sync()
		closeErr := file.Close()
		if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
			return err
		}
		if err := unix.Renameat2(dir, temporary, dir, founderSelectionFloorName, unix.RENAME_NOREPLACE); err != nil {
			return err
		}
		remove = false
		return unix.Fsync(dir)
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	temporary := ".founder-selection-floor." + hex.EncodeToString(nonce[:])
	fd, err := unix.Openat(dir, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		if remove {
			_ = unix.Unlinkat(dir, temporary, 0)
		}
	}()
	file := os.NewFile(uintptr(fd), temporary)
	if owner != nil {
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
			stat.Mode&0o777 != 0o600 || stat.Nlink != 1 {
			_ = file.Close()
			return ErrFounderSelectionFloor
		}
		if stat.Uid != owner.uid || stat.Gid != owner.gid {
			if err := unix.Fchown(fd, int(owner.uid), int(owner.gid)); err != nil {
				_ = file.Close()
				return err
			}
		}
	}
	written, writeErr := file.Write(wire)
	if written != len(wire) && writeErr == nil {
		writeErr = io.ErrShortWrite
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	if err := unix.Renameat(dir, temporary, dir, founderSelectionFloorName); err != nil {
		return err
	}
	remove = false
	return unix.Fsync(dir)
}

func encodeFounderSelectionFloor(generation uint64, selectionSHA256 string) ([]byte, error) {
	if generation == 0 || !validFounderDigest(selectionSHA256) {
		return nil, ErrFounderSelectionFloor
	}
	wire, err := protocol.EncodeJSON(founderSelectionFloor{SchemaVersion: 1,
		Generation: generation, SelectionSHA256: selectionSHA256})
	if err != nil || len(wire) > founderSelectionFloorMax {
		return nil, ErrFounderSelectionFloor
	}
	return wire, nil
}
