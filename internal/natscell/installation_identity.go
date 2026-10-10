package natscell

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"
	"golang.org/x/sys/unix"
)

// InstallationIdentity is measured from signed broker claims and existing disk
// pins. Configuration declarations alone cannot authorize opening an old store.
type InstallationIdentity struct {
	Operator, SystemAccount, CellAccount, HostSigner, RoleSigner, AccountSigner, InterRegionAccount string
	Directory, ServerName, RaftNodeID, ServerNameSHA256, NodeIdentitySHA256                         string
}

// ObserveInstalledIdentity never creates missing pins or starts a listener.
func ObserveInstalledIdentity(cfg Config) (InstallationIdentity, error) {
	if cfg.Lab || cfg.Embedded == nil {
		return InstallationIdentity{}, errors.New("installed broker identity requires production configuration")
	}
	if err := cfg.validate(); err != nil {
		return InstallationIdentity{}, err
	}
	dir, err := openInstallationDirectory(cfg.Embedded.StoreDir, false)
	if err != nil {
		return InstallationIdentity{}, err
	}
	defer unix.Close(dir)
	return observeInstalledIdentity(cfg, dir)
}

func observeInstalledIdentity(cfg Config, dir int) (InstallationIdentity, error) {
	nodeWire, err := readInstallationFileAt(dir, nodeIdentityFile, 4096)
	if err != nil {
		return InstallationIdentity{}, err
	}
	return observeInstallationIdentity(cfg, dir, nodeWire)
}

func observeInstallationIdentity(cfg Config, dir int, nodeWire []byte) (InstallationIdentity, error) {
	e := cfg.Embedded
	result := InstallationIdentity{Directory: e.StoreDir, ServerName: ServerName(cfg.Cell, cfg.Instance)}
	serverWire, err := readInstallationFileAt(dir, storeIdentityFile, 4096)
	if err != nil {
		return result, err
	}
	if string(serverWire) != result.ServerName+"\n" {
		return result, ErrStoreIdentity
	}
	var node nodeIdentity
	if err := protocol.DecodeStrict(nodeWire, &node, 4096); err != nil || node.Version != 1 || node.Cell != cfg.Cell || node.Instance != cfg.Instance {
		return result, ErrStoreIdentity
	}
	prepared, err := server.NewServer(&server.Options{ServerName: result.ServerName, DontListen: true, NoLog: true, NoSigs: true})
	if err != nil {
		return result, err
	}
	defer prepared.Shutdown()
	if node.NodeID != prepared.NodeName() {
		return result, ErrStoreIdentity
	}
	result.RaftNodeID = node.NodeID
	result.ServerNameSHA256, result.NodeIdentitySHA256 = installationDigest(serverWire), installationDigest(nodeWire)
	operatorWire, err := readInstallationFile(e.OperatorJWTFile, 64<<10)
	if err != nil {
		return result, err
	}
	operator, err := jwt.DecodeOperatorClaims(strings.TrimSpace(string(operatorWire)))
	if err != nil {
		return result, fmt.Errorf("decode installed operator: %w", err)
	}
	systemWire, err := readInstallationFile(e.SystemJWTFile, 64<<10)
	if err != nil {
		return result, err
	}
	system, err := jwt.DecodeAccountClaims(strings.TrimSpace(string(systemWire)))
	if err != nil || system.Subject != operator.SystemAccount || !operator.DidSign(system) {
		return result, errors.New("installed system account is not bound to operator")
	}
	cellWire, err := readInstallationFile(e.CellJWTFile, 64<<10)
	if err != nil {
		return result, err
	}
	cell, err := jwt.DecodeAccountClaims(strings.TrimSpace(string(cellWire)))
	if err != nil || cell.Subject == system.Subject || !operator.DidSign(cell) {
		return result, errors.New("installed cell account is not bound to operator")
	}
	result.Operator, result.SystemAccount, result.CellAccount = operator.Subject, system.Subject, cell.Subject
	for key, scope := range cell.SigningKeys {
		if scope == nil {
			if result.AccountSigner != "" {
				return result, errors.New("installed cell has multiple account signers")
			}
			result.AccountSigner = key
			continue
		}
		user, ok := scope.(*jwt.UserScope)
		if !ok || user.Key != key {
			return result, errors.New("installed broker signing scope is invalid")
		}
		switch user.Role {
		case "host":
			if result.HostSigner != "" {
				return result, errors.New("installed cell has multiple host signers")
			}
			result.HostSigner = key
		case "role":
			if result.RoleSigner != "" {
				return result, errors.New("installed cell has multiple role signers")
			}
			result.RoleSigner = key
		default:
			return result, errors.New("installed cell has unknown signing scope")
		}
	}
	if result.HostSigner == "" || result.RoleSigner == "" {
		return result, errors.New("installed host and role signing identities are required")
	}
	if e.InterRegion != nil {
		wire, err := readInstallationFile(e.InterRegion.AccountJWTFile, 64<<10)
		if err != nil {
			return result, err
		}
		claim, err := jwt.DecodeAccountClaims(strings.TrimSpace(string(wire)))
		if err != nil || !operator.DidSign(claim) || claim.Subject == system.Subject || claim.Subject == cell.Subject {
			return result, errors.New("installed interregion account is not bound to operator")
		}
		result.InterRegionAccount = claim.Subject
	}
	return result, nil
}

// PrepareInitialInstallationIdentity is only for a genuinely unaccepted current
// first install. Existing-store rekeys use ObserveInstalledIdentity exclusively.
func PrepareInitialInstallationIdentity(cfg Config, serviceUID, serviceGID uint32) (InstallationIdentity, error) {
	if cfg.Lab || cfg.Embedded == nil || serviceUID == 0 || serviceGID == 0 {
		return InstallationIdentity{}, ErrStoreIdentity
	}
	if err := cfg.validate(); err != nil {
		return InstallationIdentity{}, err
	}
	e := cfg.Embedded
	name := ServerName(cfg.Cell, cfg.Instance)
	prepared, err := server.NewServer(&server.Options{ServerName: name, DontListen: true, NoLog: true, NoSigs: true})
	if err != nil {
		return InstallationIdentity{}, err
	}
	defer prepared.Shutdown()
	nodeWire, err := json.Marshal(nodeIdentity{Version: 1, Cell: cfg.Cell, Instance: cfg.Instance, NodeID: prepared.NodeName()})
	if err != nil {
		return InstallationIdentity{}, err
	}
	dir, err := openInstallationDirectory(e.StoreDir, true)
	if err != nil {
		return InstallationIdentity{}, err
	}
	defer unix.Close(dir)
	pins := []struct {
		name string
		wire []byte
		file *os.File
	}{
		{name: storeIdentityFile, wire: []byte(name + "\n")},
		{name: nodeIdentityFile, wire: nodeWire},
	}
	// Check both existing pins before publishing either or changing ownership.
	for index := range pins {
		pin := &pins[index]
		file, wire, err := openInstallationFileAt(dir, pin.name, 4096)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return InstallationIdentity{}, err
		}
		defer file.Close()
		if !bytes.Equal(wire, pin.wire) {
			return InstallationIdentity{}, ErrStoreIdentity
		}
		pin.file = file
	}
	if pins[0].file == nil || pins[1].file == nil {
		if err := checkUnpinnedInstallationStore(dir); err != nil {
			return InstallationIdentity{}, err
		}
	}
	for index := range pins {
		pin := &pins[index]
		if pin.file == nil {
			pin.file, err = publishInstallationPin(dir, pin.name, pin.wire)
			if err != nil {
				return InstallationIdentity{}, err
			}
			defer pin.file.Close()
		}
	}
	result, err := observeInstalledIdentity(cfg, dir)
	if err != nil {
		return InstallationIdentity{}, err
	}
	for _, pin := range pins {
		wire, err := readInstallationDescriptor(dir, pin.file, 4096)
		if err != nil {
			return InstallationIdentity{}, err
		}
		if !bytes.Equal(wire, pin.wire) {
			return InstallationIdentity{}, ErrStoreIdentity
		}
	}
	for _, pin := range pins {
		if err := pin.file.Chown(int(serviceUID), int(serviceGID)); err != nil {
			return InstallationIdentity{}, err
		}
		if err := pin.file.Chmod(0o600); err != nil {
			return InstallationIdentity{}, err
		}
		if err := pin.file.Sync(); err != nil {
			return InstallationIdentity{}, err
		}
	}
	if err := unix.Fchown(dir, int(serviceUID), int(serviceGID)); err != nil {
		return InstallationIdentity{}, err
	}
	if err := unix.Fchmod(dir, 0o700); err != nil {
		return InstallationIdentity{}, err
	}
	if err := unix.Fsync(dir); err != nil {
		return InstallationIdentity{}, err
	}
	return result, nil
}

func installationDigest(wire []byte) string {
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:])
}

func readInstallationFile(path string, limit int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrStoreIdentity
	}
	dir, err := openInstallationDirectory(filepath.Dir(path), false)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dir)
	return readInstallationFileAt(dir, filepath.Base(path), limit)
}

func openInstallationDirectory(path string, create bool) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || create && path == "/" {
		return -1, ErrStoreIdentity
	}
	dir, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for component := range strings.SplitSeq(strings.TrimPrefix(path, "/"), "/") {
		if component == "" {
			continue
		}
		next, err := unix.Openat(dir, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if create && errors.Is(err, unix.ENOENT) {
			if err = unix.Mkdirat(dir, component, 0o700); err == nil || errors.Is(err, unix.EEXIST) {
				err = unix.Fsync(dir)
			}
			if err == nil {
				next, err = unix.Openat(dir, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			}
		}
		unix.Close(dir)
		if err != nil {
			return -1, err
		}
		dir = next
	}
	return dir, nil
}

func readInstallationFileAt(dir int, name string, limit int64) ([]byte, error) {
	file, wire, err := openInstallationFileAt(dir, name, limit)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return wire, nil
}

func openInstallationFileAt(dir int, name string, limit int64) (*os.File, []byte, error) {
	fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	wire, err := readInstallationDescriptor(dir, file, limit)
	if err != nil {
		file.Close()
		return nil, nil, err
	}
	return file, wire, nil
}

func readInstallationDescriptor(dir int, file *os.File, limit int64) ([]byte, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 ||
		stat.Mode&0o7777 != 0o600 || stat.Size <= 0 || stat.Size > limit {
		return nil, ErrStoreIdentity
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	wire, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	var current unix.Stat_t
	if err := unix.Fstatat(dir, file.Name(), &current, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
		current.Dev != stat.Dev || current.Ino != stat.Ino || current.Mode != stat.Mode || current.Nlink != 1 ||
		int64(len(wire)) != stat.Size || current.Size != stat.Size {
		return nil, ErrStoreIdentity
	}
	return wire, nil
}

func checkUnpinnedInstallationStore(dir int) error {
	fd, err := unix.Openat(dir, "jetstream", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "jetstream")
	defer file.Close()
	entries, err := file.ReadDir(1)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if len(entries) != 0 {
		return ErrStoreIdentity
	}
	return nil
}

func publishInstallationPin(dir int, name string, wire []byte) (*os.File, error) {
	return publishInstallationPinOwned(dir, name, wire, uint32(os.Geteuid()), uint32(os.Getegid()))
}

func publishInstallationPinOwned(dir int, name string, wire []byte, uid, gid uint32) (*os.File, error) {
	temporary := "." + name + "." + rand.Text()
	fd, err := unix.Openat(dir, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	defer unix.Unlinkat(dir, temporary, 0)
	file := os.NewFile(uintptr(fd), temporary)
	defer file.Close()
	if err := file.Chown(int(uid), int(gid)); err != nil {
		return nil, err
	}
	if n, err := file.Write(wire); err != nil || n != len(wire) {
		return nil, errors.Join(err, io.ErrShortWrite)
	}
	if err := file.Sync(); err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	// Publish complete bytes without replacing any concurrent owner's pin.
	if err := unix.Renameat2(dir, temporary, dir, name, unix.RENAME_NOREPLACE); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, err
	}
	if err := unix.Fsync(dir); err != nil {
		return nil, err
	}
	pinned, recorded, err := openInstallationFileAt(dir, name, 4096)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(recorded, wire) {
		pinned.Close()
		return nil, ErrStoreIdentity
	}
	return pinned, nil
}
