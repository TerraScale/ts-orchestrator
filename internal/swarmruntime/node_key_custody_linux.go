package swarmruntime

import (
	"crypto"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const nodeIdentityFileLimit = 64 << 10

var errNodeKeyCustody = errors.New("native signing identity custody changed or is unsafe")

type nodeCustodyDirectory struct {
	fd, parent int
	name       string
	stat       unix.Stat_t
}

type nodeCustodyFile struct {
	file   *os.File
	name   string
	stat   unix.Stat_t
	digest [sha256.Size]byte
}

// Retained descriptors pin every path component, including a root-owned sticky
// ancestor used by native integration fixtures. Current safety proves no history.
type nodeKeyCustody struct {
	directories []nodeCustodyDirectory
	files       []nodeCustodyFile
}

type nodeKeySigner struct {
	mu       sync.Mutex
	key      crypto.Signer
	public   crypto.PublicKey
	custody  *nodeKeyCustody
	consumed bool
}

func (key *nodeKeySigner) Public() crypto.PublicKey { return key.public }

func (key *nodeKeySigner) Close() error {
	key.mu.Lock()
	defer key.mu.Unlock()
	key.consumed = true
	key.key = nil
	return key.custody.close()
}

func (key *nodeKeySigner) Sign(random io.Reader, digest []byte, options crypto.SignerOpts) (signature []byte, err error) {
	key.mu.Lock()
	defer key.mu.Unlock()
	if key.consumed {
		return nil, errors.New("native signing identity has already been consumed")
	}
	key.consumed = true
	defer func() {
		key.key = nil
		err = errors.Join(err, key.custody.close())
		if err != nil {
			clear(signature)
			signature = nil
		}
	}()
	if err = key.custody.validate(); err != nil {
		return nil, err
	}
	signature, err = key.key.Sign(random, digest, options)
	if err != nil {
		return nil, err
	}
	if err = key.custody.validate(); err != nil {
		return signature, err
	}
	return signature, nil
}

func openNodeKeyCustody(stateDirectory string) (_ *nodeKeyCustody, material [3][]byte, err error) {
	if os.Geteuid() != 0 || !filepath.IsAbs(stateDirectory) || filepath.Clean(stateDirectory) != stateDirectory {
		return nil, material, errNodeKeyCustody
	}
	custody := &nodeKeyCustody{}
	defer func() {
		if err != nil {
			clear(material[0])
			_ = custody.close()
		}
	}()
	root, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, material, err
	}
	custody.directories = append(custody.directories, nodeCustodyDirectory{fd: root, parent: -1})
	components := append(strings.Split(strings.TrimPrefix(stateDirectory, "/"), "/"), "certificates")
	for _, name := range components {
		parent := custody.directories[len(custody.directories)-1].fd
		fd, openErr := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr != nil {
			return nil, material, openErr
		}
		custody.directories = append(custody.directories, nodeCustodyDirectory{fd: fd, parent: parent, name: name})
	}
	for i := range custody.directories {
		directory := &custody.directories[i]
		if unix.Fstat(directory.fd, &directory.stat) != nil || !safeNodeDirectory(directory.stat, i < len(custody.directories)-2) {
			return nil, material, errNodeKeyCustody
		}
	}
	parent := custody.directories[len(custody.directories)-1].fd
	for i, name := range []string{"swarm-node.key", "swarm-node.crt", "swarm-root-ca.crt"} {
		fd, openErr := unix.Openat(parent, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if openErr != nil {
			return nil, material, openErr
		}
		file := nodeCustodyFile{file: os.NewFile(uintptr(fd), name), name: name}
		custody.files = append(custody.files, file)
		retained := &custody.files[i]
		if unix.Fstat(fd, &retained.stat) != nil || !safeNodeFile(retained.stat, i == 0) {
			return nil, material, errNodeKeyCustody
		}
		material[i], err = readNodeCustodyFile(*retained)
		if err != nil {
			return nil, material, err
		}
		retained.digest = sha256.Sum256(material[i])
	}
	if err := custody.validate(); err != nil {
		return nil, material, err
	}
	return custody, material, nil
}

func safeNodeDirectory(stat unix.Stat_t, stickyAncestor bool) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFDIR && stat.Uid == 0 && stat.Gid == 0 &&
		(stat.Mode&0o022 == 0 || stickyAncestor && stat.Mode&unix.S_ISVTX != 0)
}

func safeNodeFile(stat unix.Stat_t, private bool) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Uid == 0 && stat.Gid == 0 && stat.Nlink == 1 &&
		stat.Size > 0 && stat.Size <= nodeIdentityFileLimit && stat.Mode&0o7022 == 0 &&
		(!private || stat.Mode&0o7777 == 0o600)
}

func sameNodeFile(before, after unix.Stat_t) bool {
	return before.Dev == after.Dev && before.Ino == after.Ino && before.Mode == after.Mode &&
		before.Uid == after.Uid && before.Gid == after.Gid && before.Nlink == after.Nlink &&
		before.Size == after.Size && before.Mtim == after.Mtim && before.Ctim == after.Ctim
}

func readNodeCustodyFile(file nodeCustodyFile) ([]byte, error) {
	var before, after unix.Stat_t
	if unix.Fstat(int(file.file.Fd()), &before) != nil || !sameNodeFile(file.stat, before) {
		return nil, errNodeKeyCustody
	}
	wire, err := io.ReadAll(io.NewSectionReader(file.file, 0, nodeIdentityFileLimit+1))
	if err != nil || int64(len(wire)) != file.stat.Size || unix.Fstat(int(file.file.Fd()), &after) != nil || !sameNodeFile(before, after) {
		clear(wire)
		return nil, errors.Join(errNodeKeyCustody, err)
	}
	return wire, nil
}

func (custody *nodeKeyCustody) validate() error {
	for i, directory := range custody.directories {
		var current unix.Stat_t
		if unix.Fstat(directory.fd, &current) != nil || !safeNodeDirectory(current, i < len(custody.directories)-2) ||
			current.Dev != directory.stat.Dev || current.Ino != directory.stat.Ino || current.Mode != directory.stat.Mode ||
			current.Uid != directory.stat.Uid || current.Gid != directory.stat.Gid {
			return errNodeKeyCustody
		}
		if directory.parent >= 0 {
			if unix.Fstatat(directory.parent, directory.name, &current, unix.AT_SYMLINK_NOFOLLOW) != nil ||
				current.Dev != directory.stat.Dev || current.Ino != directory.stat.Ino || current.Mode&unix.S_IFMT != unix.S_IFDIR {
				return errNodeKeyCustody
			}
		}
	}
	parent := custody.directories[len(custody.directories)-1].fd
	for _, file := range custody.files {
		var current unix.Stat_t
		if unix.Fstatat(parent, file.name, &current, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameNodeFile(file.stat, current) {
			return errNodeKeyCustody
		}
		wire, err := readNodeCustodyFile(file)
		digest := sha256.Sum256(wire)
		clear(wire)
		if err != nil || digest != file.digest {
			return errors.Join(errNodeKeyCustody, err)
		}
	}
	return nil
}

func (custody *nodeKeyCustody) close() error {
	var err error
	for _, file := range custody.files {
		err = errors.Join(err, file.file.Close())
	}
	custody.files = nil
	for _, directory := range custody.directories {
		err = errors.Join(err, unix.Close(directory.fd))
	}
	custody.directories = nil
	return err
}
