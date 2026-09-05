//go:build linux

package hostsecrets

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const credentialRoot = "/etc/terrascale"
const journalName = ".host-secrets-journal.json"

// BootstrapFile reads the fixed public seed without following symlinks. A
// missing seed returns os.ErrNotExist for non-OCI host startup integration.
func BootstrapFile(ctx context.Context, path string) error {
	if path != SeedPath {
		return ErrSeed
	}
	if os.Geteuid() != 0 {
		return ErrUnsupported
	}
	fd, err := openDirectory(credentialRoot, 0, false)
	if errors.Is(err, unix.ENOENT) {
		return os.ErrNotExist
	}
	if err != nil {
		return ErrOwnership
	}
	defer unix.Close(fd)
	body, err := readAt(fd, "host-secrets.json", MaxSeedBytes, 0, false)
	if errors.Is(err, unix.ENOENT) {
		return os.ErrNotExist
	}
	if err != nil {
		return ErrOwnership
	}
	seed, err := ParseSeed(body)
	if err != nil {
		return err
	}
	return Bootstrap(ctx, seed)
}

// Bootstrap fetches only pinned Vault versions through the official OCI
// instance-principal SDK. A restart verifies the same journal and bytes; it
// never overwrites a destination or accepts an unjournaled existing file.
func Bootstrap(ctx context.Context, seed Seed) error {
	if ctx == nil {
		return ErrSeed
	}
	if err := ValidateSeed(seed); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return ErrUnsupported
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	fd, err := openDirectory(credentialRoot, 0, true)
	if err != nil {
		return ErrOwnership
	}
	defer unix.Close(fd)
	publication, err := prepare(ctx, fd, seed, 0)
	if err != nil {
		return err
	}
	defer publication.close()
	var fetcher *secretFetcher
	for _, entry := range seed.Entries {
		ready, err := publication.ready(entry)
		if err != nil {
			return err
		}
		if ready {
			continue
		}
		if ctx.Err() != nil {
			return ErrFetch
		}
		if fetcher == nil {
			fetcher, err = newInstanceFetcher(ctx, seed.Region)
			if err != nil {
				return err
			}
		}
		body, err := fetcher.fetch(ctx, entry)
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			erase(body)
			return ErrFetch
		}
		err = publication.publish(entry, body)
		erase(body)
		if err != nil {
			return err
		}
	}
	return nil
}

type publication struct {
	root, lock, uid int
	seed            Seed
	ownership       *ownershipRecord
}

func (p *publication) close() { _ = unix.Flock(p.lock, unix.LOCK_UN); _ = unix.Close(p.lock) }

func openDirectory(path string, uid int, create bool) (int, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		next, e := childDirectory(fd, part, uid, create)
		unix.Close(fd)
		if e != nil {
			return -1, e
		}
		fd = next
	}
	return fd, nil
}
func childDirectory(fd int, name string, uid int, create bool) (int, error) {
	next, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) && create {
		if err = unix.Mkdirat(fd, name, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
			return -1, err
		}
		if err = unix.Fsync(fd); err != nil {
			return -1, err
		}
		next, err = unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	}
	if err != nil {
		return -1, err
	}
	var stat unix.Stat_t
	if unix.Fstat(next, &stat) != nil || stat.Uid != uint32(uid) || stat.Mode&0022 != 0 {
		unix.Close(next)
		return -1, ErrOwnership
	}
	// An earlier mkdir may have succeeded before its parent fsync failed.
	// Existing directory admission must complete that durability work too.
	if unix.Fsync(fd) != nil {
		unix.Close(next)
		return -1, ErrPublish
	}
	return next, nil
}
func (p *publication) parent(entry Entry) (int, string, error) {
	relative := entryName(entry)
	parts := strings.Split(relative, "/")
	fd, err := unix.Dup(p.root)
	if err != nil {
		return -1, "", ErrPublish
	}
	for _, part := range parts[:len(parts)-1] {
		next, e := childDirectory(fd, part, p.uid, true)
		unix.Close(fd)
		if e != nil {
			return -1, "", ErrOwnership
		}
		fd = next
	}
	return fd, parts[len(parts)-1], nil
}
func safeFile(fd, uid int, private bool) bool {
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Uid != uint32(uid) || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 {
		return false
	}
	if private {
		return stat.Mode&07777 == 0600
	}
	return stat.Mode&0022 == 0 && stat.Mode&07000 == 0
}
func readAt(parent int, name string, limit, uid int, private bool) ([]byte, error) {
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "hostsecrets-file")
	defer file.Close()
	if !safeFile(fd, uid, private) {
		return nil, ErrOwnership
	}
	body, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil || len(body) > limit {
		erase(body)
		return nil, ErrPublish
	}
	return body, nil
}
func existsAt(parent int, name string) (bool, error) {
	var st unix.Stat_t
	err := unix.Fstatat(parent, name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	return err == nil, err
}
func pendingName(entry Entry) string {
	return ".host-secret-" + digest([]byte(entry.Destination))[:32] + ".pending"
}

func prepare(ctx context.Context, root int, seed Seed, uid int) (*publication, error) {
	lock, err := unix.Openat(root, ".host-secrets.lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, ErrOwnership
	}
	if !safeFile(lock, uid, true) {
		unix.Close(lock)
		return nil, ErrOwnership
	}
	for {
		err = unix.Flock(lock, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) {
			unix.Close(lock)
			return nil, ErrPublish
		}
		select {
		case <-ctx.Done():
			unix.Close(lock)
			return nil, ErrPublish
		case <-time.After(20 * time.Millisecond):
		}
	}
	p := &publication{root: root, lock: lock, uid: uid, seed: seed}
	success := false
	defer func() {
		if !success {
			p.close()
		}
	}()
	recorded, err := readAt(root, journalName, MaxSeedBytes, uid, true)
	if err == nil {
		accepted, e := ParseSeed(recorded)
		if e != nil || seedDigest(accepted) != seedDigest(seed) {
			return nil, ErrJournal
		}
		// Re-establish directory durability after an interrupted first run.
		if unix.Fsync(root) != nil {
			return nil, ErrJournal
		}
	} else if errors.Is(err, unix.ENOENT) {
		if exists, e := existsAt(root, ownershipName); e != nil || exists {
			return nil, ErrJournal
		}
		// Ownership is established before the first secret file is created.
		// Any existing destination or pending file is unknown and is refused.
		for _, entry := range seed.Entries {
			parent, leaf, e := p.parent(entry)
			if e != nil {
				return nil, e
			}
			for _, name := range []string{leaf, pendingName(entry)} {
				exists, e := existsAt(parent, name)
				if e != nil || exists {
					unix.Close(parent)
					return nil, ErrJournal
				}
			}
			unix.Close(parent)
		}
		body, _ := json.Marshal(seed)
		if err = publishJournal(root, body); err != nil {
			return nil, err
		}
	} else {
		return nil, ErrJournal
	}
	if err = p.loadOwnership(); err != nil {
		return nil, err
	}
	success = true
	return p, nil
}
func publishJournal(root int, body []byte) error { return publishRecord(root, journalName, body) }
func publishRecord(root int, target string, body []byte) error {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return ErrJournal
	}
	name := ".host-secrets-journal-" + hex.EncodeToString(random)
	fd, err := unix.Openat(root, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return ErrJournal
	}
	file := os.NewFile(uintptr(fd), "hostsecrets-journal")
	defer func() { file.Close(); unix.Unlinkat(root, name, 0) }()
	if _, err = file.Write(body); err != nil {
		return ErrJournal
	}
	if err = file.Sync(); err != nil {
		return ErrJournal
	}
	if err = unix.Renameat2(root, name, root, target, unix.RENAME_NOREPLACE); err != nil {
		return ErrJournal
	}
	if err = unix.Fsync(root); err != nil {
		return ErrJournal
	}
	return nil
}
func (p *publication) ready(entry Entry) (bool, error) {
	parent, leaf, err := p.parent(entry)
	if err != nil {
		return false, err
	}
	defer unix.Close(parent)
	file, err := p.openCredential(parent, leaf, entry)
	if errors.Is(err, unix.ENOENT) {
		if p.ownership != nil && orchestratorEntry(entry) {
			return false, ErrOwnership
		}
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, MaxSecretBytes+1))
	defer erase(body)
	if err != nil || len(body) > MaxSecretBytes {
		return false, ErrPublish
	}
	if digest(body) != entry.SHA256 {
		return false, ErrDigest
	}
	if p.ownership != nil && orchestratorEntry(entry) {
		if err = p.finishOwnership(file, entry); err != nil {
			return false, err
		}
	}
	// A previous rename may have succeeded while directory fsync failed.
	// Do not let a verified retry forget that remaining durability work.
	if unix.Fsync(parent) != nil {
		return false, ErrPublish
	}
	return true, nil
}
func (p *publication) publish(entry Entry, body []byte) error {
	if len(body) == 0 || len(body) > MaxSecretBytes || digest(body) != entry.SHA256 {
		return ErrDigest
	}
	ready, err := p.ready(entry)
	if err != nil {
		return err
	}
	if ready {
		return nil
	}
	parent, leaf, err := p.parent(entry)
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	pending := pendingName(entry)
	fd, err := unix.Openat(parent, pending, unix.O_WRONLY|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return ErrPublish
	}
	file := os.NewFile(uintptr(fd), "hostsecrets-credential")
	defer file.Close()
	if !safeFile(fd, p.uid, true) {
		return ErrOwnership
	}
	// This exact temporary name belongs to the already-fsynced seed journal.
	if err = file.Truncate(0); err != nil {
		return ErrPublish
	}
	if _, err = file.Write(body); err != nil {
		return ErrPublish
	}
	if err = file.Sync(); err != nil {
		return ErrPublish
	}
	if err = unix.Renameat2(parent, pending, parent, leaf, unix.RENAME_NOREPLACE); err != nil {
		return ErrPublish
	}
	if err = unix.Fsync(parent); err != nil {
		return ErrPublish
	}
	ready, err = p.ready(entry)
	if err != nil {
		return err
	}
	if !ready {
		return ErrPublish
	}
	return nil
}
