package foundation

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"io"
	"os"

	"github.com/TerraScale/ts-orchestrator/internal/region"
	"golang.org/x/sys/unix"
)

const netBirdStoreRoot = "/var/lib/terrascale/netbird"
const custodyMetadataLimit = 256 << 10

type storeBinding struct {
	StoreGeneration, InstanceID, BootVolumeID, RecipeSHA256, PhysicalScopeSHA256 string
}

type custodyInode struct{ Device, Inode uint64 }

type custodyRecord struct {
	Binding                   storeBinding
	Root, Store, Data, Config custodyInode
}

type custodyAnchor struct {
	file, parent *os.File
	name         string
	identity     custodyInode
	mode         uint32
}

// storeCustody proves local inode custody; current remote authority is checked separately.
type storeCustody struct {
	anchors                            map[string]*custodyAnchor
	order                              []string
	root, store, data, config, account *os.File
	record                             custodyRecord
	closed                             bool
}

func managerStoreBinding(ctx context.Context, manager region.VerifiedNetBirdManager) (storeBinding, error) {
	physical, err := manager.PhysicalBinding(ctx)
	if err != nil {
		return storeBinding{}, err
	}
	binding := storeBinding{manager.StoreGeneration(), physical.InstanceID, physical.BootVolumeID, physical.RecipeSHA256, physical.PhysicalScopeSHA256}
	if binding.StoreGeneration == "" || binding.InstanceID == "" || binding.BootVolumeID == "" || binding.RecipeSHA256 == "" || binding.PhysicalScopeSHA256 == "" {
		return storeBinding{}, errors.New("NetBird custody requires the original physical store binding")
	}
	return binding, nil
}

func openStoreCustody(ctx context.Context, manager region.VerifiedNetBirdManager, _ region.FoundationResolver) (_ *storeCustody, err error) {
	binding, err := managerStoreBinding(ctx, manager)
	if err != nil {
		return nil, err
	}
	if os.Geteuid() != 0 {
		return nil, errors.New("NetBird store custody requires root")
	}
	s := &storeCustody{anchors: make(map[string]*custodyAnchor)}
	defer func() {
		if err != nil {
			err = errors.Join(err, s.Close())
		}
	}()
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parent := os.NewFile(uintptr(fd), "NetBird custody parent")
	if err := s.anchor("/", parent, nil, "", 0); err != nil {
		parent.Close()
		return nil, err
	}
	for _, name := range []string{"var", "lib", "terrascale", "netbird"} {
		child, err := custodyDirectory(parent, name, true)
		if err != nil {
			return nil, err
		}
		mode := uint32(0)
		if name == "netbird" {
			mode = 0700
		}
		if err := s.anchor("parent/"+name, child, parent, name, mode); err != nil {
			child.Close()
			return nil, err
		}
		parent = child
	}
	s.root = parent
	lockFD, err := unix.Openat(int(s.root.Fd()), ".owner.lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, errors.New("cannot open NetBird custody lock")
	}
	lock := os.NewFile(uintptr(lockFD), "NetBird custody lock")
	if err := s.anchor("lock", lock, s.root, ".owner.lock", 0600); err != nil {
		lock.Close()
		return nil, err
	}
	if err := unix.Flock(lockFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, errors.New("NetBird store is already owned by another process")
	}
	if err := s.root.Sync(); err != nil {
		return nil, err
	}
	var record custodyRecord
	found, err := s.loadJSON(s.root, "custody.json", "custody", &record, 64<<10)
	if err != nil {
		return nil, err
	}
	root := s.anchors["parent/netbird"].identity
	if found {
		if record.Binding != binding || record.Root != root {
			return nil, errors.New("NetBird custody belongs to another physical store or root inode")
		}
		s.record = record
	} else {
		if err := custodyAbsent(s.root, "store"); err != nil {
			return nil, errors.New("untracked NetBird store must be preserved for recovery")
		}
		s.record = custodyRecord{Binding: binding, Root: root}
		if err := s.saveJSON(s.root, "custody.json", "custody", s.record, 64<<10); err != nil {
			return nil, err
		}
	}
	if err := custodyAbsent(s.root, "store"); err == nil {
		return s, s.check()
	} else if !errors.Is(err, unix.EEXIST) {
		return nil, err
	}
	if s.record.Store == (custodyInode{}) || s.record.Data == (custodyInode{}) || s.record.Config == (custodyInode{}) {
		return nil, errors.New("partial NetBird store has no retained custody; preserve it")
	}
	if err := s.pinStore(); err != nil {
		return nil, err
	}
	if s.anchors["store"].identity != s.record.Store || s.anchors["data"].identity != s.record.Data || s.anchors["config"].identity != s.record.Config {
		return nil, errors.New("NetBird store inode was replaced; preserve it for recovery")
	}
	return s, s.check()
}

func custodyIdentity(stat unix.Stat_t) custodyInode {
	return custodyInode{uint64(stat.Dev), stat.Ino}
}

func (s *storeCustody) anchor(key string, file, parent *os.File, name string, mode uint32) error {
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return err
	}
	kind := stat.Mode & unix.S_IFMT
	if stat.Uid != 0 || stat.Gid != 0 || stat.Mode&0022 != 0 || kind != unix.S_IFDIR && kind != unix.S_IFREG ||
		mode != 0 && stat.Mode&07777 != mode || kind == unix.S_IFREG && stat.Nlink != 1 {
		return errors.New("NetBird custody inode is not private and root owned")
	}
	if kind == unix.S_IFREG && mode != 0600 || mode == 0600 && kind != unix.S_IFREG {
		return errors.New("NetBird custody expected a directory")
	}
	if old := s.anchors[key]; old != nil {
		old.file.Close()
	} else {
		s.order = append(s.order, key)
	}
	s.anchors[key] = &custodyAnchor{file, parent, name, custodyIdentity(stat), stat.Mode}
	return nil
}

func custodyDirectory(parent *os.File, name string, create bool) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if create && errors.Is(err, unix.ENOENT) {
		if err := unix.Mkdirat(int(parent.Fd()), name, 0700); err != nil {
			return nil, err
		}
		if err := parent.Sync(); err != nil {
			return nil, err
		}
		fd, err = unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	}
	if err != nil {
		return nil, errors.New("cannot open private NetBird custody directory")
	}
	return os.NewFile(uintptr(fd), "NetBird custody directory"), nil
}

func custodyAbsent(parent *os.File, name string) error {
	var stat unix.Stat_t
	err := unix.Fstatat(int(parent.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err == nil {
		return unix.EEXIST
	}
	return err
}

func (s *storeCustody) check() error {
	if s == nil || s.closed {
		return errors.New("NetBird store custody is closed")
	}
	for _, key := range s.order {
		a := s.anchors[key]
		var stat unix.Stat_t
		if err := unix.Fstat(int(a.file.Fd()), &stat); err != nil || custodyIdentity(stat) != a.identity || stat.Mode != a.mode || stat.Uid != 0 || stat.Gid != 0 || stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Nlink != 1 {
			return errors.New("NetBird retained custody inode changed")
		}
		if a.parent != nil {
			if err := unix.Fstatat(int(a.parent.Fd()), a.name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil || custodyIdentity(stat) != a.identity || stat.Mode != a.mode {
				return errors.New("NetBird custody path was substituted")
			}
		}
	}
	return nil
}

func (s *storeCustody) binding() storeBinding { return s.record.Binding }
func (s *storeCustody) prepared() bool {
	return s != nil && !s.closed && s.store != nil && s.data != nil && s.config != nil
}
func (s *storeCustody) rootPath() string { return netBirdStoreRoot }

func (s *storeCustody) current(ctx context.Context, manager region.VerifiedNetBirdManager) error {
	binding, err := managerStoreBinding(ctx, manager)
	if err != nil {
		return err
	}
	if binding != s.record.Binding {
		return errors.New("NetBird manager no longer binds the retained physical store")
	}
	return s.check()
}

func (s *storeCustody) pinStore() error {
	store, err := custodyDirectory(s.root, "store", false)
	if err != nil {
		return err
	}
	if err := s.anchor("store", store, s.root, "store", 0700); err != nil {
		store.Close()
		return err
	}
	s.store = store
	data, err := custodyDirectory(store, "data", false)
	if err != nil {
		return err
	}
	if err := s.anchor("data", data, store, "data", 0700); err != nil {
		data.Close()
		return err
	}
	s.data = data
	config, err := s.openFile(store, "config.yaml", "config")
	if err != nil {
		return err
	}
	s.config = config
	return s.check()
}

func (s *storeCustody) retainStore() error {
	s.record.Store = s.anchors["store"].identity
	s.record.Data = s.anchors["data"].identity
	s.record.Config = s.anchors["config"].identity
	return s.saveJSON(s.root, "custody.json", "custody", s.record, 64<<10)
}

func (s *storeCustody) prepareGenesis(ctx context.Context, manager region.VerifiedNetBirdManager, config []byte) error {
	if len(config) == 0 || len(config) > custodyMetadataLimit || s.prepared() {
		return errors.New("NetBird genesis requires an unprepared store and bounded configuration")
	}
	if err := s.current(ctx, manager); err != nil {
		return err
	}
	if err := custodyAbsent(s.root, "store"); err != nil {
		return errors.New("NetBird genesis refuses existing store data")
	}
	if err := manager.ClaimGenesis(ctx); err != nil {
		return err
	}
	store, err := custodyDirectory(s.root, "store", true)
	if err != nil {
		return err
	}
	if err := s.anchor("store", store, s.root, "store", 0700); err != nil {
		store.Close()
		return err
	}
	s.store = store
	data, err := custodyDirectory(store, "data", true)
	if err != nil {
		return err
	}
	if err := s.anchor("data", data, store, "data", 0700); err != nil {
		data.Close()
		return err
	}
	s.data = data
	if err := s.writeBytes(store, "config.yaml", "config", config, true); err != nil {
		return err
	}
	s.config = s.anchors["config"].file
	// The consumed durable claim intentionally survives partial local writes.

	return s.retainStore()
}

func (s *storeCustody) acceptRestoredStore(ctx context.Context, manager region.VerifiedNetBirdManager, expected []byte) error {
	if s.prepared() {
		return errors.New("NetBird restore cannot replace an already prepared store")
	}
	if err := s.current(ctx, manager); err != nil {
		return err
	}
	if err := s.pinStore(); err != nil {
		return err
	}
	if err := s.verifyConfiguration(expected); err != nil {
		return err
	}
	if err := s.ready(); err != nil {
		return err
	}
	if err := s.root.Sync(); err != nil {
		return err
	}
	return s.retainStore()
}

func (s *storeCustody) verifyConfiguration(expected []byte) error {
	if !s.prepared() || len(expected) == 0 || len(expected) > custodyMetadataLimit {
		return errors.New("NetBird configuration is not prepared")
	}
	if err := s.check(); err != nil {
		return err
	}
	wire, err := custodyRead(s.config, custodyMetadataLimit)
	defer clear(wire)
	if err != nil || !bytes.Equal(wire, expected) {
		return errors.New("NetBird retained configuration differs from current admitted configuration")
	}
	return s.check()
}

func (s *storeCustody) ready() error {
	if !s.prepared() {
		return errors.New("NetBird store is not prepared")
	}
	if err := s.check(); err != nil {
		return err
	}
	for _, name := range []string{"store.db", "idp.db"} {
		key := "database/" + name
		file := (*os.File)(nil)
		if a := s.anchors[key]; a != nil {
			file = a.file
		} else {
			var err error
			file, err = s.openFile(s.data, name, key)
			if err != nil {
				return errors.New("NetBird SQLite store is missing or unsafe")
			}
		}
		header := make([]byte, 16)
		if _, err := file.ReadAt(header, 0); err != nil || !bytes.Equal(header, []byte("SQLite format 3\x00")) {
			return errors.New("NetBird store has no valid SQLite header")
		}
	}
	return s.check()
}

func (s *storeCustody) prepareRuntime(ctx context.Context, manager region.VerifiedNetBirdManager, ingress []byte) error {
	if !s.prepared() || len(ingress) == 0 || len(ingress) > 64<<10 {
		return errors.New("NetBird runtime requires prepared store and bounded ingress configuration")
	}
	if err := s.current(ctx, manager); err != nil {
		return err
	}
	var file *os.File
	if a := s.anchors["ingress"]; a != nil {
		file = a.file
	} else {
		if err := custodyAbsent(s.root, "ingress.Caddyfile"); err == nil {
			if err := s.writeBytes(s.root, "ingress.Caddyfile", "ingress", ingress, true); err != nil {
				return err
			}
		} else if !errors.Is(err, unix.EEXIST) {
			return err
		}
		var err error
		file, err = s.openFile(s.root, "ingress.Caddyfile", "ingress")
		if err != nil {
			return err
		}
	}
	wire, err := custodyRead(file, 64<<10)
	defer clear(wire)
	if err != nil || !bytes.Equal(wire, ingress) {
		return errors.New("NetBird ingress configuration changed")
	}
	for _, name := range []string{"foundation-tls", "foundation-caddy-config"} {
		if s.anchors[name] != nil {
			continue
		}
		dir, err := custodyDirectory(s.data, name, true)
		if err != nil {
			return err
		}
		if err := s.anchor(name, dir, s.data, name, 0700); err != nil {
			dir.Close()
			return err
		}
	}
	return s.check()
}

func (s *storeCustody) openFile(parent *os.File, name, key string) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "NetBird private state")
	if err := s.anchor(key, file, parent, name, 0600); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func custodyRead(file *os.File, limit int) ([]byte, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	wire, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil || len(wire) > limit {
		clear(wire)
		return nil, errors.New("NetBird private state exceeds its bound or cannot be read")
	}
	return wire, nil
}

func (s *storeCustody) loadJSON(parent *os.File, name, key string, out any, limit int) (bool, error) {
	if err := s.check(); err != nil {
		return false, err
	}
	var file *os.File
	if a := s.anchors[key]; a != nil {
		file = a.file
	} else {
		var err error
		file, err = s.openFile(parent, name, key)
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
	}
	wire, err := custodyRead(file, limit)
	defer clear(wire)
	if err != nil || json.Unmarshal(wire, out, json.RejectUnknownMembers(true)) != nil {
		return false, errors.New("invalid NetBird private state")
	}
	return true, s.check()
}

func (s *storeCustody) saveJSON(parent *os.File, name, key string, value any, limit int) error {
	if err := s.check(); err != nil {
		return err
	}
	wire, err := json.Marshal(value)
	defer clear(wire)
	if err != nil || len(wire) > limit {
		return errors.New("cannot encode bounded NetBird private state")
	}
	return s.writeBytes(parent, name, key, wire, false)
}

func (s *storeCustody) writeBytes(parent *os.File, name, key string, wire []byte, exclusive bool) error {
	if err := s.check(); err != nil {
		return err
	}
	if a := s.anchors[key]; a == nil {
		if err := custodyAbsent(parent, name); err != nil {
			return errors.New("NetBird refuses untracked private state replacement")
		}
	} else if exclusive {
		return errors.New("NetBird private state already exists")
	}
	temporary := ".custody-" + rand.Text()
	fd, err := unix.Openat(int(parent.Fd()), temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	defer unix.Unlinkat(int(parent.Fd()), temporary, 0)
	file := os.NewFile(uintptr(fd), "NetBird private state staging")
	_, err = file.Write(wire)
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err != nil {
		return err
	}
	if err := s.check(); err != nil {
		return err
	}
	flags := uint(0)
	if exclusive || s.anchors[key] == nil {
		flags = unix.RENAME_NOREPLACE
	}
	if err := unix.Renameat2(int(parent.Fd()), temporary, int(parent.Fd()), name, flags); err != nil {
		return err
	}
	if err := parent.Sync(); err != nil {
		return err
	}
	_, err = s.openFile(parent, name, key)
	if err != nil {
		return err
	}
	return s.check()
}

func (s *storeCustody) loadRuntime(out any) (bool, error) {
	return s.loadJSON(s.root, "runtime.json", "runtime", out, custodyMetadataLimit)
}
func (s *storeCustody) saveRuntime(value any) error {
	return s.saveJSON(s.root, "runtime.json", "runtime", value, custodyMetadataLimit)
}
func (s *storeCustody) loadOwner(out any) (bool, error) {
	return s.loadJSON(s.root, "owner.json", "owner", out, custodyMetadataLimit)
}
func (s *storeCustody) saveOwner(value any) error {
	return s.saveJSON(s.root, "owner.json", "owner", value, custodyMetadataLimit)
}

func (s *storeCustody) accountDirectory(create bool) (*os.File, error) {
	if !s.prepared() {
		return nil, errors.New("NetBird account escrow requires prepared store custody")
	}
	if err := s.check(); err != nil {
		return nil, err
	}
	if s.account != nil {
		return s.account, nil
	}
	dir, err := custodyDirectory(s.data, "terrascale-identity", create)
	if err != nil {
		return nil, err
	}
	if err := s.anchor("account-dir", dir, s.data, "terrascale-identity", 0700); err != nil {
		dir.Close()
		return nil, err
	}
	s.account = dir
	return dir, nil
}

func (s *storeCustody) loadAccount(out any) (bool, error) {
	if !s.prepared() {
		return false, errors.New("NetBird account escrow requires prepared store custody")
	}
	if err := s.check(); err != nil {
		return false, err
	}
	if s.account == nil {
		if err := custodyAbsent(s.data, "terrascale-identity"); err == nil {
			return false, nil
		} else if !errors.Is(err, unix.EEXIST) {
			return false, err
		}
	}
	dir, err := s.accountDirectory(false)
	if err != nil {
		return false, err
	}
	return s.loadJSON(dir, "account.json", "account", out, 64<<10)
}

func (s *storeCustody) saveAccount(value any) error {
	dir, err := s.accountDirectory(true)
	if err != nil {
		return err
	}
	return s.saveJSON(dir, "account.json", "account", value, 64<<10)
}

func (s *storeCustody) Close() error {
	if s == nil || s.closed {
		return nil
	}
	s.closed = true
	var err error
	for i := len(s.order) - 1; i >= 0; i-- {
		err = errors.Join(err, s.anchors[s.order[i]].file.Close())
	}
	return err
}
