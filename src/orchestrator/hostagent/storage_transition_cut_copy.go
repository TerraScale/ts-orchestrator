package hostagent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
)

type cutTreeEntry struct {
	Path      string
	Directory bool
	Bytes     int64
	SHA256    string
}
type cutTree struct {
	SHA256 string
	Files  int64
	Bytes  int64
	Device uint64
	Inode  uint64
}

// inspectCutTree hashes file content and ordered relative names independently
// of ownership metadata. Links and special files never enter the copy scope.
func inspectCutTree(ctx context.Context, root *os.Root, limits controltransition.Limits) (cutTree, error) {
	var result cutTree
	info, err := root.Stat(".")
	if err != nil {
		return result, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return result, errors.New("hostagent: source identity unavailable")
	}
	result.Device, result.Inode = uint64(st.Dev), st.Ino
	hash := sha256.New()
	count := int64(0)
	err = walkCutTree(ctx, root, limits.MaxStoreFiles, func(name string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		count++
		if count > limits.MaxStoreFiles {
			return errors.New("hostagent: source file count exceeds plan")
		}
		if strings.HasSuffix(name, ".storage-copy-partial") {
			return errors.New("hostagent: source uses reserved copy name")
		}
		entry := cutTreeEntry{Path: name, Directory: d.IsDir()}
		info, err := root.Lstat(name)
		if err != nil {
			return err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("hostagent: unsafe source entry")
		}
		if !info.IsDir() {
			if !info.Mode().IsRegular() || st.Nlink != 1 {
				return errors.New("hostagent: source links and special files refused")
			}
			if info.Size() < 0 || info.Size() > limits.MaxStoreBytes-result.Bytes {
				return errors.New("hostagent: source exceeds byte bound")
			}
			f, err := root.Open(name)
			if err != nil {
				return err
			}
			opened, err := f.Stat()
			if err != nil || !os.SameFile(info, opened) {
				f.Close()
				return errors.New("hostagent: source changed during open")
			}
			h := sha256.New()
			n, readErr := io.Copy(h, io.LimitReader(cutContextReader{ctx: ctx, r: f}, info.Size()+1))
			closeErr := f.Close()
			if err := errors.Join(readErr, closeErr); err != nil {
				return err
			}
			if n != info.Size() {
				return errors.New("hostagent: source changed while hashing")
			}
			entry.Bytes = n
			entry.SHA256 = hex.EncodeToString(h.Sum(nil))
			result.Bytes += n
			result.Files++
		}
		raw, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		hash.Write(raw)
		hash.Write([]byte{'\n'})
		return nil
	})
	if err != nil {
		return cutTree{}, err
	}
	result.SHA256 = hex.EncodeToString(hash.Sum(nil))
	return result, nil
}

// copyCutTree resumes only exact completed files. A fixed private temporary
// name belongs to this plan's copy operation and is never authoritative. Each
// file and directory is synced before the final independent whole-tree read.
func copyCutTree(ctx context.Context, source, destination *os.Root, limits controltransition.Limits) error {
	err := walkCutTree(ctx, source, limits.MaxStoreFiles, func(name string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() {
			if name != "." {
				if err := destination.Mkdir(name, 0700); err != nil && !errors.Is(err, fs.ErrExist) {
					return err
				}
			}
			info, err := destination.Lstat(name)
			if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("hostagent: unsafe copy directory")
			}
			return nil
		}
		info, err := source.Lstat(name)
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("hostagent: unsafe copy source")
		}
		if info.Size() < 0 || info.Size() > limits.MaxStoreBytes {
			return errors.New("hostagent: copy file exceeds bound")
		}
		// Existing complete files are compared, never replaced to force recovery.
		if existing, err := destination.Lstat(name); err == nil {
			if !existing.Mode().IsRegular() || existing.Size() != info.Size() {
				return errors.New("hostagent: conflicting copy file")
			}
			return compareCutFile(ctx, source, destination, name, info.Size())
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		temporary := name + ".storage-copy-partial"
		if old, err := destination.Lstat(temporary); err == nil {
			st, ok := old.Sys().(*syscall.Stat_t)
			if !ok || !old.Mode().IsRegular() || st.Nlink != 1 || int(st.Uid) != os.Geteuid() {
				return errors.New("hostagent: unsafe partial copy")
			}
			if err := destination.Remove(temporary); err != nil {
				return err
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		input, err := source.Open(name)
		if err != nil {
			return err
		}
		defer input.Close()
		output, err := destination.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		n, copyErr := io.Copy(output, io.LimitReader(cutContextReader{ctx: ctx, r: input}, info.Size()+1))
		if copyErr == nil && n != info.Size() {
			copyErr = errors.New("hostagent: source changed during copy")
		}
		if copyErr == nil {
			copyErr = output.Sync()
		}
		closeErr := output.Close()
		if err := errors.Join(copyErr, closeErr); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := destination.Rename(temporary, name); err != nil {
			return err
		}
		return syncCutDirectory(destination, path.Dir(name))
	})
	if err != nil {
		return err
	}
	return walkCutTree(ctx, destination, limits.MaxStoreFiles, func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return syncCutDirectory(destination, name)
		}
		return nil
	})
}
func syncCutDirectory(root *os.Root, name string) error {
	f, err := root.Open(name)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}
func compareCutFile(ctx context.Context, a, b *os.Root, name string, size int64) error {
	left, err := a.Open(name)
	if err != nil {
		return err
	}
	defer left.Close()
	right, err := b.Open(name)
	if err != nil {
		return err
	}
	defer right.Close()
	lh, rh := sha256.New(), sha256.New()
	if _, err := io.Copy(lh, io.LimitReader(cutContextReader{ctx: ctx, r: left}, size+1)); err != nil {
		return err
	}
	if _, err := io.Copy(rh, io.LimitReader(cutContextReader{ctx: ctx, r: right}, size+1)); err != nil {
		return err
	}
	if hex.EncodeToString(lh.Sum(nil)) != hex.EncodeToString(rh.Sum(nil)) {
		return errors.New("hostagent: retained copy content differs")
	}
	return nil
}

func openCutRoot(directory string, private bool) (*os.Root, error) {
	return openCutRootOwned(directory, private, "", 0)
}

// Only the exact signed source DataVolume may have its stopped service's
// dedicated owner. Every ancestor is opened without following a symlink;
// /proc/self/fd binds os.Root to that already checked descriptor, never a
// second lookup through the original path.
func openCutRootOwned(directory string, private bool, volume string, uid uint32) (*os.Root, error) {
	bad := errors.New("hostagent: unsafe source copy ancestry")
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, bad
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() { unix.Close(fd) }()
	current := "/"
	check := func(final bool) error {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			return err
		}
		permitted := st.Uid == 0 || uid != 0 && st.Uid == uid && volume != "" && (current == volume || strings.HasPrefix(current, volume+"/"))
		if !permitted || st.Mode&0022 != 0 {
			return bad
		}
		if final && private && (st.Uid != 0 || st.Mode&0777 != 0700) {
			return bad
		}
		return nil
	}
	if err := check(directory == "/"); err != nil {
		return nil, err
	}
	for component := range strings.SplitSeq(strings.TrimPrefix(directory, "/"), "/") {
		if component == "" {
			continue
		}
		next, err := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		unix.Close(fd)
		fd = next
		current = filepath.Join(current, component)
		if err := check(current == directory); err != nil {
			return nil, err
		}
	}
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		return nil, err
	}
	info, err := root.Stat(".")
	if err != nil {
		root.Close()
		return nil, err
	}
	after, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(after.Dev) != uint64(before.Dev) || after.Ino != before.Ino {
		root.Close()
		return nil, bad
	}
	return root, nil
}

// Read directory entries in bounded batches before sorting; fs.WalkDir would
// allocate an unbounded single-directory listing before applying our limit.
func walkCutTree(ctx context.Context, root *os.Root, limit int64, visit fs.WalkDirFunc) error {
	if limit <= 0 {
		return errors.New("hostagent: positive tree limit required")
	}
	total := int64(0)
	var walk func(string, fs.DirEntry) error
	walk = func(name string, entry fs.DirEntry) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		total++
		if total > limit {
			return errors.New("hostagent: source tree exceeds file bound")
		}
		if err := visit(name, entry, nil); err != nil {
			return err
		}
		if !entry.IsDir() {
			return nil
		}
		directory, err := root.Open(name)
		if err != nil {
			return err
		}
		var children []fs.DirEntry
		for {
			batch, readErr := directory.ReadDir(128)
			children = append(children, batch...)
			if int64(len(children)) > limit-total {
				directory.Close()
				return errors.New("hostagent: source directory exceeds file bound")
			}
			if errors.Is(readErr, io.EOF) {
				break
			}
			if readErr != nil {
				directory.Close()
				return readErr
			}
			if err := ctx.Err(); err != nil {
				directory.Close()
				return err
			}
		}
		if err := directory.Close(); err != nil {
			return err
		}
		slices.SortFunc(children, func(a, b fs.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
		for _, child := range children {
			if err := walk(path.Join(name, child.Name()), child); err != nil {
				return err
			}
		}
		return nil
	}
	info, err := root.Lstat(".")
	if err != nil {
		return err
	}
	return walk(".", fs.FileInfoToDirEntry(info))
}

type cutContextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r cutContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}
