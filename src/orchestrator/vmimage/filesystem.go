package vmimage

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const cacheLockName = ".vmimage-cache.lock"

var stagingNamePattern = regexp.MustCompile(`^\.staging-[0-9a-f]{16}$`)

// ensurePrivateTree creates root and target without accepting a symlink in
// any existing ancestor. Directories owned by this package are normalized to
// 0700; pre-existing ancestors above root are inspected but never chmodded.
func ensurePrivateTree(root, target string) error {
	root = filepath.Clean(root)
	target = filepath.Clean(target)
	if !filepath.IsAbs(root) || !filepath.IsAbs(target) || (target != root && !pathWithin(root, target)) {
		return errors.New("vmimage: private directory target lies outside its root")
	}
	if filepath.Dir(root) == root {
		return errors.New("vmimage: filesystem root is not an admissible artifact root")
	}
	return ensurePrivateTreePlatform(root, target)
}

func ensurePrivateTreeFallback(root, target string) error {
	if err := rejectSymlinkAncestors(root); err != nil {
		return err
	}
	if err := createPrivateDirectory(root); err != nil {
		return err
	}
	if target != root {
		relative, err := filepath.Rel(root, target)
		if err != nil {
			return err
		}
		current := root
		for _, element := range strings.Split(relative, string(filepath.Separator)) {
			if element == "" || element == "." || element == ".." {
				return errors.New("vmimage: private directory contains an unsafe component")
			}
			current = filepath.Join(current, element)
			if err := createPrivateDirectory(current); err != nil {
				return err
			}
		}
	}
	return rejectSymlinkAncestors(target)
}

func createPrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	created := false
	if errors.Is(err, os.ErrNotExist) {
		if err := ensureParentDirectories(path); err != nil {
			return err
		}
		mkdirErr := os.Mkdir(path, 0o700)
		if mkdirErr != nil && !errors.Is(mkdirErr, os.ErrExist) {
			return fmt.Errorf("vmimage: create private directory: %w", mkdirErr)
		}
		created = mkdirErr == nil
		info, err = os.Lstat(path)
	}
	if err != nil {
		return fmt.Errorf("vmimage: inspect private directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("vmimage: private directory must be a real directory, not a symlink")
	}
	if created {
		if err := os.Chmod(path, 0o700); err != nil {
			return fmt.Errorf("vmimage: secure private directory: %w", err)
		}
		if err := syncDir(path); err != nil {
			return fmt.Errorf("vmimage: sync private directory: %w", err)
		}
		if err := syncDir(filepath.Dir(path)); err != nil {
			return fmt.Errorf("vmimage: sync private directory parent: %w", err)
		}
	}
	return verifyDirectory(path)
}

// ensureParentDirectories creates missing ancestors using 0700. Existing
// ancestors retain their modes, but a link or non-directory is always fatal.
func ensureParentDirectories(path string) error {
	parent := filepath.Dir(path)
	if parent == path {
		return nil
	}
	info, err := os.Lstat(parent)
	created := false
	if errors.Is(err, os.ErrNotExist) {
		if err := ensureParentDirectories(parent); err != nil {
			return err
		}
		mkdirErr := os.Mkdir(parent, 0o700)
		if mkdirErr != nil && !errors.Is(mkdirErr, os.ErrExist) {
			return fmt.Errorf("vmimage: create private ancestor: %w", mkdirErr)
		}
		created = mkdirErr == nil
		info, err = os.Lstat(parent)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("vmimage: artifact root has a symlink or non-directory ancestor")
	}
	if created {
		if err := os.Chmod(parent, 0o700); err != nil {
			return fmt.Errorf("vmimage: secure private ancestor: %w", err)
		}
		info, err = os.Lstat(parent)
		if err != nil || info.Mode().Perm() != 0o700 {
			return errors.New("vmimage: created private ancestor has an unsafe mode")
		}
		if err := syncDir(parent); err != nil {
			return fmt.Errorf("vmimage: sync private ancestor: %w", err)
		}
		if err := syncDir(filepath.Dir(parent)); err != nil {
			return fmt.Errorf("vmimage: sync private ancestor parent: %w", err)
		}
	}
	return nil
}

func rejectSymlinkAncestors(path string) error {
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		return errors.New("vmimage: artifact path must be absolute")
	}
	volume := filepath.VolumeName(path)
	current := volume + string(filepath.Separator)
	relative := strings.TrimPrefix(path[len(volume):], string(filepath.Separator))
	for _, element := range strings.Split(relative, string(filepath.Separator)) {
		if element == "" {
			continue
		}
		current = filepath.Join(current, element)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("vmimage: inspect artifact path ancestor: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("vmimage: artifact path ancestor %q is a symlink or non-directory", current)
		}
	}
	return nil
}

func readRegularFile(path string, mode os.FileMode, maxBytes int64) ([]byte, error) {
	directory, directoryMetadata, err := openVerifiedDirectory(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	return readRegularFileAt(directory, directoryMetadata, filepath.Base(path), mode, maxBytes)
}

func verifyExactDirectoryEntries(directory string, expected ...string) error {
	file, _, err := openVerifiedDirectory(directory)
	if err != nil {
		return err
	}
	defer file.Close()
	return verifyExactDirectoryEntriesAt(file, expected...)
}

func openVerifiedDirectory(path string) (*os.File, secureFileMetadata, error) {
	file, metadata, err := secureOpenPath(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, secureFileMetadata{}, err
	}
	if !metadata.directory || metadata.special || metadata.permissions != 0o700 || metadata.uid != uint32(os.Geteuid()) {
		_ = file.Close()
		return nil, secureFileMetadata{}, errors.New("vmimage: cache directory metadata is unsafe")
	}
	return file, metadata, nil
}

func verifyExactDirectoryEntriesAt(directory *os.File, expected ...string) error {
	if _, err := directory.Seek(0, io.SeekStart); err != nil {
		return err
	}
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return err
	}
	actual := make([]string, 0, len(entries))
	for _, entry := range entries {
		actual = append(actual, entry.Name())
	}
	sort.Strings(actual)
	want := append([]string(nil), expected...)
	sort.Strings(want)
	if len(actual) != len(want) {
		return errors.New("vmimage: artifact directory contains an unexpected entry set")
	}
	for index := range actual {
		if actual[index] != want[index] {
			return errors.New("vmimage: artifact directory contains an unexpected entry set")
		}
	}
	return nil
}

func readRegularFileAt(directory *os.File, directoryMetadata secureFileMetadata, name string, mode os.FileMode, maxBytes int64) ([]byte, error) {
	file, metadata, err := secureOpenAt(directory, name, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if err := validateCacheFileMetadata(metadata, directoryMetadata, mode, 1, maxBytes); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != metadata.size {
		return nil, errors.New("vmimage: metadata file changed while it was read")
	}
	after, err := secureMetadata(file)
	if err != nil || after != metadata {
		return nil, errors.New("vmimage: metadata file changed while it was read")
	}
	return data, nil
}

func verifyArtifactAt(directory *os.File, directoryMetadata secureFileMetadata, name string, artifact ArtifactManifest) error {
	file, metadata, err := secureOpenAt(directory, name, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("vmimage: open artifact: %w", err)
	}
	defer file.Close()
	if err := validateCacheFileMetadata(metadata, directoryMetadata, os.FileMode(artifact.expectedMode()), artifact.Size, artifact.Size); err != nil {
		return err
	}
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, artifact.Size+1))
	if err != nil {
		return fmt.Errorf("vmimage: hash artifact: %w", err)
	}
	if written != artifact.Size || hex.EncodeToString(hash.Sum(nil)) != artifact.digest() {
		return errors.New("vmimage: artifact bytes do not match manifest")
	}
	after, err := secureMetadata(file)
	if err != nil || after != metadata {
		return errors.New("vmimage: artifact changed while it was verified")
	}
	return nil
}

func validateCacheFileMetadata(metadata, directory secureFileMetadata, mode os.FileMode, minimumSize, maximumSize int64) error {
	if !metadata.regular || metadata.special || metadata.permissions != mode.Perm() || metadata.uid != uint32(os.Geteuid()) ||
		metadata.links != 1 || metadata.device != directory.device || metadata.size < minimumSize || metadata.size > maximumSize {
		return errors.New("vmimage: cache file type, ownership, links, device, mode, or size is invalid")
	}
	return nil
}

func acquireCacheLock(root string) (*os.File, error) {
	directory, directoryMetadata, err := openVerifiedDirectory(root)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	created := false
	file, metadata, err := secureOpenAt(directory, cacheLockName, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		file, metadata, err = secureOpenAt(directory, cacheLockName, os.O_RDWR, 0)
	} else if err == nil {
		created = true
	}
	if err != nil {
		return nil, fmt.Errorf("vmimage: open cache lock: %w", err)
	}
	if err := lockExclusive(file); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("vmimage: lock cache: %w", err)
	}
	if created {
		if err := file.Chmod(0o600); err != nil {
			_ = unlockFile(file)
			_ = file.Close()
			return nil, err
		}
	}
	metadata, err = secureMetadata(file)
	if err != nil || validateCacheFileMetadata(metadata, directoryMetadata, 0o600, 0, 0) != nil {
		_ = unlockFile(file)
		_ = file.Close()
		return nil, errors.New("vmimage: cache lock metadata is unsafe")
	}
	if created {
		if err := file.Sync(); err != nil {
			_ = unlockFile(file)
			_ = file.Close()
			return nil, err
		}
		if err := directory.Sync(); err != nil {
			_ = unlockFile(file)
			_ = file.Close()
			return nil, err
		}
	}
	return file, nil
}

func releaseCacheLock(file *os.File) {
	if file == nil {
		return
	}
	_ = unlockFile(file)
	_ = file.Close()
}

func recoverStaging(parent string) error {
	directory, directoryMetadata, err := openVerifiedDirectory(parent)
	if err != nil {
		return err
	}
	defer directory.Close()
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if !stagingNamePattern.MatchString(name) {
			continue
		}
		staging, metadata, err := secureOpenAt(directory, name, os.O_RDONLY, 0)
		if err != nil {
			return fmt.Errorf("vmimage: inspect stale staging directory: %w", err)
		}
		if !metadata.directory || metadata.special || metadata.permissions != 0o700 || metadata.uid != uint32(os.Geteuid()) || metadata.device != directoryMetadata.device {
			_ = staging.Close()
			return errors.New("vmimage: stale staging directory metadata is unsafe")
		}
		children, err := staging.ReadDir(-1)
		if err != nil || len(children) > 16 {
			_ = staging.Close()
			return errors.New("vmimage: stale staging directory is invalid")
		}
		for _, child := range children {
			childFile, childMetadata, err := secureOpenAt(staging, child.Name(), os.O_RDONLY, 0)
			if err != nil {
				_ = staging.Close()
				return fmt.Errorf("vmimage: inspect stale staging entry: %w", err)
			}
			_ = childFile.Close()
			if !childMetadata.regular || childMetadata.special || childMetadata.uid != uint32(os.Geteuid()) || childMetadata.device != directoryMetadata.device || childMetadata.links != 1 {
				_ = staging.Close()
				return errors.New("vmimage: stale staging entry metadata is unsafe")
			}
			if err := unlinkChild(staging, child.Name(), false); err != nil {
				_ = staging.Close()
				return err
			}
		}
		if err := staging.Sync(); err != nil {
			_ = staging.Close()
			return err
		}
		if err := staging.Close(); err != nil {
			return err
		}
		if err := unlinkChild(directory, name, true); err != nil {
			return err
		}
		if err := directory.Sync(); err != nil {
			return err
		}
	}
	return nil
}

func removeFileEntry(path string) error {
	directory, metadata, err := secureOpenPath(filepath.Dir(path), os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer directory.Close()
	if !metadata.directory {
		return errors.New("vmimage: removal parent is not a directory")
	}
	err = unlinkChild(directory, filepath.Base(path), false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
