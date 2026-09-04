package vmimage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

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
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != mode || info.Size() <= 0 || info.Size() > maxBytes {
		return nil, errors.New("vmimage: metadata file type, mode, or size is invalid")
	}
	return os.ReadFile(path)
}

func verifyExactDirectoryEntries(directory string, expected ...string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	actual := make([]string, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("vmimage: artifact entry is not a regular non-symlink file")
		}
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
