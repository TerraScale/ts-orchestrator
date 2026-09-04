package vmguest

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func atomicWrite(root, relative string, data []byte, mode os.FileMode) error {
	if !validRelativePath(relative) || len(data) == 0 || mode.Perm() != mode || mode&^0o777 != 0 {
		return errors.New("vmguest: write parameters are invalid")
	}
	target, parent, err := secureTarget(root, relative, true)
	if err != nil {
		return err
	}
	if info, err := os.Lstat(target); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("vmguest: write target is not a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("vmguest: inspect write target")
	}
	file, err := os.CreateTemp(parent, ".vmguest-write-*")
	if err != nil {
		return errors.New("vmguest: create temporary file")
	}
	temporary := file.Name()
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(temporary)
		}
	}()
	if err := file.Chmod(mode); err != nil {
		return errors.New("vmguest: set temporary file mode")
	}
	if _, err := file.Write(data); err != nil {
		return errors.New("vmguest: write temporary file")
	}
	if err := file.Sync(); err != nil {
		return errors.New("vmguest: sync temporary file")
	}
	if err := file.Close(); err != nil {
		return errors.New("vmguest: close temporary file")
	}
	if err := os.Rename(temporary, target); err != nil {
		return errors.New("vmguest: publish file")
	}
	if err := syncDirectory(parent); err != nil {
		return err
	}
	ok = true
	return nil
}

func boundedRead(root, relative string, limit int) ([]byte, error) {
	if !validRelativePath(relative) || limit <= 0 {
		return nil, errors.New("vmguest: read parameters are invalid")
	}
	target, _, err := secureTarget(root, relative, false)
	if err != nil {
		return nil, err
	}
	before, err := os.Lstat(target)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("vmguest: read target is not a regular file")
	}
	if before.Size() < 0 || before.Size() > int64(limit) {
		return nil, errors.New("vmguest: read target exceeds the size limit")
	}
	file, err := os.Open(target)
	if err != nil {
		return nil, errors.New("vmguest: open read target")
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() {
		return nil, errors.New("vmguest: read target changed during open")
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, errors.New("vmguest: read target")
	}
	if len(data) > limit {
		return nil, errors.New("vmguest: read target exceeds the size limit")
	}
	return data, nil
}

func secureTarget(root, relative string, create bool) (string, string, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == string(filepath.Separator) || !validRelativePath(relative) {
		return "", "", errors.New("vmguest: storage path is invalid")
	}
	if create {
		if err := os.MkdirAll(root, 0o700); err != nil {
			return "", "", errors.New("vmguest: create storage root")
		}
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return "", "", errors.New("vmguest: storage root is not a directory")
	}
	parts := strings.Split(relative, string(filepath.Separator))
	parent := root
	for _, part := range parts[:len(parts)-1] {
		parent = filepath.Join(parent, part)
		info, err := os.Lstat(parent)
		if errors.Is(err, os.ErrNotExist) && create {
			if err := os.Mkdir(parent, 0o700); err != nil {
				return "", "", errors.New("vmguest: create storage directory")
			}
			info, err = os.Lstat(parent)
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", "", errors.New("vmguest: storage directory is unsafe")
		}
	}
	target := filepath.Join(parent, parts[len(parts)-1])
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", "", fmt.Errorf("vmguest: storage target escapes root")
	}
	return target, parent, nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return errors.New("vmguest: open storage directory")
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return errors.New("vmguest: sync storage directory")
	}
	return nil
}
