//go:build linux

package vmqual

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func openFailureDiagnosticAt(root, path string) (*os.File, os.FileInfo, error) {
	if !filepath.IsAbs(root) || !filepath.IsAbs(path) || filepath.Dir(filepath.Clean(path)) != filepath.Clean(root) {
		return nil, nil, errors.New("diagnostic path is outside its exact VM state directory")
	}
	rootFD, err := unix.Openat2(unix.AT_FDCWD, filepath.Clean(root), &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return nil, nil, err
	}
	defer unix.Close(rootFD)
	fd, err := unix.Openat2(rootFD, filepath.Base(path), &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV,
	})
	if err != nil {
		return nil, nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, nil, errors.New("open diagnostic file descriptor")
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if !safeFailureDiagnosticInfo(info) {
		_ = file.Close()
		return nil, nil, errors.New("unsafe diagnostic source metadata")
	}
	return file, info, nil
}
