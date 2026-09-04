//go:build linux

package vmimage

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func publishDirectory(staging, destination string) error {
	parent, _, err := secureOpenPath(filepath.Dir(staging), os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer parent.Close()
	if filepath.Dir(staging) != filepath.Dir(destination) {
		return unix.EXDEV
	}
	return unix.Renameat2(int(parent.Fd()), filepath.Base(staging), int(parent.Fd()), filepath.Base(destination), unix.RENAME_NOREPLACE)
}

func publishDownload(staging, target string) error {
	parent, _, err := secureOpenPath(filepath.Dir(staging), os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer parent.Close()
	if filepath.Dir(staging) != filepath.Dir(target) {
		return unix.EXDEV
	}
	if err := unix.Linkat(int(parent.Fd()), filepath.Base(staging), int(parent.Fd()), filepath.Base(target), 0); err != nil {
		return err
	}
	return unix.Unlinkat(int(parent.Fd()), filepath.Base(staging), 0)
}
