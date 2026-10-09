//go:build linux

package vaultsecret

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

func openMemoryDirectory(directory string) (*os.Root, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, errors.New("Vault delivery requires a clean absolute directory")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return nil, errors.New("Vault delivery directory must exist with mode 0700")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	fail := func() (*os.Root, error) {
		root.Close()
		return nil, errors.New("Vault delivery needs an owner-only tmpfs directory with swap disabled")
	}
	file, err := root.Open(".")
	if err != nil {
		return fail()
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil || info.Mode().Perm() != 0o700 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return fail()
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(int(file.Fd()), &fs); err != nil || fs.Type != unix.TMPFS_MAGIC {
		return fail()
	}
	if !SwapOff() {
		return fail()
	}
	return root, nil
}

// RequireMemoryFilesystem checks the filesystem beneath host-owned runtime
// directories whose group must traverse them to read workload-owned files.
func RequireMemoryFilesystem(directory string) error {
	file, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer file.Close()
	var fs unix.Statfs_t
	if err := unix.Fstatfs(int(file.Fd()), &fs); err != nil || fs.Type != unix.TMPFS_MAGIC || !SwapOff() {
		return errors.New("Vault runtime files require tmpfs with swap disabled")
	}
	return nil
}

// SwapOff reports whether no swap is active. sysinfo(2) needs no /proc, so
// it also answers inside units with ProcSubset=pid, such as the controller.
func SwapOff() bool {
	var info unix.Sysinfo_t
	return unix.Sysinfo(&info) == nil && info.Totalswap == 0
}
