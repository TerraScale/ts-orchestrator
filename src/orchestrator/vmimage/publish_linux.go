//go:build linux

package vmimage

import "golang.org/x/sys/unix"

func publishDirectory(staging, destination string) error {
	return unix.Renameat2(unix.AT_FDCWD, staging, unix.AT_FDCWD, destination, unix.RENAME_NOREPLACE)
}
