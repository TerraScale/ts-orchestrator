//go:build linux

package security

import (
	"os"
	"syscall"
)

// unixMode extracts the POSIX permission bits of a file.
func unixMode(info os.FileInfo) uint32 {
	if stat, ok := info.Sys().(*statT); ok {
		return uint32(stat.Mode) & 0o777
	}
	return 0
}

// openCommandSigningCredential rejects symlinks and opens nonblocking so a
// FIFO cannot suspend credential validation before the descriptor's Stat.
func openCommandSigningCredential(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
}
