//go:build linux

package security

import "os"

// unixMode extracts the POSIX permission bits of a file.
func unixMode(info os.FileInfo) uint32 {
	if stat, ok := info.Sys().(*statT); ok {
		return uint32(stat.Mode) & 0o777
	}
	return 0
}
