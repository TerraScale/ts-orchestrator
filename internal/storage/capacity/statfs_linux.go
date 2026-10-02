//go:build linux

package capacity

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// Statfs measures the filesystem containing path.
func Statfs(path string) (FSStat, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return FSStat{}, fmt.Errorf("statfs %s: %w", path, err)
	}
	blockSize := uint64(stat.Bsize)
	return FSStat{
		TotalBytes: stat.Blocks * blockSize, FreeBytes: stat.Bfree * blockSize, AvailBytes: stat.Bavail * blockSize,
		InodesTotal: stat.Files, InodesFree: stat.Ffree,
	}, nil
}
