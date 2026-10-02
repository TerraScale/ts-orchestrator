//go:build linux

package observability

import "golang.org/x/sys/unix"

func statFilesystem(path string) (FilesystemView, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return FilesystemView{}, err
	}
	blockSize := uint64(stat.Bsize)
	return FilesystemView{SizeBytes: stat.Blocks * blockSize, AvailBytes: stat.Bavail * blockSize,
		FreeBytes: stat.Bfree * blockSize, Files: stat.Files, FilesFree: stat.Ffree}, nil
}
