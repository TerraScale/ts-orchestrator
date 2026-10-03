//go:build linux

package observability

import "golang.org/x/sys/unix"

func statFilesystem(path string) (FilesystemView, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return FilesystemView{}, err
	}
	blockSize := uint64(stat.Bsize)
	view := FilesystemView{SizeBytes: stat.Blocks * blockSize, AvailBytes: stat.Bavail * blockSize,
		FreeBytes: stat.Bfree * blockSize, Files: stat.Files, FilesFree: stat.Ffree}
	var info unix.Stat_t
	if err := unix.Stat(path, &info); err == nil {
		view.Device = uint64(info.Dev) // Dev is narrower on some architectures.
	}
	return view, nil
}
