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

// readClock reads the kernel's NTP state through a read-only adjtimex.
func readClock() *ClockView {
	var state unix.Timex
	status, err := unix.Adjtimex(&state)
	if err != nil {
		return nil
	}
	offset := float64(state.Offset) / 1e6 // microseconds unless STA_NANO
	if state.Status&unix.STA_NANO != 0 {
		offset = float64(state.Offset) / 1e9
	}
	return &ClockView{
		Synchronized:    status != unix.TIME_ERROR && state.Status&(unix.STA_UNSYNC|unix.STA_CLOCKERR) == 0,
		OffsetSeconds:   offset,
		MaxErrorSeconds: float64(state.Maxerror) / 1e6,
	}
}
