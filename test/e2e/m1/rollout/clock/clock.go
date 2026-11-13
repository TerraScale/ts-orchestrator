package clock

import (
	"os"
	"path/filepath"
	"strconv"
	"time"
	"unsafe"
)

func Now() time.Time {
	now := time.Now()
	if len(os.Args) < 3 {
		return now
	}
	data, err := os.ReadFile(filepath.Join(os.Args[2], "clock-offset"))
	if err != nil {
		return now
	}
	offset, err := strconv.ParseInt(string(data), 10, 64)
	if err != nil {
		panic(err)
	}
	type reading struct {
		wall uint64
		ext  int64
		loc  *time.Location
	}
	original := *(*reading)(unsafe.Pointer(&now))
	shifted := now.Add(time.Duration(offset))
	if original.wall>>63 != 0 {
		(*reading)(unsafe.Pointer(&shifted)).ext = original.ext
	}
	return shifted
}

func Since(start time.Time) time.Duration { return Now().Sub(start) }
