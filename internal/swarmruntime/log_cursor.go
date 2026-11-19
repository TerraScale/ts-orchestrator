package swarmruntime

import (
	"encoding/binary"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

const LogErrorAttribute = "terrascale.log.error"
const logCursorAttribute = "user.ts-orch.log-cursor"

type logCursor struct {
	Base uint64
	Tail uint64
}

func readLogCursor(file *os.File) (logCursor, bool, error) {
	var data [16]byte
	n, err := unix.Fgetxattr(int(file.Fd()), logCursorAttribute, data[:])
	if errors.Is(err, unix.ENODATA) {
		return logCursor{}, false, nil
	}
	if err != nil {
		return logCursor{}, false, err
	}
	if n != len(data) {
		return logCursor{}, false, errors.New("invalid runtime log cursor")
	}
	return logCursor{binary.BigEndian.Uint64(data[:8]), binary.BigEndian.Uint64(data[8:])}, true, nil
}

func writeLogCursor(file *os.File, cursor logCursor) error {
	var data [16]byte
	binary.BigEndian.PutUint64(data[:8], cursor.Base)
	binary.BigEndian.PutUint64(data[8:], cursor.Tail)
	return unix.Fsetxattr(int(file.Fd()), logCursorAttribute, data[:], 0)
}

func appendRuntimeLog(file *os.File, data []byte, size int64) (next int64, err error) {
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		return size, err
	}
	defer func() { err = errors.Join(err, unix.Flock(int(file.Fd()), unix.LOCK_UN)) }()
	if size+int64(len(data)) > logSegmentBytes {
		size, err = keepLogTail(file, size)
		if err != nil {
			return size, err
		}
	}
	n, err := file.Write(data)
	return size + int64(n), err
}

func readRuntimeLog(file *os.File, follow bool) (data []byte, cursor logCursor, synchronized bool, err error) {
	if err = unix.Flock(int(file.Fd()), unix.LOCK_SH); err != nil {
		return
	}
	defer func() { err = errors.Join(err, unix.Flock(int(file.Fd()), unix.LOCK_UN)) }()
	cursor, synchronized, err = readLogCursor(file)
	if err != nil {
		return
	}
	if follow && !synchronized {
		err = errors.New("task logger has no compaction cursor; follow requires a task started by the current release")
		return
	}
	before, err := file.Stat()
	if err != nil {
		return
	}
	data, err = io.ReadAll(io.LimitReader(file, logSegmentBytes))
	if err != nil {
		return
	}
	after, err := file.Stat()
	if err != nil {
		return
	}
	if before.Size() != after.Size() || after.Size() != int64(len(data)) || !before.ModTime().Equal(after.ModTime()) || cursor.Tail > uint64(len(data)) || (cursor.Tail != 0 && cursor.Tail < uint64(len(logGap))) || (cursor.Tail == 0 && cursor.Base != 0) {
		err = errors.New("runtime log changed during snapshot or compaction is incomplete")
	}
	return
}
