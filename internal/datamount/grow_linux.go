package datamount

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const ext4ResizeFS = 0x40086610

func Grow(ctx context.Context) error {
	device, err := os.Open(Device)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open data device: %w", err)
	}
	defer device.Close()
	var disk unix.Stat_t
	if err := unix.Fstat(int(device.Fd()), &disk); err != nil {
		return err
	}
	if disk.Mode&unix.S_IFMT != unix.S_IFBLK {
		return errors.New("data device is not a block device")
	}
	root, err := os.Open(MountPoint)
	if err != nil {
		return err
	}
	defer root.Close()
	var mount unix.Stat_t
	if err := unix.Fstat(int(root.Fd()), &mount); err != nil {
		return err
	}
	var before unix.Statfs_t
	if err := unix.Fstatfs(int(root.Fd()), &before); err != nil {
		return err
	}
	if mount.Dev != disk.Rdev || mount.Ino != 2 || before.Type != unix.EXT4_SUPER_MAGIC || before.Flags&unix.ST_RDONLY != 0 {
		return errors.New("data growth requires the data device mounted read-write as ext4 at " + MountPoint)
	}
	expectedUUID, err := os.ReadFile("/etc/ts-orch/data-volume-uuid")
	if err != nil {
		return fmt.Errorf("read recorded data UUID: %w", err)
	}
	expectedSerial, err := os.ReadFile("/etc/ts-orch/data-volume-serial")
	if err != nil {
		return fmt.Errorf("read recorded data serial: %w", err)
	}
	serialCommand := exec.CommandContext(ctx, "lsblk", "-dnr", "-o", "SERIAL", "/proc/self/fd/3")
	serialCommand.ExtraFiles = []*os.File{device}
	serial, err := serialCommand.Output()
	if err != nil {
		return fmt.Errorf("read pinned data serial: %w", err)
	}
	if !diskSerial.MatchString(strings.TrimSpace(string(expectedSerial))) || strings.TrimSpace(string(serial)) != strings.TrimSpace(string(expectedSerial)) {
		return errors.New("data growth refused: recorded serial differs from pinned device")
	}
	header := make([]byte, 1024)
	if _, err := device.ReadAt(header, 1024); err != nil {
		return fmt.Errorf("read pinned ext4 superblock: %w", err)
	}
	uuid := fmt.Sprintf("%x-%x-%x-%x-%x", header[104:108], header[108:110], header[110:112], header[112:114], header[114:120])
	if binary.LittleEndian.Uint16(header[56:58]) != 0xef53 || uuid != strings.TrimSpace(string(expectedUUID)) {
		return errors.New("data growth refused: recorded UUID differs from pinned ext4 device")
	}
	rescan := fmt.Sprintf("/sys/dev/block/%d:%d/device/rescan", unix.Major(disk.Rdev), unix.Minor(disk.Rdev))
	if err := os.WriteFile(rescan, []byte("1\n"), 0); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("rescan data device: %w", err)
	}
	bytes, err := device.Seek(0, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("read pinned data capacity: %w", err)
	}
	target := uint64(bytes) / uint64(before.Bsize)
	blocks := uint64(binary.LittleEndian.Uint32(header[4:8]))
	if binary.LittleEndian.Uint32(header[96:100])&0x80 != 0 {
		blocks |= uint64(binary.LittleEndian.Uint32(header[336:340])) << 32
	}
	if target <= blocks {
		return nil
	}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, root.Fd(), ext4ResizeFS, uintptr(unsafe.Pointer(&target))); errno != 0 {
		return fmt.Errorf("grow pinned mounted ext4 filesystem: %w", errno)
	}
	slog.Info("data filesystem grown", "mount", MountPoint, "before_blocks", blocks, "after_blocks", target, "block_size", before.Bsize)
	return nil
}

func Maintain(ctx context.Context) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if err := Grow(ctx); err != nil && ctx.Err() == nil {
				slog.Error("data filesystem growth failed", "error", err)
			}
		}
	}
}
