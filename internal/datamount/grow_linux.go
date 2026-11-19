package datamount

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

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
	if mount.Dev != disk.Rdev || before.Type != unix.EXT4_SUPER_MAGIC || before.Flags&unix.ST_RDONLY != 0 {
		return errors.New("data growth requires the data device mounted read-write as ext4 at " + MountPoint)
	}
	rescan := fmt.Sprintf("/sys/dev/block/%d:%d/device/rescan", unix.Major(disk.Rdev), unix.Minor(disk.Rdev))
	if err := os.WriteFile(rescan, []byte("1\n"), 0); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("rescan data device: %w", err)
	}
	output, err := exec.CommandContext(ctx, "resize2fs", Device).CombinedOutput()
	if err != nil {
		return fmt.Errorf("grow mounted data filesystem: %w: %s", err, strings.TrimSpace(string(output)))
	}
	var after unix.Statfs_t
	if err := unix.Fstatfs(int(root.Fd()), &after); err != nil {
		return err
	}
	if after.Blocks > before.Blocks {
		slog.Info("data filesystem grown", "mount", MountPoint, "before_blocks", before.Blocks, "after_blocks", after.Blocks, "block_size", after.Bsize)
	}
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
