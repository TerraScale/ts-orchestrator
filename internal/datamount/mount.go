package datamount

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const Device = "/dev/oracleoci/oraclevdb"
const MountPoint = "/var/lib/ts-data"

var diskSerial = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)

type Report struct {
	Serial         string `json:"serial"`
	MountPoint     string `json:"mount_point"`
	Device         string `json:"device"`
	UUID           string `json:"uuid"`
	FilesystemType string `json:"filesystem_type"`
	SizeBytes      int64  `json:"size_bytes"`
}

func Read(ctx context.Context) (*Report, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "findmnt", "--json", "--mountpoint", MountPoint, "--output", "TARGET,SOURCE,UUID,FSTYPE").Output()
	if err != nil {
		return nil, fmt.Errorf("data directory is not a mount point: %w", err)
	}
	var table struct {
		Filesystems []struct{ Target, Source, UUID, Fstype string }
	}
	if err := json.Unmarshal(output, &table); err != nil {
		return nil, err
	}
	if len(table.Filesystems) != 1 || table.Filesystems[0].Target != MountPoint {
		return nil, fmt.Errorf("data mount report requires exactly %s", MountPoint)
	}
	mount := table.Filesystems[0]
	expected, err := filepath.EvalSymlinks(Device)
	if err != nil {
		return nil, err
	}
	actual, err := filepath.EvalSymlinks(mount.Source)
	if err != nil {
		return nil, err
	}
	if actual != expected {
		return nil, fmt.Errorf("data mount device %s resolves to %s, expected %s (%s)", mount.Source, actual, Device, expected)
	}
	size, err := exec.CommandContext(ctx, "blockdev", "--getsize64", Device).Output()
	if err != nil {
		return nil, fmt.Errorf("data device size: %w", err)
	}
	bytes, err := strconv.ParseInt(strings.TrimSpace(string(size)), 10, 64)
	if err != nil || bytes <= 0 {
		return nil, fmt.Errorf("invalid data device size %q", size)
	}
	identity := make(map[string]string)
	for _, field := range []string{"MODEL", "SERIAL", "WWN"} {
		value, err := exec.CommandContext(ctx, "lsblk", "-dnr", "-o", field, Device).Output()
		if err != nil {
			return nil, fmt.Errorf("data device %s: %w", field, err)
		}
		identity[field] = strings.TrimSpace(string(value))
	}
	if identity["MODEL"] != "BlockVolume" || !diskSerial.MatchString(identity["SERIAL"]) || identity["WWN"] != "0x"+identity["SERIAL"] {
		return nil, fmt.Errorf("invalid data device identity")
	}
	return &Report{Serial: identity["SERIAL"], MountPoint: mount.Target, Device: Device, UUID: mount.UUID, FilesystemType: mount.Fstype, SizeBytes: bytes}, nil
}
