//go:build sandboxvm

package vmqualruntime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/vmimage"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
)

// injectNoCloudRoot uses cloud-init's local seed directory. The pinned kernel
// supports ext4, while cloud-init block discovery requires FAT or ISO9660.
// Only the private, stopped per-VM root copy may be passed to this function.
func injectNoCloudRoot(ctx context.Context, root, payloadDir string, seed vmimage.NoCloudSeed) error {
	debugfs, err := resolveHostExecutable("debugfs")
	if err != nil {
		return err
	}
	fsck, err := resolveHostExecutable("e2fsck")
	if err != nil {
		return err
	}
	run := func(write bool, request string, limit int) ([]byte, error) {
		args := []string{"-R", request, root}
		if write {
			args = append([]string{"-w"}, args...)
		}
		command := exec.CommandContext(ctx, debugfs, args...)
		command.Dir, command.Env = payloadDir, hostToolEnvironment()
		command.WaitDelay = 2 * time.Second
		out, diagnostic := &limitedBuffer{limit: limit}, &limitedBuffer{limit: 64 << 10}
		command.Stdout, command.Stderr = out, diagnostic
		if err := command.Run(); err != nil {
			return nil, fmt.Errorf("vmqual: access NoCloud root filesystem: %w", err)
		}
		return out.buffer.Bytes(), nil
	}
	for _, directory := range []string{"/var/lib/cloud", "/var/lib/cloud/seed", "/var/lib/cloud/seed/nocloud"} {
		// debugfs reports an existing directory on stderr with exit status zero.
		// Verify the inode type after the request instead of trusting exit status.
		if _, err := run(true, "mkdir "+directory, 64<<10); err != nil {
			return err
		}
		stat, err := run(false, "stat "+directory, 64<<10)
		if err != nil || !strings.Contains(string(stat), "Type: directory") {
			return errors.New("vmqual: NoCloud path is not a directory in the root filesystem")
		}
	}
	for _, input := range []struct {
		name string
		data []byte
	}{{"meta-data", seed.MetaData}, {"network-config", seed.NetworkConfig}, {"user-data", seed.UserData}} {
		if len(input.data) == 0 || len(input.data) > 128<<20 {
			return errors.New("vmqual: NoCloud input exceeds its filesystem bound")
		}
		target := "/var/lib/cloud/seed/nocloud/" + input.name
		if _, err := run(true, "write "+input.name+" "+target, 64<<10); err != nil {
			return err
		}
		got, err := run(false, "cat "+target, len(input.data)+1)
		if err != nil || !bytes.Equal(got, input.data) {
			return errors.New("vmqual: NoCloud root filesystem content did not round-trip exactly")
		}
	}
	seen := make(map[string]bool)
	for index, file := range seed.RootFiles {
		if err := file.Validate(); err != nil || seen[file.Path] {
			return errors.New("vmqual: invalid or repeated NoCloud root payload")
		}
		seen[file.Path] = true
		parent := ""
		for _, part := range strings.Split(strings.TrimPrefix(path.Dir(file.Path), "/"), "/") {
			parent += "/" + part
			if _, err := run(true, "mkdir "+parent, 64<<10); err != nil {
				return err
			}
			stat, err := run(false, "stat "+parent, 64<<10)
			if err != nil || !strings.Contains(string(stat), "Type: directory") {
				return errors.New("vmqual: root payload parent is not a directory")
			}
		}
		name := fmt.Sprintf("root-file-%d", index)
		if err := writeNewStateFile(filepath.Join(payloadDir, name), file.Content); err != nil {
			return err
		}
		stat, err := run(false, "stat "+file.Path, 64<<10)
		if err != nil || len(stat) != 0 {
			return errors.New("vmqual: root payload destination already exists")
		}
		if _, err := run(true, "write "+name+" "+file.Path, 64<<10); err != nil {
			return err
		}
		// Stage private material under root while the guest is stopped. The
		// bootstrap script creates and verifies any declared final service owner.
		for _, field := range []string{fmt.Sprintf("mode 0%o", 0100000|file.Mode), "uid 0", "gid 0"} {
			if _, err := run(true, "set_inode_field "+file.Path+" "+field, 64<<10); err != nil {
				return err
			}
		}
		stat, err = run(false, "stat "+file.Path, 64<<10)
		modeMatch := regexp.MustCompile(`Type: regular\s+Mode:\s+0*([0-7]+)`).FindSubmatch(stat)
		mode := uint64(0)
		if len(modeMatch) == 2 {
			mode, _ = strconv.ParseUint(string(modeMatch[1]), 8, 32)
		}
		if err != nil || mode != uint64(file.Mode) || !regexp.MustCompile(`User:\s+0\s+Group:\s+0\s`).Match(stat) {
			return errors.New("vmqual: root payload ownership or mode did not round-trip exactly")
		}
		got, err := run(false, "cat "+file.Path, len(file.Content)+1)
		if err != nil || !bytes.Equal(got, file.Content) {
			return errors.New("vmqual: root payload content did not round-trip exactly")
		}
	}
	if err := vmqual.SyncPath(root); err != nil {
		return err
	}
	check := exec.CommandContext(ctx, fsck, "-fn", root)
	check.Env, check.WaitDelay = hostToolEnvironment(), 2*time.Second
	check.Stdout, check.Stderr = &limitedBuffer{limit: 64 << 10}, &limitedBuffer{limit: 64 << 10}
	if err := check.Run(); err != nil {
		return fmt.Errorf("vmqual: verify seeded root filesystem: %w", err)
	}
	return nil
}
