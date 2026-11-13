package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const hostJournalConfig = `[Journal]
Storage=persistent
SystemMaxUse=512M
RuntimeMaxUse=128M
SystemMaxFileSize=64M
MaxRetentionSec=7day
ForwardToSyslog=no
`

func ensureHostLogs(ctx context.Context, state string) error {
	ctx, cancel := context.WithTimeout(ctx, 29*time.Second)
	defer cancel()
	if os.Geteuid() != 0 {
		return errors.New("host logging requires root")
	}
	journal, err := os.Stat("/run/systemd/journal/socket")
	if err != nil {
		return fmt.Errorf("systemd journal socket unavailable: %w", err)
	}
	if journal.Mode()&os.ModeSocket == 0 {
		return errors.New("systemd journal socket unavailable")
	}
	const directory = "/etc/systemd/journald.conf.d"
	for parent := directory; ; parent = filepath.Dir(parent) {
		err := unix.Faccessat(unix.AT_FDCWD, parent, unix.W_OK, unix.AT_EACCESS)
		if errors.Is(err, unix.ENOENT) && parent != "/" {
			continue
		}
		if err != nil {
			return fmt.Errorf("journal configuration directory is not writable: %w", err)
		}
		break
	}
	if output, err := runHostLogCommand(ctx, "systemctl", "is-active", "--quiet", "systemd-journald.service"); err != nil {
		return fmt.Errorf("systemd journal is not controllable: %w: %s", err, output)
	}
	rsyslog, err := runHostLogCommand(ctx, "systemctl", "show", "rsyslog.service", "--property=LoadState,UnitFileState,ActiveState")
	if err != nil {
		return fmt.Errorf("read syslog service state: %w: %s", err, rsyslog)
	}
	status := string(rsyslog)
	var preserveSyslog error
	if !strings.Contains(status, "LoadState=not-found\n") {
		requiredBy, err := hostSyslogRequiredBy(ctx)
		if err != nil {
			return err
		}
		if len(requiredBy) != 0 {
			preserveSyslog = fmt.Errorf("syslog disable skipped: required by enabled units %s; journal settings applied", strings.Join(requiredBy, ", "))
		}
	}
	const path = directory + "/60-ts-orch.conf"
	current, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	pending := filepath.Join(state, "host-logs-activation-pending")
	_, err = os.Stat(pending)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	activate := err == nil
	changed := !bytes.Equal(current, []byte(hostJournalConfig))
	if changed {
		if err := os.MkdirAll(directory, 0755); err != nil {
			return err
		}
		if err := os.MkdirAll(state, 0700); err != nil {
			return err
		}
		if err := writeAtomicHostFile(pending, []byte("pending\n"), 0600); err != nil {
			return err
		}
		if err := writeAtomicHostFile(path, []byte(hostJournalConfig), 0644); err != nil {
			return err
		}
		activate = true
	}
	var commands [][]string
	if preserveSyslog == nil && !strings.Contains(status, "LoadState=not-found\n") {
		if !strings.Contains(status, "UnitFileState=masked\n") {
			commands = append(commands,
				[]string{"systemctl", "disable", "--now", "rsyslog.service"},
				[]string{"systemctl", "mask", "rsyslog.service"})
		} else if !strings.Contains(status, "ActiveState=inactive\n") {
			commands = append(commands, []string{"systemctl", "stop", "rsyslog.service"})
		}
	}
	if activate {
		commands = append(commands,
			[]string{"systemctl", "restart", "systemd-journald.service"},
			[]string{"journalctl", "--rotate"})
	}
	for _, command := range commands {
		if output, err := runHostLogCommand(ctx, command[0], command[1:]...); err != nil {
			return fmt.Errorf("apply host log settings: %s: %w: %s", command[0], err, output)
		}
	}
	if activate {
		if err := os.Remove(pending); err != nil {
			return err
		}
		directory, err := os.Open(state)
		if err != nil {
			return err
		}
		defer directory.Close()
		if err := directory.Sync(); err != nil {
			return err
		}
	}
	return preserveSyslog
}

func hostSyslogRequiredBy(ctx context.Context) ([]string, error) {
	output, err := runHostLogCommand(ctx, "systemctl", "list-unit-files", "--state=enabled,enabled-runtime", "--no-legend", "--no-pager")
	if err != nil {
		return nil, fmt.Errorf("list enabled syslog dependents: %w: %s", err, output)
	}
	args := []string{"show", "--property=Id,Requires,UnitFileState"}
	for line := range strings.SplitSeq(string(output), "\n") {
		if fields := strings.Fields(line); len(fields) != 0 && !strings.Contains(fields[0], "@.") {
			args = append(args, fields[0])
		}
	}
	for _, directory := range []string{"/etc/systemd/system", "/run/systemd/system"} {
		for _, relation := range []string{"wants", "requires", "upholds"} {
			instances, err := filepath.Glob(filepath.Join(directory, "*."+relation, "*@*"))
			if err != nil {
				return nil, err
			}
			for _, instance := range instances {
				if name := filepath.Base(instance); !strings.Contains(name, "@.") {
					args = append(args, name)
				}
			}
		}
	}
	if len(args) == 2 {
		return nil, nil
	}
	output, err = runHostLogCommand(ctx, "systemctl", args...)
	if err != nil {
		return nil, fmt.Errorf("read enabled syslog dependents: %w: %s", err, output)
	}
	var requiredBy []string
	for block := range strings.SplitSeq(string(output), "\n\n") {
		var id string
		var requires, enabled bool
		for line := range strings.SplitSeq(block, "\n") {
			if value, ok := strings.CutPrefix(line, "Id="); ok {
				id = value
			}
			if value, ok := strings.CutPrefix(line, "UnitFileState="); ok {
				enabled = value == "enabled" || value == "enabled-runtime"
			}
			if value, ok := strings.CutPrefix(line, "Requires="); ok {
				for unit := range strings.FieldsSeq(value) {
					requires = requires || unit == "rsyslog.service"
				}
			}
		}
		if requires && enabled {
			requiredBy = append(requiredBy, id)
		}
	}
	return requiredBy, nil
}

func runHostLogCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, name, args...)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		err := unix.Kill(-command.Process.Pid, unix.SIGKILL)
		if errors.Is(err, unix.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	command.WaitDelay = 500 * time.Millisecond
	output, err := command.CombinedOutput()
	if command.Process != nil {
		_ = unix.Kill(-command.Process.Pid, unix.SIGKILL)
	}
	return output, err
}
