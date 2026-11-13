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

func ensureHostLogs(ctx context.Context) error {
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
	const path = directory + "/60-ts-orch.conf"
	current, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if !bytes.Equal(current, []byte(hostJournalConfig)) {
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
		if err := os.MkdirAll(directory, 0755); err != nil {
			return err
		}
		if err := publishHostJournal(path); err != nil {
			return err
		}
	}
	active, err := hostJournalActive(ctx, path)
	if err != nil {
		return fmt.Errorf("journal activation unknown: %w", err)
	}
	if !active {
		output, restartErr := runHostLogCommand(ctx, "systemctl", "restart", "systemd-journald.service")
		if active, err := hostJournalActive(ctx, path); !active {
			return fmt.Errorf("restart journal not confirmed: %w: %s", errors.Join(restartErr, err, errors.New("journal start is not later than configuration")), output)
		}
		if output, err := runHostLogCommand(ctx, "journalctl", "--rotate"); err != nil {
			return fmt.Errorf("rotate journal: %w: %s", err, output)
		}
	}
	rsyslog, err := runHostLogCommand(ctx, "systemctl", "show", "rsyslog.service", "--property=LoadState,UnitFileState,ActiveState")
	if err != nil {
		return fmt.Errorf("read syslog service state: %w: %s", err, rsyslog)
	}
	status := string(rsyslog)
	if strings.Contains(status, "LoadState=not-found\n") {
		return nil
	}
	requiredBy, err := hostSyslogRequiredBy(ctx)
	if err != nil {
		return err
	}
	if len(requiredBy) != 0 {
		return fmt.Errorf("syslog disable skipped: required by enabled units %s; journal settings applied", strings.Join(requiredBy, ", "))
	}
	var commands [][]string
	if !strings.Contains(status, "UnitFileState=masked\n") {
		commands = append(commands,
			[]string{"disable", "--now", "rsyslog.service"},
			[]string{"mask", "rsyslog.service"})
	} else if !strings.Contains(status, "ActiveState=inactive\n") {
		commands = append(commands, []string{"stop", "rsyslog.service"})
	}
	for _, args := range commands {
		if output, err := runHostLogCommand(ctx, "systemctl", args...); err != nil {
			return fmt.Errorf("handle syslog: %w: %s", err, output)
		}
	}
	return nil
}

func hostJournalActive(ctx context.Context, path string) (bool, error) {
	file, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	output, err := runHostLogCommand(ctx, "systemctl", "--timestamp=us+utc", "show", "systemd-journald.service", "--property=ActiveState,ActiveEnterTimestamp")
	if err != nil {
		return false, fmt.Errorf("read journal start time: %w: %s", err, output)
	}
	var started time.Time
	for line := range strings.SplitSeq(string(output), "\n") {
		if value, ok := strings.CutPrefix(line, "ActiveEnterTimestamp="); ok {
			started, err = time.Parse("Mon 2006-01-02 15:04:05.999999 MST", value)
			if err != nil {
				return false, fmt.Errorf("read journal start time: %w", err)
			}
		}
	}
	now := time.Now()
	return strings.Contains(string(output), "ActiveState=active\n") && !file.ModTime().After(now) && !started.After(now) && started.After(file.ModTime()), nil
}

func publishHostJournal(path string) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".60-ts-orch-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if _, err := file.Write([]byte(hostJournalConfig)); err != nil {
		return err
	}
	if err := file.Chown(0, 0); err != nil {
		return err
	}
	if err := file.Chmod(0644); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	return syncHostLogDirectory(filepath.Dir(path))
}

func syncHostLogDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
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
	command.Env = append(command.Environ(), "LC_ALL=C", "TZ=UTC")
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
