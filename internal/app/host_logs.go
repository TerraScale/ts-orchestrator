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
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", "systemd-journald.service").CombinedOutput(); err != nil {
		return fmt.Errorf("systemd journal is not controllable: %w: %s", err, output)
	}
	rsyslog, err := exec.CommandContext(ctx, "systemctl", "show", "rsyslog.service", "--property=LoadState,UnitFileState,ActiveState").CombinedOutput()
	if err != nil {
		return fmt.Errorf("read syslog service state: %w: %s", err, rsyslog)
	}
	const path = directory + "/60-ts-orch.conf"
	current, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	changed := !bytes.Equal(current, []byte(hostJournalConfig))
	if changed {
		if err := os.MkdirAll(directory, 0755); err != nil {
			return err
		}
		if err := writeAtomicHostFile(path, []byte(hostJournalConfig), 0644); err != nil {
			return err
		}
	}
	var commands [][]string
	status := string(rsyslog)
	if !strings.Contains(status, "LoadState=not-found\n") {
		if !strings.Contains(status, "UnitFileState=masked\n") {
			commands = append(commands,
				[]string{"systemctl", "disable", "--now", "rsyslog.service"},
				[]string{"systemctl", "mask", "rsyslog.service"})
		} else if !strings.Contains(status, "ActiveState=inactive\n") {
			commands = append(commands, []string{"systemctl", "stop", "rsyslog.service"})
		}
	}
	if changed {
		commands = append(commands,
			[]string{"systemctl", "restart", "systemd-journald.service"},
			[]string{"journalctl", "--rotate"})
	}
	for _, command := range commands {
		if output, err := exec.CommandContext(ctx, command[0], command[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("apply host log settings: %s: %w: %s", command[0], err, output)
		}
	}
	return nil
}
