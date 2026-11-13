package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
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
	const directory = "/etc/systemd/journald.conf.d"
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
	commands := [][]string{
		{"systemctl", "disable", "--now", "rsyslog.service"},
		{"systemctl", "mask", "rsyslog.service"},
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
