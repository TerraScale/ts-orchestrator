package releasepush

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func withTrialLock(state string, action func() error) error {
	file, err := os.OpenFile(filepath.Join(state, "nats", "release-lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	return action()
}

func Guard(ctx context.Context, args []string) error {
	if len(args) != 0 || os.Geteuid() != 0 {
		return errors.New("release guard requires root and accepts no arguments")
	}
	state := "/var/lib/ts-orch"
	if _, err := os.Stat(trialFile(state)); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return withTrialLock(state, func() error {
		t, err := readTrial(state)
		if err != nil || t == nil {
			return err
		}
		if time.Now().Before(t.GuardAfter) {
			return nil
		}
		if t.Phase != "intent" {
			if err := quiesceAgent(ctx); err != nil {
				return err
			}
		}
		return restoreTrial(ctx, state, "release guard deadline passed without confirmation")
	})
}

func restoreTrial(ctx context.Context, state, reason string) error {
	t, err := readTrial(state)
	if err != nil || t == nil {
		return err
	}
	if t.Reason == "" {
		t.Reason = reason
	} else if !strings.Contains(t.Reason, reason) {
		t.Reason += "; " + reason
	}
	if t.Phase == "intent" {
		if err := systemctl(ctx, "reset-failed", "ts-orch.servic[e]"); err != nil {
			return err
		}
		if err := systemctl(ctx, "restart", "--no-block", "ts-orch.service"); err != nil {
			return err
		}
		if err := writeJSON(rollbackFile(state), Rollback{SHA: t.SHA, RunID: t.RunID, Reason: t.Reason}); err != nil {
			return err
		}
		return removeIfExists(trialFile(state))
	}
	if t.Binary == "" || t.BinaryBackup == "" || t.UnitBackup == "" {
		return errors.New("release trial does not name both recovery backups")
	}
	if t.Phase != "restoring" && t.Phase != "restored" {
		t.Phase = "restoring"
		if err := writeJSON(trialFile(state), t); err != nil {
			return err
		}
	}
	previousUnit, err := os.ReadFile(t.UnitBackup)
	if err != nil {
		return fmt.Errorf("read recovery unit: %w", err)
	}
	if err := atomicFile(unitPath, previousUnit); err != nil {
		return err
	}
	previous, err := os.ReadFile(t.BinaryBackup)
	if err != nil {
		return fmt.Errorf("read recovery binary: %w", err)
	}
	if err := atomicMode(t.Binary, previous, 0o755); err != nil {
		return err
	}
	if err := systemctl(ctx, "daemon-reload"); err != nil {
		return err
	}
	if err := systemctl(ctx, "reset-failed", "ts-orch.servic[e]"); err != nil {
		return err
	}
	t.Phase = "restored"
	if err := writeJSON(trialFile(state), t); err != nil {
		return err
	}
	if err := writeJSON(rollbackFile(state), Rollback{SHA: t.SHA, RunID: t.RunID, Reason: t.Reason}); err != nil {
		return err
	}
	if err := systemctl(ctx, "restart", "--no-block", "ts-orch.service"); err != nil {
		return err
	}
	return removeIfExists(trialFile(state))
}

func quiesceAgent(ctx context.Context) error {
	if err := systemctl(ctx, "stop", "--no-block", "ts-orch.service"); err != nil {
		return err
	}
	err := systemctl(ctx, "kill", "--signal=SIGKILL", "ts-orch.service")
	if err == nil {
		return nil
	}
	output, stateErr := exec.CommandContext(ctx, "systemctl", "show", "ts-orch.service", "-p", "ActiveState", "--value").Output()
	state := strings.TrimSpace(string(output))
	if stateErr == nil && (state == "inactive" || state == "failed") {
		return nil
	}
	return errors.Join(err, stateErr)
}
