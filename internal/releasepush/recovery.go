package releasepush

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	recoveryBinary      = "/usr/local/bin/terrascale-orchestrator"
	recoveryState       = "/var/lib/ts-orch"
	recoveryUnit        = "ts-orch-release-recovery.service"
	recoveryTimer       = "ts-orch-release-recovery.timer"
	recoveryServiceText = `[Unit]
Description=Recover an unconfirmed orchestrator binary
After=local-fs.target
[Service]
Type=oneshot
ExecStart=/usr/local/bin/terrascale-orchestrator.recovery release recover
TimeoutStartSec=30min
`
	recoveryTimerText = `[Unit]
Description=Check unconfirmed orchestrator binary deadlines
[Timer]
OnBootSec=15s
OnUnitActiveSec=1min
AccuracySec=1s
[Install]
WantedBy=timers.target
`
)

func recoveryCommand(ctx context.Context, name string, args ...string) error {
	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", name, err, output)
	}
	return nil
}

func (h *Handler) prepareRecovery(ctx context.Context) (time.Time, error) {
	if h.Binary != recoveryBinary || h.runningBinary != h.Binary || filepath.Dir(filepath.Dir(h.TrialFile)) != recoveryState {
		return time.Time{}, nil
	}
	output, err := exec.CommandContext(ctx, "systemctl", "show", "ts-orch.service", "-p", "TimeoutStartUSec", "-p", "TimeoutStopUSec", "-p", "RestartUSec").Output()
	if err != nil {
		return time.Time{}, fmt.Errorf("recovery needs loaded service bounds: %w", err)
	}
	bounds := map[string]time.Duration{}
	for line := range strings.SplitSeq(string(output), "\n") {
		key, text, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		duration, err := time.ParseDuration(strings.ReplaceAll(strings.Join(strings.Fields(text), ""), "min", "m"))
		if err != nil || duration < 0 {
			return time.Time{}, fmt.Errorf("invalid recovery service bound %q", text)
		}
		bounds[key] = duration
	}
	if len(bounds) != 3 {
		return time.Time{}, errors.New("recovery needs three finite service bounds")
	}
	wait := bounds["TimeoutStopUSec"] + bounds["RestartUSec"] + max(bounds["TimeoutStartUSec"], 10*time.Minute) + probationWait + 30*time.Second
	directory, err := os.MkdirTemp("", "release-recovery-")
	if err != nil {
		return time.Time{}, err
	}
	defer os.RemoveAll(directory)
	for name, text := range map[string]string{recoveryUnit: recoveryServiceText, recoveryTimer: recoveryTimerText} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(text), 0644); err != nil {
			return time.Time{}, err
		}
	}
	status, _ := h.probation.status()
	if status != "" {
		if _, err := os.Stat(h.Binary + ".recovery"); err != nil {
			return time.Time{}, fmt.Errorf("unconfirmed updater has no independent recovery executable: %w", err)
		}
		if err := recoveryCommand(ctx, "systemctl", "is-enabled", "--quiet", recoveryTimer); err != nil {
			return time.Time{}, err
		}
		if err := recoveryCommand(ctx, "systemctl", "start", recoveryTimer); err != nil {
			return time.Time{}, err
		}
		return time.Now().Add(wait), nil
	}
	{
		source, err := os.Open("/proc/self/exe")
		if err != nil {
			return time.Time{}, err
		}
		defer source.Close()
		next := h.Binary + ".recovery.next"
		defer os.Remove(next)
		target, err := os.OpenFile(next, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0755)
		if err != nil {
			return time.Time{}, err
		}
		_, err = io.Copy(target, source)
		err = errors.Join(err, target.Chmod(0755), target.Sync(), target.Close())
		if err != nil {
			return time.Time{}, err
		}
		if err := os.Rename(next, h.Binary+".recovery"); err != nil {
			return time.Time{}, err
		}
		if err := syncDirectory(filepath.Dir(h.Binary)); err != nil {
			return time.Time{}, err
		}
	}
	if err := recoveryCommand(ctx, "systemd-analyze", "verify", "--man=no", filepath.Join(directory, recoveryUnit), filepath.Join(directory, recoveryTimer)); err != nil {
		return time.Time{}, err
	}
	units := filepath.Join(filepath.Dir(h.Binary), "ts-orch-release-recovery")
	if err := os.MkdirAll(units, 0755); err != nil {
		return time.Time{}, err
	}
	for name, text := range map[string]string{recoveryUnit: recoveryServiceText, recoveryTimer: recoveryTimerText} {
		if err := writeState(filepath.Join(units, name), []byte(text)); err != nil {
			return time.Time{}, err
		}
	}
	if err := recoveryCommand(ctx, "systemctl", "link", filepath.Join(units, recoveryUnit), filepath.Join(units, recoveryTimer)); err != nil {
		return time.Time{}, err
	}
	if err := recoveryCommand(ctx, "systemctl", "daemon-reload"); err != nil {
		return time.Time{}, err
	}
	if err := recoveryCommand(ctx, "systemctl", "enable", "--now", recoveryTimer); err != nil {
		return time.Time{}, err
	}
	return time.Now().Add(wait), nil
}

func Recovery(ctx context.Context, output io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, 25*time.Minute)
	defer cancel()
	marker := filepath.Join(recoveryState, "nats", "release-recovery")
	var pending trial
	resuming, err := readRecord(marker, &pending)
	if err != nil {
		return err
	}
	if !resuming {
		self, err := binaryIdentity(recoveryBinary)
		if err != nil {
			return err
		}
		var staged trial
		present, err := readRecord(stagedTrial(trialFile(recoveryState)), &staged)
		if present && err == nil && staged.names(self) {
			pending = staged
		} else {
			present, err = readRecord(trialFile(recoveryState), &pending)
			if err != nil {
				return err
			}
			if !present || !pending.names(self) {
				return nil
			}
		}
		if !pending.valid() {
			return errors.New("recovery trial is damaged")
		}
		deadline := pending.RecoverAfter
		if deadline.IsZero() {
			deadline = pending.Installed.Add(20 * time.Minute)
		}
		if time.Now().Before(deadline) {
			return nil
		}
		if err := writeJSON(marker, pending); err != nil {
			return err
		}
	}
	if !pending.valid() {
		return errors.New("recovery intent is damaged")
	}
	if err := recoveryCommand(ctx, "systemctl", "stop", "ts-orch.service"); err != nil {
		return err
	}
	self, err := binaryIdentity(recoveryBinary)
	if err != nil {
		return err
	}
	if err := settleStaging(recoveryState, recoveryBinary, self); err != nil {
		return err
	}
	var current trial
	present, err := readRecord(trialFile(recoveryState), &current)
	if err != nil {
		return err
	}
	if present && current.names(self) && current.SHA == pending.SHA && current.SHA256 == pending.SHA256 && current.RunID == pending.RunID {
		p := &Probation{state: recoveryState, binary: recoveryBinary, trial: current, output: output}
		result := p.rollBack("independent recovery deadline expired")
		if result == nil {
			return errors.New(p.unconfirmed)
		}
		restored, err := binaryIdentity(recoveryBinary)
		if err != nil {
			return err
		}
		if restored == self {
			return result
		}
		fmt.Fprintln(output, result)
	}
	if err := recoveryCommand(ctx, "systemctl", "reset-failed", "ts-orch.servic[e]"); err != nil {
		return err
	}
	if err := recoveryCommand(ctx, "systemctl", "start", "ts-orch.service"); err != nil {
		return err
	}
	return removeDurable(marker)
}
