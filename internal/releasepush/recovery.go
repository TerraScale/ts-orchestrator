package releasepush

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
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
	_, recoveryErr := os.Stat(h.Binary + ".recovery")
	if status != "" && recoveryErr == nil {
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

type recoveryRuntime struct {
	SHA     string        `json:"sha"`
	SHA256  string        `json:"sha256"`
	RunID   string        `json:"run_id"`
	BootID  string        `json:"boot_id"`
	Started int64         `json:"started"`
	Window  time.Duration `json:"window"`
}

func recoveryExpired(ctx context.Context, pending trial) (bool, error) {
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return false, err
	}
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		return false, err
	}
	path := filepath.Join(recoveryState, "nats", "release-runtime")
	var runtime recoveryRuntime
	present, err := readRecord(path, &runtime)
	if err != nil {
		return false, err
	}
	if !present || runtime.SHA != pending.SHA || runtime.SHA256 != pending.SHA256 || runtime.RunID != pending.RunID || runtime.BootID != strings.TrimSpace(string(boot)) {
		output, err := exec.CommandContext(ctx, "systemctl", "show", "ts-orch.service", "-p", "ExecMainStartTimestampMonotonic", "-p", "MainPID").Output()
		if err != nil {
			return false, fmt.Errorf("candidate start time unavailable: %w", err)
		}
		properties := map[string]string{}
		for line := range strings.SplitSeq(string(output), "\\n") {
			key, value, ok := strings.Cut(line, "=")
			if ok {
				properties[key] = value
			}
		}
		started, err := strconv.ParseInt(properties["ExecMainStartTimestampMonotonic"], 10, 64)
		if err != nil || started < 0 || started > now.Nano()/1000 {
			return false, fmt.Errorf("invalid candidate monotonic start %q", output)
		}
		if started == 0 {
			return false, nil
		}
		pid, err := strconv.ParseUint(properties["MainPID"], 10, 32)
		if err != nil {
			return false, fmt.Errorf("invalid candidate process %q", output)
		}
		if pid != 0 {
			running, err := os.Stat(fmt.Sprintf("/proc/%d/exe", pid))
			if err != nil {
				return false, err
			}
			installed, err := os.Stat(recoveryBinary)
			if err != nil {
				return false, err
			}
			if !os.SameFile(running, installed) {
				return false, nil
			}
		}
		window := 20 * time.Minute
		if !pending.RecoverAfter.IsZero() {
			window = pending.RecoverAfter.Sub(pending.Installed)
		}
		if window <= 0 {
			return false, errors.New("invalid recovery window")
		}
		runtime = recoveryRuntime{SHA: pending.SHA, SHA256: pending.SHA256, RunID: pending.RunID, BootID: strings.TrimSpace(string(boot)), Started: started * 1000, Window: window}
		if err := writeJSON(path, runtime); err != nil {
			return false, err
		}
	}
	if runtime.Started <= 0 || runtime.Started > now.Nano() || runtime.Window <= 0 {
		return false, errors.New("recovery runtime is damaged")
	}
	return time.Duration(now.Nano()-runtime.Started) >= runtime.Window, nil
}

func recoveryTrial(pending trial, output io.Writer) (*Probation, releaseID, error) {
	self, err := binaryIdentity(recoveryBinary)
	if err != nil {
		return nil, self, err
	}
	if err := settleStaging(recoveryState, recoveryBinary, self); err != nil {
		return nil, self, err
	}
	var current trial
	present, err := readRecord(trialFile(recoveryState), &current)
	if err != nil {
		return nil, self, err
	}
	if !present || !current.names(self) || current.SHA != pending.SHA || current.SHA256 != pending.SHA256 || current.RunID != pending.RunID {
		return nil, self, nil
	}
	return &Probation{state: recoveryState, binary: recoveryBinary, trial: current, output: output}, self, nil
}

func Recovery(ctx context.Context, output io.Writer) (result error) {
	ctx, cancel := context.WithTimeout(ctx, 25*time.Minute)
	defer cancel()
	marker := filepath.Join(recoveryState, "nats", "release-recovery")
	var pending trial
	resuming, err := readRecord(marker, &pending)
	if err != nil {
		return err
	}
	if !resuming {
		var staged, current trial
		stagedPresent, stagedErr := readRecord(stagedTrial(trialFile(recoveryState)), &staged)
		currentPresent, currentErr := readRecord(trialFile(recoveryState), &current)
		if !stagedPresent && !currentPresent {
			return errors.Join(stagedErr, currentErr)
		}
		self, err := binaryIdentity(recoveryBinary)
		if err != nil {
			return err
		}
		if stagedPresent && stagedErr == nil && staged.names(self) {
			pending = staged
		} else {
			if currentErr != nil {
				return currentErr
			}
			if !currentPresent || !current.names(self) {
				return nil
			}
			pending = current
		}
		if !pending.valid() {
			return errors.New("recovery trial is damaged")
		}
		expired, err := recoveryExpired(ctx, pending)
		if err != nil || !expired {
			return err
		}
		if err := writeJSON(marker, pending); err != nil {
			return err
		}
	}
	if !pending.valid() {
		return errors.New("recovery intent is damaged")
	}
	defer func() {
		restartCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Minute)
		defer cancel()
		resetErr := recoveryCommand(restartCtx, "systemctl", "reset-failed", "ts-orch.service")
		startErr := recoveryCommand(restartCtx, "systemctl", "start", "ts-orch.service")
		result = errors.Join(result, resetErr, startErr)
		if result == nil {
			result = removeDurable(marker)
		}
	}()
	probation, _, err := recoveryTrial(pending, output)
	if err != nil {
		return err
	}
	if probation != nil {
		if err := probation.checkPrevious(recoveryBinary + ".prev"); err != nil {
			probation.trial.Failure = "rollback unavailable: " + err.Error()
			fmt.Fprintln(output, probation.trial.Failure)
			return errors.Join(errors.New(probation.trial.Failure), writeJSON(trialFile(recoveryState), probation.trial))
		}
	}

	if probation == nil {
		return nil
	}
	if err := recoveryCommand(ctx, "systemctl", "stop", "ts-orch.service"); err != nil {
		return err
	}
	probation, self, err := recoveryTrial(pending, output)
	if err != nil {
		return err
	}
	if probation == nil {
		return nil
	}
	rollback := probation.rollBack("independent recovery deadline expired")
	if rollback == nil {
		return errors.New(probation.unconfirmed)
	}
	restored, err := binaryIdentity(recoveryBinary)
	if err != nil {
		return err
	}
	if restored == self {
		return rollback
	}
	fmt.Fprintln(output, rollback)
	return nil
}
