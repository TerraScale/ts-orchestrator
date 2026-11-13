package releasepush

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/deploy/m1"
)

const unitPath = "/etc/systemd/system/ts-orch.service"
const guardService = "ts-orch-release-guard.service"
const guardTimer = "ts-orch-release-guard.timer"

func Unit(ctx context.Context, args []string, output io.Writer) error {
	data, err := m1.Files.ReadFile("ts-orch.service")
	if err != nil {
		return err
	}
	if len(args) == 0 {
		_, err := output.Write(data)
		return err
	}
	if len(args) != 3 || !filepath.IsAbs(args[1]) || !filepath.IsAbs(args[2]) || os.Geteuid() != 0 {
		return errors.New("release unit requires root and install|restore|guard-install <absolute binary path> <absolute state path>")
	}
	return withTrialLock(args[2], func() error {
		switch args[0] {
		case "install":
			return installUnit(ctx, data, args[1], args[2])
		case "restore":
			return restoreTrial(ctx, args[2], "release failed before serving")
		case "guard-install":
			return installGuard(ctx, args[1], args[2])
		default:
			return errors.New("release unit accepts install, restore or guard-install")
		}
	})
}

func stageUnits(ctx context.Context, units map[string][]byte) (string, error) {
	dir, err := os.MkdirTemp(filepath.Dir(unitPath), ".ts-orch-stage-")
	if err != nil {
		return "", err
	}
	paths := []string{"verify", "--man=no", "--generators=no"}
	for name, data := range units {
		path := filepath.Join(dir, name)
		if err := atomicFile(path, data); err != nil {
			_ = os.RemoveAll(dir)
			return "", err
		}
		paths = append(paths, path)
	}
	command := exec.CommandContext(ctx, "systemd-analyze", paths...)
	command.Env = append(os.Environ(), "SYSTEMD_UNIT_PATH="+dir+":/etc/systemd/system:/run/systemd/system:/usr/local/lib/systemd/system:/usr/lib/systemd/system:/lib/systemd/system")
	output, err := command.CombinedOutput()
	if err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("verify release units: %w: %s", err, output)
	}
	return dir, nil
}

func guardUnits(binary string) map[string][]byte {
	units := map[string][]byte{guardService: []byte(m1.ReleaseGuardService), guardTimer: []byte(m1.ReleaseGuardTimer)}
	for name, data := range units {
		units[name] = bytes.ReplaceAll(data, []byte("/usr/local/bin/terrascale-orchestrator"), []byte(binary))
	}
	return units
}

func installGuard(ctx context.Context, binary, state string) error {
	units := guardUnits(binary)
	changed, deferred, missing := false, false, false
	for name, data := range units {
		previous, err := os.ReadFile(filepath.Join(filepath.Dir(unitPath), name))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if !bytes.Equal(previous, data) {
			missing = missing || errors.Is(err, os.ErrNotExist)
			if err == nil {
				if _, err := os.Stat(trialFile(state)); err == nil {
					deferred = true
				} else if !errors.Is(err, os.ErrNotExist) {
					return err
				}
			}
			changed = true
		}
	}
	if deferred {
		if missing {
			return errors.New("cannot replace an incomplete release guard during probation")
		}
		return systemctl(ctx, "start", guardTimer)
	}
	if changed {
		dir, err := stageUnits(ctx, units)
		if err != nil {
			return err
		}
		defer os.RemoveAll(dir)
		for name, data := range units {
			if err := atomicFile(filepath.Join(filepath.Dir(unitPath), name), data); err != nil {
				return err
			}
		}
		if err := systemctl(ctx, "daemon-reload"); err != nil {
			return err
		}
	}
	return systemctl(ctx, "enable", "--now", "--no-reload", guardTimer)
}

func installUnit(ctx context.Context, data []byte, binary, state string) error {
	t, err := readTrial(state)
	if err != nil {
		return err
	}
	if t == nil {
		return errors.New("release unit install requires durable trial intent")
	}

	if t.OriginalUnit && t.UnitBackup == "" {
		previous, err := os.ReadFile(unitPath)
		if err != nil {
			return err
		}
		t.UnitBackup = binary + ".prev.unit"
		if err := atomicFile(t.UnitBackup, previous); err != nil {
			return err
		}
		original := binary + ".original.unit"
		if _, err := os.Stat(original); errors.Is(err, os.ErrNotExist) {
			if err := atomicFile(original, previous); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		if err := writeJSON(trialFile(state), t); err != nil {
			return err
		}
		if err := installGuard(ctx, binary, state); err != nil {
			return err
		}
	}
	units := guardUnits(binary)
	units[filepath.Base(unitPath)] = data
	dir, err := stageUnits(ctx, units)
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	previous, err := os.ReadFile(unitPath)
	if err != nil {
		return fmt.Errorf("read installed unit: %w", err)
	}
	if err := installGuard(ctx, binary, state); err != nil {
		return err
	}
	if t.Phase == "intent" {
		if err := removeIfExists(binary + ".prev"); err != nil {
			return err
		}
		if err := os.Link(binary, binary+".prev"); err != nil {
			return err
		}
		if err := syncDir(filepath.Dir(binary)); err != nil {
			return err
		}
	}
	if t.Phase == "intent" || t.UnitBackup == "" {
		if err := atomicFile(binary+".prev.unit", previous); err != nil {
			return err
		}
		t.UnitBackup = binary + ".prev.unit"
	}
	budget, err := startBudget(ctx, data)
	if err != nil {
		return err
	}
	transition, err := transitionBudget(ctx)
	if err != nil {
		return err
	}
	t.StartTimeout = budget
	t.extend(time.Now().Add(transition), budget)
	t.Phase = "unit-staged"
	if err := writeJSON(trialFile(state), t); err != nil {
		return err
	}
	if !bytes.Equal(previous, data) {
		if err := atomicFile(unitPath, data); err != nil {
			return fmt.Errorf("install service unit: %w", err)
		}
		if err := systemctl(ctx, "daemon-reload"); err != nil {
			return err
		}
	}
	if err := systemctl(ctx, "reset-failed", "ts-orch.service"); err != nil {
		return err
	}
	t.Phase = "unit-installed"
	return writeJSON(trialFile(state), t)
}

func systemctl(ctx context.Context, args ...string) error {
	output, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, output)
	}
	return nil
}

func atomicFile(path string, data []byte) error { return atomicMode(path, data, 0o644) }

func atomicMode(path string, data []byte, mode os.FileMode) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".ts-orch-write-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, err = file.Write(data)
	err = errors.Join(err, file.Chmod(mode), file.Sync(), file.Close())
	if err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func unitService(ctx context.Context, executable, action, binary, state string) error {
	ctx, cancel := context.WithTimeout(ctx, rootStepWait)
	defer cancel()
	output, err := exec.CommandContext(ctx, "systemd-run", "--quiet", "--wait", "--pipe", "--collect",
		"--property=RuntimeMaxSec="+rootStepRuntime.String(), executable, "release", "unit", action, binary, state).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s release unit: %w: %s", action, err, output)
	}
	return nil
}

func prepareUnit(ctx context.Context, next, binary, state string) (bool, error) {
	data, err := exec.CommandContext(ctx, next, "release", "unit").Output()
	if err != nil {
		return false, fmt.Errorf("read release unit from verified binary: %w", err)
	}
	previous, err := os.ReadFile(unitPath)
	if err != nil {
		return false, fmt.Errorf("read installed unit: %w", err)
	}
	return !bytes.Equal(previous, data), unitService(ctx, next, "install", binary, state)
}

func ensureGuard(ctx context.Context, binary, state string) error {
	units := guardUnits(binary)
	for name, data := range units {
		installed, err := os.ReadFile(filepath.Join(filepath.Dir(unitPath), name))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if !bytes.Equal(installed, data) {
			return unitService(ctx, binary, "guard-install", binary, state)
		}
	}
	return nil
}
