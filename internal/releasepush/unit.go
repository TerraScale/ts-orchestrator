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
	"time"

	"github.com/TerraScale/ts-orchestrator/deploy/m1"
)

const unitPath = "/etc/systemd/system/ts-orch.service"

func Unit(ctx context.Context, args []string, output io.Writer) error {
	data, err := m1.Files.ReadFile("ts-orch.service")
	if err != nil {
		return err
	}
	if len(args) == 0 {
		_, err := output.Write(data)
		return err
	}
	if len(args) != 2 || !filepath.IsAbs(args[1]) || os.Geteuid() != 0 {
		return errors.New("release unit requires root and install|restore <absolute binary path>")
	}
	backup := args[1] + ".prev.unit"
	switch args[0] {
	case "install":
		previous, err := os.ReadFile(unitPath)
		if err != nil {
			return fmt.Errorf("read installed unit: %w", err)
		}
		if bytes.Equal(previous, data) {
			return nil
		}
		if err := atomicFile(backup, previous); err != nil {
			return fmt.Errorf("retain previous unit: %w", err)
		}
		if err := replaceUnit(ctx, data); err != nil {
			return errors.Join(err, replaceUnit(ctx, previous))
		}
		return nil
	case "restore":
		previous, err := os.ReadFile(backup)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read previous unit: %w", err)
		}
		return replaceUnit(ctx, previous)
	default:
		return errors.New("release unit accepts install or restore")
	}
}

func replaceUnit(ctx context.Context, data []byte) error {
	if err := atomicFile(unitPath, data); err != nil {
		return fmt.Errorf("write service unit: %w", err)
	}
	output, err := exec.CommandContext(ctx, "systemctl", "daemon-reload").CombinedOutput()
	if err != nil {
		return fmt.Errorf("reload service manager: %w: %s", err, output)
	}
	return nil
}

func atomicFile(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".ts-orch-unit-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, err = file.Write(data)
	err = errors.Join(err, file.Chmod(0o644), file.Sync(), file.Close())
	if err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func unitService(ctx context.Context, executable, action, binary string) error {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "systemd-run", "--quiet", "--wait", "--pipe", "--collect",
		"--property=RuntimeMaxSec=30s", executable, "release", "unit", action, binary).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s release unit: %w: %s", action, err, output)
	}
	return nil
}

func prepareUnit(ctx context.Context, next, binary string) (bool, error) {
	data, err := exec.CommandContext(ctx, next, "release", "unit").Output()
	if err != nil {
		return false, fmt.Errorf("read release unit from verified binary: %w", err)
	}
	previous, err := os.ReadFile(unitPath)
	if err != nil {
		return false, fmt.Errorf("read installed unit: %w", err)
	}
	if bytes.Equal(previous, data) {
		return false, nil
	}
	return true, unitService(ctx, next, "install", binary)
}

func restoreUnit(ctx context.Context, executable, binary string) error {
	if _, err := os.Stat(binary + ".prev.unit"); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return unitService(ctx, executable, "restore", binary)
}
