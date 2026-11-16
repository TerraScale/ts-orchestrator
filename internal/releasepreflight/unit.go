package releasepreflight

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	m1 "github.com/TerraScale/ts-orchestrator/deploy/m1"
)

const (
	installedUnit = "/etc/systemd/system/ts-orch.service"
	installedBin  = "/usr/local/bin/terrascale-orchestrator"
	unitPairs     = "/var/lib/ts-orch/units"
	pairingDropin = "/run/systemd/system/ts-orch.service.d/ts-orch-unit.conf"
)

func pairUnit(ctx context.Context) error {
	installed, err := os.ReadFile(installedUnit)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	unit, err := m1.Files.ReadFile("ts-orch.service")
	if err != nil {
		return err
	}
	self, err := fileDigest("/proc/self/exe")
	if err != nil {
		return err
	}
	keep := map[string]bool{self + ".service": true}
	if err := os.MkdirAll(unitPairs, 0o700); err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(unitPairs, self+".service"), unit); err != nil {
		return err
	}
	current, err := fileDigest(installedBin)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return err
	default:
		keep[current+".service"] = true
		pair := filepath.Join(unitPairs, current+".service")
		if _, err := os.Stat(pair); errors.Is(err, os.ErrNotExist) {
			if err := writeAtomic(pair, installed); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
	}
	if previous, err := fileDigest(installedBin + ".prev"); err == nil {
		keep[previous+".service"] = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	entries, err := os.ReadDir(unitPairs)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !keep[entry.Name()] {
			if err := os.Remove(filepath.Join(unitPairs, entry.Name())); err != nil {
				return err
			}
		}
	}
	pairing := pairingLines(unit)
	if pairing == "" {
		return errors.New("ts-orch.service carries no unit pairing")
	}
	if strings.Contains(string(installed), pairing) {
		return nil
	}
	dropin := []byte("[Service]\n" + pairing + "\n")
	if existing, err := os.ReadFile(pairingDropin); err == nil && bytes.Equal(existing, dropin) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(pairingDropin), 0o755); err != nil {
		return err
	}
	if err := writeAtomic(pairingDropin, dropin); err != nil {
		return err
	}
	if err := os.Chmod(pairingDropin, 0o644); err != nil {
		return err
	}
	if output, err := exec.CommandContext(ctx, "systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w: %s", err, output)
	}
	return nil
}

func pairingLines(unit []byte) string {
	lines := []string{}
	for line := range strings.SplitSeq(string(unit), "\n") {
		if strings.HasPrefix(line, "ExecStartPre=") {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n")
}

func fileDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	sum := sha256.New()
	if _, err := io.Copy(sum, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

func writeAtomic(path string, data []byte) error {
	next := path + ".next"
	file, err := os.OpenFile(next, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	if err = errors.Join(err, file.Sync(), file.Close()); err != nil {
		_ = os.Remove(next)
		return err
	}
	if err := os.Rename(next, path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}
