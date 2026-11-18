package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"

	m1 "github.com/TerraScale/ts-orchestrator/deploy/m1"
)

const companionUnitPath = "/etc/systemd/system/netbird-server.service"

func ensureCompanionUnit(ctx context.Context) (bool, error) {
	want, err := m1.Files.ReadFile("services/netbird-server.service")
	if err != nil {
		return false, err
	}
	installed, err := os.ReadFile(companionUnitPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if bytes.Equal(installed, want) {
		return false, nil
	}
	next := companionUnitPath + ".next"
	if err := os.WriteFile(next, want, 0o644); err != nil {
		return false, err
	}
	if err := os.Rename(next, companionUnitPath); err != nil {
		return false, errors.Join(err, os.Remove(next))
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", "netbird-server.service"}, {"restart", "netbird-server.service"}} {
		if output, err := runHostLogCommand(ctx, "systemctl", args...); err != nil {
			return false, fmt.Errorf("systemctl %v: %w: %s", args, err, bytes.TrimSpace(output))
		}
	}
	return true, nil
}
