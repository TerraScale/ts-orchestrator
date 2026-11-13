package releasepush

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/deploy/m1"
)

func unitBytes() ([]byte, error) { return m1.Files.ReadFile("ts-orch.service") }

func startBudget(ctx context.Context, data []byte) (time.Duration, error) {
	output, err := exec.CommandContext(ctx, "systemctl", "show", "ts-orch.service", "-p", "TimeoutStartUSec", "--value").Output()
	if err != nil {
		return 0, fmt.Errorf("read service start bound: %w", err)
	}
	budget, err := systemdDuration(strings.TrimSpace(string(output)))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), "TimeoutStartSec="); ok {
			duration, err := systemdDuration(value)
			if err != nil {
				return 0, err
			}
			budget = max(budget, duration)
		}
	}
	asset, err := os.ReadFile("/sys/class/dmi/id/chassis_asset_tag")
	if err != nil && !os.IsNotExist(err) {
		return 0, err
	}
	if strings.TrimSpace(string(asset)) == "OracleCloud.com" {
		budget = max(budget, PlanningWindow)
	}
	return budget, nil
}

func systemdDuration(value string) (time.Duration, error) {
	value = strings.ReplaceAll(value, "min", "m")
	value = strings.ReplaceAll(value, " ", "")
	if !strings.ContainsAny(value, "abcdefghijklmnopqrstuvwxyzµ") {
		value += "s"
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return 0, fmt.Errorf("release requires a finite positive start timeout, got %q", value)
	}
	return duration, nil
}

func transitionBudget(ctx context.Context) (time.Duration, error) {
	output, err := exec.CommandContext(ctx, "systemctl", "show", "ts-orch.service", "-p", "TimeoutStopUSec", "-p", "RestartUSec").Output()
	if err != nil {
		return 0, err
	}
	var budget time.Duration
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		_, value, ok := strings.Cut(line, "=")
		if !ok {
			return 0, fmt.Errorf("invalid service transition bound: %q", line)
		}
		duration, err := systemdDuration(value)
		if err != nil {
			return 0, err
		}
		budget += duration
	}
	return budget, nil
}
