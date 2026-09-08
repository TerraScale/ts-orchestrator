package hostplatform

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// UnitStopped proves both the systemd state and absence of surviving cgroup
// processes. Inactive status alone is insufficient for sealing broker files.
func (c *SystemctlController) UnitStopped(ctx context.Context, unit string) (bool, error) {
	raw, err := c.runOutput(ctx, "show", unit, "--property=LoadState,ActiveState,SubState,MainPID,ControlGroup")
	if err != nil {
		return false, err
	}
	values := map[string]string{}
	for line := range strings.SplitSeq(strings.TrimSpace(string(raw)), "\n") {
		k, v, ok := strings.Cut(line, "=")
		_, duplicate := values[k]
		if !ok || duplicate {
			return false, errors.New("hostplatform: invalid stopped-unit observation")
		}
		values[k] = v
	}
	if len(values) != 5 {
		return false, errors.New("hostplatform: incomplete stopped-unit observation")
	}
	if _, ok := values["ControlGroup"]; !ok {
		return false, errors.New("hostplatform: service cgroup observation absent")
	}
	if values["LoadState"] != "loaded" || values["ActiveState"] != "inactive" || values["SubState"] != "dead" || values["MainPID"] != "0" {
		return false, nil
	}
	group := values["ControlGroup"]
	if group == "" {
		return true, nil
	}
	if !strings.HasPrefix(group, "/") || filepath.Clean(group) != group || group == "/" {
		return false, errors.New("hostplatform: unsafe service cgroup")
	}
	events, err := os.ReadFile(filepath.Join("/sys/fs/cgroup", group, "cgroup.events"))
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	for line := range strings.SplitSeq(string(events), "\n") {
		if line == "populated 0" {
			return true, nil
		}
		if line == "populated 1" {
			return false, nil
		}
	}
	return false, errors.New("hostplatform: cgroup population unavailable")
}
