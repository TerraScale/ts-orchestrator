package hostmetrics

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func parseCounter(value string) (uint64, error) {
	return strconv.ParseUint(value, 10, 64)
}

func writeRuntime(ctx context.Context, w io.Writer) error {
	oom, err := readCounter("/proc/vmstat", "oom_kill")
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "ts_host_oom_kills_total %d\n", oom)
	data, err := exec.CommandContext(ctx, "systemctl", "show", "--type=service", "--all", "--property=Id,NRestarts").Output()
	if err != nil {
		return err
	}
	count := 0
	for _, block := range strings.Split(strings.TrimSpace(string(data)), "\n\n") {
		values := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			key, value, _ := strings.Cut(line, "=")
			values[key] = value
		}
		unit := values["Id"]
		if unit != "ts-orch.service" && unit != "containerd.service" && unit != "netbird.service" && !strings.HasPrefix(unit, "ts-") {
			continue
		}
		restarts, err := parseCounter(values["NRestarts"])
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "ts_host_unit_restarts_total{unit=%q} %d\n", unit, restarts)
		count++
	}
	if count == 0 {
		return fmt.Errorf("host units unavailable")
	}
	return nil
}

func readCounter(path, key string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == key {
			return parseCounter(fields[1])
		}
	}
	return 0, errors.New("host counter unavailable")
}
