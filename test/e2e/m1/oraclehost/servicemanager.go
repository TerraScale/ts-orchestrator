package oraclehost

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	systemctlCommand = "systemctl"
	analyzeCommand   = "systemd-analyze"
	managedUnit      = "ts-orch.service"
	managerDir       = "/run/oraclehost-systemd"
)

var recoveryUnits = []string{"ts-orch-release-recovery.service", "ts-orch-release-recovery.timer"}

func (s *supervisor) recordStart(pid int, invocation string) error {
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(managerDir, "enabled"), 0o755); err != nil {
		return err
	}
	text := fmt.Sprintf("MainPID=%d\nInvocationID=%s\nExecMainStartTimestampMonotonic=%d\n", pid, invocation, now.Nano()/1000)
	return os.WriteFile(filepath.Join(managerDir, managedUnit), []byte(text), 0o644)
}

func serviceManager(name string, args []string) int {
	var err error
	switch name {
	case systemctlCommand:
		err = systemctl(args)
	case analyzeCommand:
		err = analyze(args)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %s: %v\n", name, strings.Join(args, " "), err)
		return 1
	}
	return 0
}

func systemctl(args []string) error {
	verb, units, properties := "", []string{}, []string{}
	for i := 0; i < len(args); i++ {
		switch arg := args[i]; {
		case arg == "-p" && i+1 < len(args):
			i++
			properties = append(properties, args[i])
		case strings.HasPrefix(arg, "-"):
		case verb == "":
			verb = arg
		default:
			units = append(units, arg)
		}
	}
	switch {
	case verb == "daemon-reload" && len(units) == 0:
		return nil
	case verb == "link" && len(units) != 0:
		for _, path := range units {
			if !slices.Contains(recoveryUnits, filepath.Base(path)) {
				return fmt.Errorf("the Oracle host harness only links the release recovery units")
			}
			if _, err := os.Stat(path); err != nil {
				return err
			}
		}
		return nil
	case verb == "enable" && len(units) != 0:
		for _, name := range units {
			if !slices.Contains(recoveryUnits, name) {
				return fmt.Errorf("the Oracle host harness only enables the release recovery units")
			}
			if err := os.WriteFile(filepath.Join(managerDir, "enabled", name), nil, 0o644); err != nil {
				return err
			}
		}
		return nil
	case (verb == "is-enabled" || verb == "start") && len(units) == 1 && slices.Contains(recoveryUnits, units[0]):
		_, err := os.Stat(filepath.Join(managerDir, "enabled", units[0]))
		return err
	case verb == "show" && len(units) == 1 && units[0] == managedUnit && len(properties) != 0:
		return show(properties)
	}
	return fmt.Errorf("the Oracle host harness reproduces no such service manager request")
}

func show(properties []string) error {
	u, err := productionUnit()
	if err != nil {
		return err
	}
	values := map[string]string{
		"TimeoutStartUSec": u.TimeoutStartSec.String(),
		"TimeoutStopUSec":  u.TimeoutStopSec.String(),
		"RestartUSec":      u.RestartSec.String(),
	}
	file, err := os.Open(filepath.Join(managerDir, managedUnit))
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, _ := strings.Cut(scanner.Text(), "=")
		values[key] = value
	}
	for _, property := range properties {
		value, ok := values[property]
		if !ok {
			return fmt.Errorf("property %s is not reproduced", property)
		}
		fmt.Printf("%s=%s\n", property, value)
	}
	return scanner.Err()
}

func analyze(args []string) error {
	if len(args) < 2 || args[0] != "verify" {
		return fmt.Errorf("the Oracle host harness only verifies unit files")
	}
	for _, path := range args[1:] {
		if strings.HasPrefix(path, "-") {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !strings.Contains(string(data), "[Unit]") {
			return fmt.Errorf("%s has no [Unit] section", path)
		}
	}
	return nil
}
