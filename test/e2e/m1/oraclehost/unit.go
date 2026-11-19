package oraclehost

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"

	m1 "github.com/TerraScale/ts-orchestrator/deploy/m1"
)

type unit struct {
	ExecStart              []string
	Environment            []string
	RestartSec             time.Duration
	TimeoutStartSec        time.Duration
	TimeoutStopSec         time.Duration
	LimitNOFILE            uint64
	UMask                  int
	ReadWritePaths         []string
	ConfigurationDirectory []string
	ProtectSystem          string
	ProtectHome            bool
	PrivateTmp             bool
	NoNewPrivileges        bool
}

var acceptedKeys = map[string]bool{
	"Type": true, "NotifyAccess": true, "Restart": true, "KillMode": true, "ExecStartPre": true,
	"ProtectKernelLogs": true, "ProtectClock": true, "ProtectHostname": true, "LockPersonality": true,
	"RestrictRealtime": true, "RestrictSUIDSGID": true, "SystemCallArchitectures": true,
}

func productionUnit() (unit, error) {
	data, err := m1.Files.ReadFile("ts-orch.service")
	if err != nil {
		return unit{}, err
	}
	return parseUnit(data)
}

func parseUnit(data []byte) (unit, error) {
	var u unit
	section := ""
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = line
			continue
		}
		if section != "[Service]" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return unit{}, fmt.Errorf("unit line %q is not key=value", line)
		}
		var err error
		switch key {
		case "ExecStart":
			u.ExecStart = strings.Fields(value)
		case "Environment":
			u.Environment = append(u.Environment, strings.Fields(value)...)
		case "RestartSec":
			u.RestartSec, err = time.ParseDuration(value)
		case "TimeoutStartSec":
			u.TimeoutStartSec, err = time.ParseDuration(strings.Replace(value, "min", "m", 1))
		case "TimeoutStopSec":
			u.TimeoutStopSec, err = time.ParseDuration(value)
		case "LimitNOFILE":
			u.LimitNOFILE, err = strconv.ParseUint(value, 10, 64)
		case "UMask":
			var mask int64
			mask, err = strconv.ParseInt(value, 8, 32)
			u.UMask = int(mask)
		case "ReadWritePaths":
			u.ReadWritePaths = append(u.ReadWritePaths, strings.Fields(value)...)
		case "ConfigurationDirectory":
			u.ConfigurationDirectory = append(u.ConfigurationDirectory, strings.Fields(value)...)
		case "ProtectSystem":
			u.ProtectSystem = value
		case "ProtectHome":
			u.ProtectHome = value == "yes"
		case "PrivateTmp":
			u.PrivateTmp = value == "yes"
		case "NoNewPrivileges":
			u.NoNewPrivileges = value == "yes"
		default:
			if !acceptedKeys[key] {
				return unit{}, fmt.Errorf("ts-orch.service sets %s, which the Oracle host harness does not reproduce", key)
			}
		}
		if err != nil {
			return unit{}, fmt.Errorf("ts-orch.service %s: %w", key, err)
		}
	}
	if len(u.ExecStart) == 0 || !strings.HasPrefix(u.ExecStart[0], "/") {
		return unit{}, fmt.Errorf("ts-orch.service has no absolute ExecStart")
	}
	if u.ProtectSystem != "" && u.ProtectSystem != "full" {
		return unit{}, fmt.Errorf("ts-orch.service ProtectSystem=%s is not reproduced", u.ProtectSystem)
	}
	return u, scanner.Err()
}
