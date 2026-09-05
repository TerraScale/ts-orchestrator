package vmqualruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/sandboxvm"
)

const startupStatusProperties = "--property=MainPID,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus"

// Only fixed labels and numeric process results leave the guest diagnostic
// channel. Raw journal messages, command errors and stderr are never retained.
type startupServiceDiagnostic struct {
	Unit               string   `json:"unit"`
	Observation        string   `json:"observation"`
	MainPID            uint64   `json:"mainPid,omitempty"`
	ActiveState        string   `json:"activeState,omitempty"`
	SubState           string   `json:"subState,omitempty"`
	Result             string   `json:"result,omitempty"`
	ExecMainCode       uint64   `json:"execMainCode,omitempty"`
	ExecMainStatus     uint64   `json:"execMainStatus,omitempty"`
	JournalEntries     int      `json:"journalEntries"`
	JournalUnavailable bool     `json:"journalUnavailable,omitempty"`
	SeverityCounts     [8]int   `json:"severityCounts"`
	Categories         []string `json:"categories,omitempty"`
}
type startupFailure struct {
	cause    error
	services []startupServiceDiagnostic
}

func (failure *startupFailure) Error() string {
	encoded, _ := json.Marshal(failure.services)
	return failure.cause.Error() + "; guestStartupDiagnostics=" + string(encoded)
}
func (failure *startupFailure) Unwrap() error { return failure.cause }

func (v *sandboxVM) failStartup(ctx context.Context, cause error) error {
	return retainStartupFailure(ctx, v.executor, cause, func(stopCtx context.Context) error { return v.provider.Stop(stopCtx, v.id) })
}
func retainStartupFailure(ctx context.Context, runner sandboxvm.CommandRunner, cause error, stop func(context.Context) error) error {
	diagnosticCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	services := collectStartupServices(diagnosticCtx, runner)
	cancel()
	stopCtx, stopCancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer stopCancel()
	return errors.Join(&startupFailure{cause: cause, services: services}, stop(stopCtx))
}

type startupBoundedOutput struct{ buffer bytes.Buffer }

func (buffer *startupBoundedOutput) Len() int      { return buffer.buffer.Len() }
func (buffer *startupBoundedOutput) Bytes() []byte { return buffer.buffer.Bytes() }

func (buffer *startupBoundedOutput) Write(data []byte) (int, error) {
	const maximum = 64 << 10
	remaining := maximum - buffer.Len()
	if len(data) > remaining {
		_, _ = buffer.buffer.Write(data[:remaining])
		return remaining, errors.New("startup diagnostic output exceeded bound")
	}
	return buffer.buffer.Write(data)
}
func startupCommand(ctx context.Context, runner sandboxvm.CommandRunner, path string, args ...string) ([]byte, error) {
	var output startupBoundedOutput
	err := runner.Run(ctx, sandboxvm.Command{Path: path, Args: args, Stdout: &output, Stderr: io.Discard})
	if err != nil {
		return nil, errors.New("guest diagnostic unavailable")
	}
	return output.Bytes(), nil
}
func collectStartupServices(ctx context.Context, runner sandboxvm.CommandRunner) []startupServiceDiagnostic {
	units := []string{"terrascale-ts-node.service", "terrascale-orchestrator.service", "terrascale-terrabase.service"}
	reports := make([]startupServiceDiagnostic, 0, len(units))
	unavailable := runner == nil
	for _, unit := range units {
		report := startupServiceDiagnostic{Unit: unit, Observation: "unavailable"}
		if unavailable || ctx.Err() != nil {
			reports = append(reports, report)
			continue
		}
		status, err := startupCommand(ctx, runner, "/usr/bin/systemctl", "show", unit, startupStatusProperties)
		if err != nil {
			unavailable = true
			reports = append(reports, report)
			continue
		}
		report.Observation = "observed"
		parseStartupStatus(&report, status)
		journal, err := startupCommand(ctx, runner, "/usr/bin/journalctl", "--unit", unit, "--lines=20", "--no-pager", "--output=json", "--output-fields=MESSAGE,PRIORITY", "--boot")
		if err != nil {
			report.JournalUnavailable = true
		} else {
			parseStartupJournal(&report, journal)
		}
		reports = append(reports, report)
	}
	return reports
}
func fixedStartupValue(value string, allowed ...string) string {
	for _, candidate := range allowed {
		if value == candidate {
			return value
		}
	}
	return "unknown"
}
func parseStartupStatus(report *startupServiceDiagnostic, data []byte) {
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		number, _ := strconv.ParseUint(value, 10, 32)
		switch key {
		case "MainPID":
			report.MainPID = number
		case "ExecMainCode":
			report.ExecMainCode = number
		case "ExecMainStatus":
			report.ExecMainStatus = number
		case "ActiveState":
			report.ActiveState = fixedStartupValue(value, "active", "inactive", "failed", "activating", "deactivating", "reloading")
		case "SubState":
			report.SubState = fixedStartupValue(value, "running", "dead", "failed", "exited", "start", "start-pre", "start-post", "auto-restart", "stop", "stop-sigterm")
		case "Result":
			report.Result = fixedStartupValue(value, "success", "exit-code", "signal", "core-dump", "timeout", "watchdog", "start-limit-hit", "resources", "protocol", "oom-kill")
		}
	}
}
func parseStartupJournal(report *startupServiceDiagnostic, data []byte) {
	categories := []struct{ match, label string }{
		{"error: missingconfigurationpath", "terrabase-configuration-missing"},
		{"no durable orchestrator membership source is configured", "membership-source-missing"},
		{"orchestrator: production runtime requires configured estate publisher, key rotation, free-tier reaper, restore drill, and delivery mirror adapters", "production-composition-missing"},
		{"orchestrator: oci estate verification requires ts_orch_oci_estate_file, ts_orch_oci_key_id, and ts_orch_oci_private_key_file", "oci-estate-configuration-missing"},
		{"no such file or directory", "file-missing"},
		{"not a directory", "path-not-directory"},
		{"initialgrant:", "initial-admission-rejected"},
		{"initial control:", "initial-control-rejected"},
		{"permission denied", "permission-denied"},
		{"exec format error", "executable-format"},
		{"failed at step exec", "exec-failed"},
		{"out of memory", "out-of-memory"},
		{"address already in use", "address-in-use"},
		{"connection refused", "connection-refused"},
	}
	seen := make(map[string]bool)
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		if report.JournalEntries == 20 {
			break
		}
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var entry struct {
			Message  string `json:"MESSAGE"`
			Priority string `json:"PRIORITY"`
		}
		if json.Unmarshal(line, &entry) != nil {
			report.JournalUnavailable = true
			continue
		}
		report.JournalEntries++
		if priority, err := strconv.Atoi(entry.Priority); err == nil && priority >= 0 && priority < 8 {
			report.SeverityCounts[priority]++
		}
		message := strings.ToLower(entry.Message)
		for _, category := range categories {
			if strings.Contains(message, category.match) {
				seen[category.label] = true
			}
		}
	}
	for _, category := range categories {
		if seen[category.label] {
			report.Categories = append(report.Categories, category.label)
		}
	}
}
