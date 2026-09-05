package guestdiagnostic

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
)

// Only fixed labels and numeric process results leave the guest diagnostic
// channel. Raw journal messages, command errors and stderr are never retained.
type Service struct {
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

func fixedStartupValue(value string, allowed ...string) string {
	for _, candidate := range allowed {
		if value == candidate {
			return value
		}
	}
	return "unknown"
}

// ParseStatus retains fixed systemd states and bounded numeric process results.
func ParseStatus(report *Service, data []byte) {
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

// ParseJournal counts at most 20 decoded journal entries and retains only fixed categories.
func ParseJournal(report *Service, data []byte) {
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
