package natscell

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"github.com/nats-io/nats.go"
)

// captureDefault routes the default logger into a JSON buffer for one test.
func captureDefault(t *testing.T) *bytes.Buffer {
	t.Helper()
	t.Setenv("JOURNAL_STREAM", "")
	var output bytes.Buffer
	logger, err := observability.NewLogger(&output, observability.LogConfig{Level: "debug"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	previous := slog.Default()
	observability.ConfigureDefault(logger)
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &output
}

func TestNATSServerOutputMapsToLevels(t *testing.T) {
	output := captureDefault(t)
	var logger natsLogger
	logger.Noticef("ready %d", 1)
	logger.Warnf("slow consumer %s", "x")
	logger.Warnf("Metalayer blocking snapshot for peer %s", "p1")
	logger.Errorf("store failed")
	logger.Fatalf("fatal")
	logger.Debugf("debug")
	logger.Tracef("trace")
	want := []struct{ level, message string }{
		{"INFO", "ready 1"}, {"WARN", "slow consumer x"},
		{"INFO", "Metalayer blocking snapshot for peer p1"}, {"ERROR", "store failed"},
		{"ERROR", "fatal"}, {"DEBUG", "debug"}, {"DEBUG", "trace"},
	}
	lines := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte("\n"))
	if len(lines) != len(want) {
		t.Fatalf("wrote %d records, want %d: %s", len(lines), len(want), output)
	}
	for i, line := range lines {
		var record map[string]any
		if err := json.Unmarshal(line, &record); err != nil {
			t.Fatal(err)
		}
		if record["level"] != want[i].level || record["msg"] != want[i].message || record["component"] != "nats" {
			t.Fatalf("record %d = %v, want %s %q", i, record, want[i].level, want[i].message)
		}
	}
}

func TestClientErrorsLogAtTheirSeverity(t *testing.T) {
	output := captureDefault(t)
	ErrorHandler(nil, nil, nats.ErrPermissionViolation)
	ErrorHandler(nil, nil, nats.ErrAuthorization)
	ErrorHandler(nil, nil, errors.New("slow consumer"))
	want := []string{"ERROR", "ERROR", "WARN"}
	lines := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte("\n"))
	if len(lines) != len(want) {
		t.Fatalf("wrote %d records, want %d: %s", len(lines), len(want), output)
	}
	for i, line := range lines {
		var record map[string]any
		if err := json.Unmarshal(line, &record); err != nil {
			t.Fatal(err)
		}
		if record["level"] != want[i] || record["component"] != "nats-client" {
			t.Fatalf("record %d = %v, want level %s", i, record, want[i])
		}
	}
}
