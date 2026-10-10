package observability

import (
	"bytes"
	"log/slog"
	"os"
	"strings"
	"testing"
)

// The tests parse unprefixed output, so they run as if outside journald even
// when the test runner is a systemd service.
func TestMain(m *testing.M) {
	journalStream = func() bool { return false }
	os.Exit(m.Run())
}

func TestJournalOutputStartsEachRecordWithItsPriority(t *testing.T) {
	restore := journalStream
	journalStream = func() bool { return true }
	t.Cleanup(func() { journalStream = restore })
	for _, format := range []string{"json", "logfmt"} {
		var output bytes.Buffer
		logger, err := NewLogger(&output, LogConfig{Format: format, Level: "debug"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		logger.Error("failed")
		logger.Warn("level=DEBUG spoofed")
		logger.Info("started")
		logger.Debug("tick")
		lines := strings.Split(strings.TrimSpace(output.String()), "\n")
		want := []string{"<3>", "<4>", "<5>", "<7>"}
		if len(lines) != len(want) {
			t.Fatalf("%s wrote %d records, want %d: %q", format, len(lines), len(want), output.String())
		}
		for i, line := range lines {
			if !strings.HasPrefix(line, want[i]) {
				t.Fatalf("%s record %d = %q, want priority %s", format, i, line, want[i])
			}
		}
	}
}

func TestOutputWithoutJournalHasNoPriority(t *testing.T) {
	restore := journalStream
	journalStream = func() bool { return false }
	t.Cleanup(func() { journalStream = restore })
	var output bytes.Buffer
	logger, err := NewLogger(&output, LogConfig{}, nil, slog.String("service", "ts-orchestrator"))
	if err != nil {
		t.Fatal(err)
	}
	logger.Info("started")
	if !strings.HasPrefix(output.String(), "{") {
		t.Fatalf("record = %q, want unprefixed JSON", output.String())
	}
}
