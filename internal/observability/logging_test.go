package observability

import (
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
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
		output := newLogOutput(t)
		logger, err := NewLogger(output, LogConfig{Format: format, Level: "debug"}, nil)
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
	output := newLogOutput(t)
	logger, err := NewLogger(output, LogConfig{}, nil, slog.String("service", "ts-orchestrator"))
	if err != nil {
		t.Fatal(err)
	}
	logger.Info("started")
	if !strings.HasPrefix(output.String(), "{") {
		t.Fatalf("record = %q, want unprefixed JSON", output.String())
	}
}

var (
	utcRecordTime = regexp.MustCompile(`2026-10-09T15:00:00(\.\d+)?Z`)
	localTimeAttr = regexp.MustCompile(`2026-10-09T12:00:00(\.\d+)?-03:00`)
)

func TestRecordTimeIsUTCAndAttributeKeepsItsZone(t *testing.T) {
	at := time.Date(2026, 10, 9, 12, 0, 0, 0, time.FixedZone("UTC-3", -3*3600))
	for _, format := range []string{"json", "logfmt"} {
		output := newLogOutput(t)
		logger, err := NewLogger(output, LogConfig{Format: format}, nil)
		if err != nil {
			t.Fatal(err)
		}
		record := slog.NewRecord(at, slog.LevelInfo, "started", 0)
		record.AddAttrs(slog.Time("at", at))
		if err := logger.Handler().Handle(t.Context(), record); err != nil {
			t.Fatal(err)
		}
		out := output.String()
		if !utcRecordTime.MatchString(out) {
			t.Fatalf("%s record time is not UTC: %q", format, out)
		}
		if !localTimeAttr.MatchString(out) {
			t.Fatalf("%s time attribute lost its zone: %q", format, out)
		}
	}
}

// logOutput observes the same file boundary as the process log sink.
type logOutput struct {
	*os.File
	t *testing.T
}

func newLogOutput(t *testing.T) *logOutput {
	t.Helper()
	file, err := os.Create(filepath.Join(t.TempDir(), "process.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	})
	return &logOutput{File: file, t: t}
}

func (output *logOutput) Bytes() []byte {
	output.t.Helper()
	data, err := os.ReadFile(output.Name())
	if err != nil {
		output.t.Fatal(err)
	}
	return data
}
func (output *logOutput) String() string { return string(output.Bytes()) }
func (output *logOutput) Len() int       { return len(output.Bytes()) }
func (output *logOutput) Reset() {
	output.t.Helper()
	if err := output.Truncate(0); err != nil {
		output.t.Fatal(err)
	}
	if _, err := output.Seek(0, 0); err != nil {
		output.t.Fatal(err)
	}
}
