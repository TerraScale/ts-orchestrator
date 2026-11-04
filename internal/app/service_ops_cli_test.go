package app

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

func TestServiceLogsReadsBothStreamsAndFollowsTruncation(t *testing.T) {
	state := t.TempDir()
	write := func(stream, data string) {
		path := swarmruntime.RuntimeLogFile(state, "task1", stream)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	row := swarmruntime.TaskRow{ID: "task1", State: "RUNNING"}
	var out bytes.Buffer
	if err := writeTaskLogs(t.Context(), &out, state, row, false); err == nil || !strings.Contains(err.Error(), "no container logs yet") {
		t.Fatalf("missing logs: %v", err)
	}
	write("stdout", "out\n")
	write("stderr", "err\n")
	if err := writeTaskLogs(t.Context(), &out, state, row, false); err != nil || out.String() != "out\nerr\n" {
		t.Fatalf("logs %q, %v", out.String(), err)
	}
	out.Reset()
	ctx, cancel := context.WithTimeout(t.Context(), 1500*time.Millisecond)
	defer cancel()
	go func() {
		time.Sleep(700 * time.Millisecond)
		write("stdout", "x\n") // Shorter than before: the logger truncated a full segment.
	}()
	if err := writeTaskLogs(ctx, &out, state, row, true); err != nil || out.String() != "out\nerr\nx\n" {
		t.Fatalf("follow %q, %v", out.String(), err)
	}
}
