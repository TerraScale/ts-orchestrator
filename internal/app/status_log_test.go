package app

import (
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
)

// statusLog captures the default logger's records.
type statusLog struct {
	mu    sync.Mutex
	lines []string
}

func (s *statusLog) Write(record []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lines = append(s.lines, string(record))
	return len(record), nil
}

// count returns the records with msg at level.
func (s *statusLog) count(level, msg string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, line := range s.lines {
		if strings.Contains(line, `"level":"`+level+`"`) && strings.Contains(line, `"msg":"`+msg+`"`) {
			n++
		}
	}
	return n
}

func captureStatusLog(t *testing.T) *statusLog {
	t.Helper()
	original := slog.Default()
	t.Cleanup(func() { slog.SetDefault(original) })
	output := new(statusLog)
	slog.SetDefault(slog.New(slog.NewJSONHandler(output, &slog.HandlerOptions{Level: slog.LevelDebug})))
	return output
}

func TestReleaseChannelStatusLogsOnlyChangesAtInfo(t *testing.T) {
	output := captureStatusLog(t)
	ctx, kv := t.Context(), fenceKV(t)
	c := &rolloutControl{cell: "gru"}
	now := time.Now().UTC()
	status := releasechannel.Status{Schema: releasechannel.StatusSchema, Cell: "GRU", RunNumber: 3,
		State: releasechannel.StateRolling, Reason: "waiting", UpdatedAt: now,
		Pins: &releasechannel.ReleasePins{Rollback: []string{}, KnownBad: []string{}}}
	if err := c.report(ctx, kv, status); err != nil {
		t.Fatal(err)
	}
	// The pins refresh is due, but the run, state and reason are unchanged.
	status.UpdatedAt = now.Add(releasechannel.PinRefreshInterval)
	if err := c.report(ctx, kv, status); err != nil {
		t.Fatal(err)
	}
	status.Reason, status.UpdatedAt = "the next generation is rolling", now.Add(2*releasechannel.PinRefreshInterval)
	if err := c.report(ctx, kv, status); err != nil {
		t.Fatal(err)
	}
	if info, debug := output.count("INFO", "release channel status"), output.count("DEBUG", "release channel status"); info != 2 || debug != 1 {
		t.Fatalf("release channel status logged %d INFO and %d DEBUG, want 2 and 1", info, debug)
	}
}

func TestServiceReleaseStatusLogsOnlyChangesAtInfo(t *testing.T) {
	output := captureStatusLog(t)
	r, kv, _, _ := servicePinsFixture(t)
	ctx, role := t.Context(), terrabase.Role
	state := serviceReleaseState{Digest: strings.Repeat("a", 64), State: releasechannel.StateRolling, Reason: "waiting"}
	if err := r.report(ctx, kv, role, state); err != nil {
		t.Fatal(err)
	}
	// A new known-bad pin rewrites the status with the same digest, state and reason.
	if _, err := kv.Put(ctx, knownBadKey(role, strings.Repeat("b", 64)), []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if err := r.report(ctx, kv, role, state); err != nil {
		t.Fatal(err)
	}
	state.Reason = "still waiting"
	if err := r.report(ctx, kv, role, state); err != nil {
		t.Fatal(err)
	}
	if info, debug := output.count("INFO", "service release status"), output.count("DEBUG", "service release status"); info != 2 || debug != 1 {
		t.Fatalf("service release status logged %d INFO and %d DEBUG, want 2 and 1", info, debug)
	}
}

func TestServiceReleaseFailureWarnsOncePerErrorText(t *testing.T) {
	output := captureStatusLog(t)
	r, kv, _, _ := servicePinsFixture(t)
	ctx, role := t.Context(), terrabase.Role
	failing := serviceReleaseState{State: releasechannel.StateRolling, Retained: []string{"not-a-digest"}}
	r.reportQuietly(ctx, kv, role, failing)
	r.reportQuietly(ctx, kv, role, failing)
	failing.Retained = []string{"also-not-a-digest"}
	r.reportQuietly(ctx, kv, role, failing)
	if warn, debug := output.count("WARN", "service release status"), output.count("DEBUG", "service release status"); warn != 2 || debug != 1 {
		t.Fatalf("service release failures logged %d WARN and %d DEBUG, want 2 and 1", warn, debug)
	}
}
