package netbird

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnrollmentIntegrationBoundsHungStatusProcess(t *testing.T) {
	for _, observed := range []bool{false, true} {
		t.Run(map[bool]string{false: "first-query", true: "after-observation"}[observed], func(t *testing.T) {
			e := testEnroller(t)
			writeIntegrationFile(t, filepath.Join(filepath.Dir(e.hostsPath), "hang"), "", 0o600)
			var first *daemonStatus
			if observed {
				first = &daemonStatus{DaemonStatus: "Connecting"}
			}
			started := time.Now()
			status, done, err := e.observe(t.Context(), 100*time.Millisecond, first, func(daemonStatus) bool { return false })
			if time.Since(started) > 3*time.Second {
				t.Fatal("hung process escaped observation deadline")
			}
			if observed {
				if err != nil || done || status.DaemonStatus != "Connecting" {
					t.Fatalf("last observation lost: %v %t %v", status, done, err)
				}
			} else if err == nil || done || status != (daemonStatus{}) {
				t.Fatalf("first query invented observation: %v %t %v", status, done, err)
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(e.hostsPath), "commands")); err != nil {
				t.Fatal("status executable never ran")
			}
		})
	}
}

func TestEnrollmentIntegrationCancellationStopsStatusProcess(t *testing.T) {
	e := testEnroller(t)
	writeIntegrationFile(t, filepath.Join(filepath.Dir(e.hostsPath), "hang"), "", 0o600)
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if _, _, err := e.observe(ctx, time.Minute, nil, func(daemonStatus) bool { return false }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancellation lost: %v", err)
	}
}
