package command

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCancelTerminatesInheritedOutputPipes(t *testing.T) {
	bin := t.TempDir()
	path := filepath.Join(bin, "oci")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nsleep 60 &\nwait\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := (CLI{}).Call(ctx, "network", "vcn", "list")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("provider cancellation waited on child output pipes: %v", elapsed)
	}
}
