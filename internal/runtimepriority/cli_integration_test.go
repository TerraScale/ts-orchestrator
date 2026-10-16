package runtimepriority

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestRuntimePriorityCLIProcess(t *testing.T) {
	if os.Getenv("TS_RUNTIME_PRIORITY_CLI_PROCESS") != "1" {
		return
	}
	separator := slices.Index(os.Args, "--")
	if separator < 0 {
		os.Exit(3)
	}
	if err := Run(t.Context(), os.Args[separator+1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", ErrorType(err), err)
		os.Exit(2)
	}
	os.Exit(0)
}

func runtimeCLI(t *testing.T, args ...string) ([]byte, error) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, append([]string{"-test.run=^TestRuntimePriorityCLIProcess$", "--"}, args...)...)
	cmd.Env = append(os.Environ(), "TS_RUNTIME_PRIORITY_CLI_PROCESS=1", "GORACE=atexit_sleep_ms=0")
	cmd.WaitDelay = time.Second
	return cmd.CombinedOutput()
}

func runtimeCommandFixture(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "command")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nset -eu\n"+body), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}
