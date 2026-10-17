package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestFunctionWorkerCLIProcess(t *testing.T) {
	cases := []struct {
		name  string
		args  []string
		want  string
		cause error
	}{
		{name: "missing-material", want: "function material directory:", cause: os.ErrNotExist},
		{name: "module-argument", args: []string{"module.wasm"}, want: "function-worker accepts no arguments"},
		{name: "config-override", args: []string{"--config", "worker.json"}, want: "function-worker accepts no arguments"},
		{name: "canceled", want: "context canceled", cause: context.Canceled},
	}
	const selector = "TS_ORCH_FUNCTION_CLI_TEST_CASE"
	if name := os.Getenv(selector); name != "" {
		for _, tc := range cases {
			if tc.name != name {
				continue
			}
			if name == "missing-material" {
				// Never read an existing production material mount from a test process.
				if _, err := os.Lstat("/run/ts-orch/function"); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("fixed function material path must be absent: %v", err)
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if name == "canceled" {
				cancel()
			}
			var output bytes.Buffer
			err := Run(ctx, append([]string{"function-worker"}, tc.args...), &output)
			if err == nil || !strings.HasPrefix(err.Error(), tc.want) {
				t.Fatalf("worker error = %v, want %q", err, tc.want)
			}
			if tc.cause != nil && !errors.Is(err, tc.cause) {
				t.Fatalf("worker error = %v, want wrapped %v", err, tc.cause)
			}
			if output.Len() != 0 {
				t.Fatalf("rejected worker wrote output: %q", output.String())
			}
			fmt.Fprintln(os.Stderr, "function-worker CLI rejection:", err)
			os.Exit(1)
		}
		t.Fatalf("unknown worker process case %q", name)
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, executable, "-test.run=^TestFunctionWorkerCLIProcess$")
			child.Env = append(os.Environ(), selector+"="+tc.name)
			var stdout, stderr bytes.Buffer
			child.Stdout, child.Stderr = &stdout, &stderr
			err := child.Run()
			exit, ok := errors.AsType[*exec.ExitError](err)
			if !ok || exit.ExitCode() != 1 {
				t.Fatalf("worker child exit = %v; stdout = %q; stderr = %q", err, stdout.String(), stderr.String())
			}
			if stdout.Len() != 0 || !strings.HasPrefix(stderr.String(), "function-worker CLI rejection: "+tc.want) {
				t.Fatalf("worker child stdout = %q; stderr = %q", stdout.String(), stderr.String())
			}
		})
	}
}
