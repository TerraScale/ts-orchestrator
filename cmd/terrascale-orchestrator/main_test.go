package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestOperatorCommandsTerminateOnFirstSignal(t *testing.T) {
	for _, command := range []string{"bootstrap", "release"} {
		for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM} {
			t.Run(fmt.Sprintf("%s/%s", command, sig), func(t *testing.T) {
				child, output := startSignalChild(t, command, false)
				expectSignalChildOutput(t, output, "ready")
				if err := child.Process.Signal(sig); err != nil {
					t.Fatal(err)
				}
				expectSignalExit(t, child, sig)
			})
		}
	}
}

func TestRuntimeCommandsShutDownGracefullyOnFirstSignal(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM} {
		t.Run(sig.String(), func(t *testing.T) {
			child, output := startSignalChild(t, "run", true)
			expectSignalChildOutput(t, output, "ready")
			if err := child.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			expectSignalChildOutput(t, output, "canceled")
			if err := child.Wait(); err != nil {
				t.Fatalf("graceful shutdown: %v", err)
			}
		})
	}
}

func TestRuntimeCommandsTerminateOnSecondSignal(t *testing.T) {
	for _, first := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM} {
		for _, second := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM} {
			t.Run(fmt.Sprintf("%s/%s", first, second), func(t *testing.T) {
				child, output := startSignalChild(t, "host", false)
				expectSignalChildOutput(t, output, "ready")
				if err := child.Process.Signal(first); err != nil {
					t.Fatal(err)
				}
				expectSignalChildOutput(t, output, "canceled")
				if err := child.Process.Signal(second); err != nil {
					t.Fatal(err)
				}
				expectSignalExit(t, child, second)
			})
		}
	}
}

func TestCommandSignalChild(t *testing.T) {
	command := os.Getenv("TS_ORCH_SIGNAL_TEST_COMMAND")
	if command == "" {
		return
	}
	ctx, cancel := commandContext([]string{command})
	defer cancel()
	fmt.Println("ready")
	if command != "bootstrap" && command != "release" {
		<-ctx.Done()
		fmt.Println("canceled")
		if os.Getenv("TS_ORCH_SIGNAL_TEST_GRACEFUL") == "true" {
			return
		}
	}
	// The parent holds stdin open to simulate work that ignores cancellation.
	if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
		t.Fatal(err)
	}
}

func startSignalChild(t *testing.T, command string, graceful bool) (*exec.Cmd, *bufio.Reader) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	child := exec.CommandContext(ctx, executable, "-test.run=^TestCommandSignalChild$")
	child.Env = append(os.Environ(), "TS_ORCH_SIGNAL_TEST_COMMAND="+command,
		fmt.Sprintf("TS_ORCH_SIGNAL_TEST_GRACEFUL=%t", graceful))
	child.Stderr = os.Stderr
	input, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = input.Close() })
	output, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if child.ProcessState == nil {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	})
	return child, bufio.NewReader(output)
}

func expectSignalChildOutput(t *testing.T, output *bufio.Reader, want string) {
	t.Helper()
	line, err := output.ReadString('\n')
	if err != nil || line != want+"\n" {
		t.Fatalf("child output = %q, error = %v; want %q", line, err, want)
	}
}

func expectSignalExit(t *testing.T, child *exec.Cmd, want syscall.Signal) {
	t.Helper()
	err := child.Wait()
	exit, ok := errors.AsType[*exec.ExitError](err)
	if !ok {
		t.Fatalf("child exit = %v, want termination by %s", err, want)
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != want {
		t.Fatalf("child exit = %v, want termination by %s", err, want)
	}
}
