package hostplatform

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func fakeSystemctlBinary(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "systemctl")
	program := []byte(`#!/bin/sh
case "${SYSTEMCTL_TEST_MODE:-success}" in
sleep)
    # Stop the process without relying on any host utility. CommandContext
    # must kill this blocked fake when its deadline or parent cancellation
    # fires.
    kill -STOP $$
    ;;
active)
    exit 0
    ;;
inactive)
    exit 3
    ;;
failure)
    printf '%s\n' 'fake systemctl failure' >&2
    exit 1
    ;;
success)
    exit 0
    ;;
*)
    exit 2
    ;;
esac
`)
	if err := os.WriteFile(path, program, 0o755); err != nil {
		t.Fatalf("write fake systemctl: %v", err)
	}
	return path
}

func TestNewSystemctlControllerRejectsInvalidTimeout(t *testing.T) {
	for _, timeout := range []time.Duration{0, -time.Second} {
		if _, err := NewSystemctlController("/usr/bin/systemctl", timeout); err == nil {
			t.Fatalf("timeout %s was accepted", timeout)
		}
	}

	controller := &SystemctlController{SystemctlBinary: "/usr/bin/systemctl"}
	if err := controller.StartUnit(context.Background(), "example.service"); err == nil {
		t.Fatal("zero timeout on a direct controller was accepted")
	}
	if _, err := NewSystemctlController("/usr/bin/../bin/systemctl", time.Second); err == nil {
		t.Fatal("unclean systemctl path was accepted")
	}
}

func TestSystemctlControllerBoundsEveryOperation(t *testing.T) {
	binary := fakeSystemctlBinary(t)
	controller := &SystemctlController{SystemctlBinary: binary, Timeout: 40 * time.Millisecond}

	t.Setenv("SYSTEMCTL_TEST_MODE", "sleep")
	operations := []struct {
		name string
		call func(context.Context) error
	}{
		{name: "daemon-reload", call: controller.DaemonReload},
		{name: "enable", call: func(ctx context.Context) error {
			return controller.EnableUnit(ctx, "example.service")
		}},
		{name: "disable", call: func(ctx context.Context) error {
			return controller.DisableUnit(ctx, "example.service")
		}},
		{name: "start", call: func(ctx context.Context) error {
			return controller.StartUnit(ctx, "example.service")
		}},
		{name: "stop", call: func(ctx context.Context) error {
			return controller.StopUnit(ctx, "example.service")
		}},
		{name: "restart", call: func(ctx context.Context) error {
			return controller.RestartUnit(ctx, "example.service")
		}},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			started := time.Now()
			err := operation.call(context.Background())
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("error = %v, want context deadline exceeded", err)
			}
			if elapsed := time.Since(started); elapsed > time.Second {
				t.Fatalf("operation took %s after its deadline", elapsed)
			}
		})
	}

	t.Run("unit-active", func(t *testing.T) {
		active, err := controller.UnitActive(context.Background(), "example.service")
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("error = %v, want context deadline exceeded", err)
		}
		if active {
			t.Fatal("timed out unit was reported active")
		}
	})
}

func TestSystemctlControllerPreservesCallerCancellation(t *testing.T) {
	binary := fakeSystemctlBinary(t)
	controller := &SystemctlController{SystemctlBinary: binary, Timeout: time.Second}
	t.Setenv("SYSTEMCTL_TEST_MODE", "sleep")

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(30*time.Millisecond, cancel)
	defer cancel()

	err := controller.RestartUnit(ctx, "example.service")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context canceled", err)
	}
}

func TestSystemctlControllerUnitActive(t *testing.T) {
	binary := fakeSystemctlBinary(t)
	controller := &SystemctlController{SystemctlBinary: binary, Timeout: time.Second}

	t.Run("active", func(t *testing.T) {
		t.Setenv("SYSTEMCTL_TEST_MODE", "active")
		active, err := controller.UnitActive(context.Background(), "example.service")
		if err != nil || !active {
			t.Fatalf("UnitActive = (%v, %v), want (true, nil)", active, err)
		}
	})
	t.Run("inactive", func(t *testing.T) {
		t.Setenv("SYSTEMCTL_TEST_MODE", "inactive")
		active, err := controller.UnitActive(context.Background(), "example.service")
		if err != nil || active {
			t.Fatalf("UnitActive = (%v, %v), want (false, nil)", active, err)
		}
	})
	t.Run("failure", func(t *testing.T) {
		t.Setenv("SYSTEMCTL_TEST_MODE", "failure")
		active, err := controller.UnitActive(context.Background(), "example.service")
		if err == nil || active {
			t.Fatalf("UnitActive = (%v, %v), want (false, error)", active, err)
		}
	})
}
