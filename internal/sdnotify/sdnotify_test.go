package sdnotify

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func listen(t *testing.T, name string) *net.UnixConn {
	t.Helper()
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: name, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func receive(t *testing.T, conn *net.UnixConn) string {
	t.Helper()
	buffer := make([]byte, 4096)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	count, err := conn.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	return string(buffer[:count])
}

func TestNotifierSendsReadyAndStoppingToPathSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify")
	conn := listen(t, path)
	notifier := New(path, "", "", 1)
	if !notifier.Enabled() {
		t.Fatal("notifier with a socket is disabled")
	}
	if err := notifier.Ready("controller ready\nin gru"); err != nil {
		t.Fatal(err)
	}
	if got := receive(t, conn); got != "READY=1\nSTATUS=controller ready in gru" {
		t.Fatalf("ready = %q", got)
	}
	if err := notifier.Stopping(); err != nil {
		t.Fatal(err)
	}
	if got := receive(t, conn); got != "STOPPING=1" {
		t.Fatalf("stopping = %q", got)
	}
}

func TestNotifierSupportsAbstractSockets(t *testing.T) {
	name := "ts-sdnotify-" + strings.ReplaceAll(t.Name(), "/", "-") + "-" + time.Now().Format("150405.000000000")
	conn := listen(t, "\x00"+name)
	if err := New("@"+name, "", "", 1).Notify("READY=1"); err != nil {
		t.Fatal(err)
	}
	if got := receive(t, conn); got != "READY=1" {
		t.Fatalf("abstract notify = %q", got)
	}
}

func TestNotifierEnvironmentAndWatchdogProcess(t *testing.T) {
	if os.Getenv("TS_SDNOTIFY_TEST_CHILD") == "1" {
		if os.Getenv("WATCHDOG_PID") == "self" {
			t.Setenv("WATCHDOG_PID", strconv.Itoa(os.Getpid()))
		}
		notifier := FromEnvironment()
		for _, name := range []string{"NOTIFY_SOCKET", "WATCHDOG_USEC", "WATCHDOG_PID"} {
			if _, exists := os.LookupEnv(name); exists {
				t.Fatalf("notification environment %s would leak to workloads", name)
			}
		}
		var absent *Notifier
		if err := absent.Notify("READY=1"); err != nil {
			t.Fatal(err)
		}
		absent.RunWatchdog(t.Context(), nil)
		absent.KeepStarting(t.Context(), time.Millisecond, time.Minute)()
		if err := notifier.Ready("child ready"); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		notifier.RunWatchdog(ctx, nil)
		if err := notifier.Stopping(); err != nil {
			t.Fatal(err)
		}
		return
	}

	for _, tc := range []struct {
		name, socket, usec, pid string
		watchdog                bool
	}{
		{name: "owner-unspecified", usec: "40000", watchdog: true},
		{name: "owner-matches", usec: "40000", pid: "self", watchdog: true},
		{name: "another-owner", usec: "40000", pid: "0"},
		{name: "invalid-owner", usec: "40000", pid: "invalid"},
		{name: "invalid-interval", usec: "invalid"},
		{name: "zero-interval", usec: "0"},
		{name: "missing-socket", socket: "missing", usec: "40000"},
		{name: "relative-socket", socket: "relative/path", usec: "40000"},
		{name: "unsupported-socket", socket: "tcp://host", usec: "40000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "notify")
			conn := listen(t, path)
			socket := tc.socket
			if socket == "" {
				socket = path
			} else if socket == "missing" {
				socket = ""
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestNotifierEnvironmentAndWatchdogProcess$")
			cmd.Env = append(os.Environ(), "TS_SDNOTIFY_TEST_CHILD=1", "NOTIFY_SOCKET="+socket,
				"WATCHDOG_USEC="+tc.usec, "WATCHDOG_PID="+tc.pid, "GORACE=atexit_sleep_ms=0")
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("notifier process: %v\n%s", err, output)
			}
			if socket != path {
				_ = conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
				if _, err := conn.Read(make([]byte, 4096)); err == nil {
					t.Fatal("notification sent without a valid systemd socket")
				} else if timeout, ok := errors.AsType[net.Error](err); !ok || !timeout.Timeout() {
					t.Fatal(err)
				}
				return
			}
			if got := receive(t, conn); got != "READY=1\nSTATUS=child ready" {
				t.Fatalf("ready = %q", got)
			}
			pings := 0
			for state := receive(t, conn); state != "STOPPING=1"; state = receive(t, conn) {
				if state != "WATCHDOG=1" || !tc.watchdog {
					t.Fatalf("unexpected notification %q", state)
				}
				pings++
			}
			if tc.watchdog && pings == 0 {
				t.Fatal("healthy owner sent no watchdog notification")
			}
		})
	}
}

func TestRunWatchdogPingsOnlyWhileHealthy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify")
	conn := listen(t, path)
	notifier := New(path, "40000", "", 1) // 20ms pings
	var healthy atomic.Bool
	healthy.Store(true)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		notifier.RunWatchdog(ctx, healthy.Load)
		close(done)
	}()
	if got := receive(t, conn); got != "WATCHDOG=1" {
		t.Fatalf("watchdog = %q", got)
	}
	healthy.Store(false)
	time.Sleep(60 * time.Millisecond)
	// Drain pings sent before the health change, then require silence.
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	buffer := make([]byte, 64)
	for {
		if _, err := conn.Read(buffer); err != nil {
			break
		}
	}
	_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := conn.Read(buffer); err == nil {
		t.Fatal("unhealthy service kept sending watchdog pings")
	}
	cancel()
	<-done
}
