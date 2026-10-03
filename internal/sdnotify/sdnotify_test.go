package sdnotify

import (
	"context"
	"net"
	"path/filepath"
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

func TestNotifierIsANoOpOutsideSystemd(t *testing.T) {
	for _, socket := range []string{"", "relative/path", "tcp://host"} {
		notifier := New(socket, "1000000", "", 1)
		if notifier.Enabled() || notifier.WatchdogInterval() != 0 {
			t.Fatalf("socket %q enabled notifications", socket)
		}
		if err := notifier.Ready("x"); err != nil {
			t.Fatal(err)
		}
	}
	var nilNotifier *Notifier
	if nilNotifier.Enabled() || nilNotifier.Notify("READY=1") != nil {
		t.Fatal("nil notifier is not a no-op")
	}
}

func TestWatchdogIntervalHonorsOwnerPID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify")
	if got := New(path, "4000000", "", 7).WatchdogInterval(); got != 2*time.Second {
		t.Fatalf("interval = %s", got)
	}
	if got := New(path, "4000000", "7", 7).WatchdogInterval(); got != 2*time.Second {
		t.Fatalf("owned interval = %s", got)
	}
	if got := New(path, "4000000", "8", 7).WatchdogInterval(); got != 0 {
		t.Fatalf("another process's watchdog applied: %s", got)
	}
	if got := New(path, "junk", "", 7).WatchdogInterval(); got != 0 {
		t.Fatalf("invalid watchdog applied: %s", got)
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
