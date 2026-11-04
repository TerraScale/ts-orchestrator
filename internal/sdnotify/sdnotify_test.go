package sdnotify

import (
	"net"

	"path/filepath"

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
