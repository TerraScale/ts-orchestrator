package sdnotify

import (
	"path/filepath"
	"testing"
	"time"
)

// A deliberate pre-READY wait keeps extending the start timeout until it is
// stopped, so TimeoutStartSec does not kill a broker that is riding out an
// OCI outage during offline restart admission (#127 11985).
func TestKeepStartingExtendsTheStartTimeoutUntilStopped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify")
	conn := listen(t, path)
	notifier := New(path, "", "", 1)
	stop := notifier.KeepStarting(t.Context(), 10*time.Millisecond, 3*time.Minute)
	for range 2 {
		if got := receive(t, conn); got != "EXTEND_TIMEOUT_USEC=180000000" {
			t.Fatalf("extension = %q", got)
		}
	}
	stop()
	// Drain anything sent before stop returned, then require silence.
	buffer := make([]byte, 128)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		if _, err := conn.Read(buffer); err != nil {
			break
		}
	}
	_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if count, err := conn.Read(buffer); err == nil {
		t.Fatalf("extension sent after stop: %q", buffer[:count])
	}
	// Outside systemd, or with an extension no longer than the interval, it
	// is a no-op.
	New("", "", "", 1).KeepStarting(t.Context(), time.Millisecond, time.Minute)()
	notifier.KeepStarting(t.Context(), time.Minute, time.Minute)()
}
