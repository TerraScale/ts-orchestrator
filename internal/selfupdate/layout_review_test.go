package selfupdate

import (
	"errors"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A FIFO planted where a state file belongs is refused at once instead of
// blocking the read (and the update lock) waiting for a writer.
func TestReadBoundedRefusesAFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proof")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := readBounded(path, 1024)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("FIFO read = %v, want ErrInvalid", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reading a FIFO state file blocked")
	}
}
