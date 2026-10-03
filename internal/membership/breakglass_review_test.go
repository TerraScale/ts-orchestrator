package membership

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBrokerChecksFailClosedWithoutListeners(t *testing.T) {
	target := survivorStore(t)
	target.ClientAddress, target.RouteAddress = "", ""
	if err := BrokerStopped(t.Context(), target); !errors.Is(err, errNoBrokerListener) {
		t.Fatalf("BrokerStopped without listeners = %v", err)
	}
	if _, err := Preflight(t.Context(), target, new(bytes.Buffer)); !errors.Is(err, errNoBrokerListener) {
		t.Fatalf("Preflight without listeners = %v", err)
	}
	target.ClientAddress = "127.0.0.1:-1"
	if err := BrokerStopped(t.Context(), target); !errors.Is(err, errNoBrokerListener) {
		t.Fatalf("BrokerStopped with a random port = %v", err)
	}
}

func TestBrokerStoppedRejectsIndeterminateDials(t *testing.T) {
	target := survivorStore(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := BrokerStopped(ctx, target); err == nil {
		t.Fatal("a cancelled probe established a stopped broker")
	}
	target.ClientAddress = "unresolvable.invalid:4222"
	if err := BrokerStopped(t.Context(), target); err == nil {
		t.Fatal("an unresolvable listener established a stopped broker")
	}
}

func TestBrokerRunningRequiresAnAcceptingListener(t *testing.T) {
	target := survivorStore(t)
	if err := BrokerRunning(t.Context(), target); err == nil {
		t.Fatal("a stopped survivor counted as running")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	target.RouteAddress = listener.Addr().String()
	if err := BrokerRunning(t.Context(), target); err != nil {
		t.Fatal(err)
	}
}

func TestConfirmRequiresANewline(t *testing.T) {
	if err := Confirm(context.Background(), strings.NewReader("re-found gru/b"), new(bytes.Buffer), "w", "re-found gru/b"); err == nil {
		t.Fatal("confirmation without a newline was accepted")
	}
	if err := Confirm(context.Background(), strings.NewReader("re-found gru/b\n"), new(bytes.Buffer), "w", "re-found gru/b"); err != nil {
		t.Fatal(err)
	}
}

func TestBackupRefusesASymlinkedDestinationInsideTheStore(t *testing.T) {
	target := survivorStore(t)
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(target.StoreDir, alias); err != nil {
		t.Fatal(err)
	}
	err := Backup(t.Context(), target, filepath.Join(alias, "backup"),
		strings.NewReader("back up gru/controller-a\n"), new(bytes.Buffer))
	if err == nil || !strings.Contains(err.Error(), "outside the survivor store") {
		t.Fatalf("symlinked destination inside the store = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(target.StoreDir, "backup")); !os.IsNotExist(err) {
		t.Fatal("backup wrote into the survivor store")
	}
}

func TestFailedBackupRemovesItsDestination(t *testing.T) {
	target := survivorStore(t)
	destination := filepath.Join(t.TempDir(), "backup")
	unreadable := filepath.Join(target.StoreDir, "jetstream/ACCOUNT/streams/TS_CONTROL_LOG/msgs/1.blk")
	if os.Geteuid() == 0 {
		t.Skip("root reads unreadable files")
	}
	if err := os.Chmod(unreadable, 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(unreadable, 0o600)
	if err := Backup(t.Context(), target, destination, strings.NewReader("back up gru/controller-a\n"),
		new(bytes.Buffer)); err == nil {
		t.Fatal("backup of an unreadable store succeeded")
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatalf("failed backup left %s behind", destination)
	}
}

func TestVerifyBackupForBindsSurvivorAndAge(t *testing.T) {
	target := survivorStore(t)
	destination := filepath.Join(t.TempDir(), "backup")
	if err := Backup(t.Context(), target, destination, strings.NewReader("back up gru/controller-a\n"),
		new(bytes.Buffer)); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if files, err := VerifyBackupFor(destination, target, now, BackupMaxAge); err != nil || files != 3 {
		t.Fatalf("matching backup = %d, %v", files, err)
	}
	other := target
	other.Slot = "controller-b"
	if _, err := VerifyBackupFor(destination, other, now, BackupMaxAge); err == nil {
		t.Fatal("a backup of another survivor verified")
	}
	if _, err := VerifyBackupFor(destination, target, now.Add(BackupMaxAge+time.Hour), BackupMaxAge); err == nil {
		t.Fatal("a stale backup verified")
	}
}

func TestVerifyBackupNameRules(t *testing.T) {
	for name, want := range map[string]bool{"a..b": true, "jetstream/x..y/1.blk": true, "../x": false,
		"a/../b": false, "/abs": false, "a//b": false, "./a": false, BackupManifestName: false} {
		if got := validBackupName(name); got != want {
			t.Errorf("validBackupName(%q) = %v, want %v", name, got, want)
		}
	}
	dir := t.TempDir()
	sum := strings.Repeat("0", 64)
	if err := os.WriteFile(filepath.Join(dir, BackupManifestName),
		[]byte(sum+"  a\n"+sum+"  a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBackup(dir); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("duplicated manifest entry = %v", err)
	}
}
