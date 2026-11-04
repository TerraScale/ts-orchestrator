package membership

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func survivorStore(t *testing.T) RecoveryTarget {
	t.Helper()
	store := filepath.Join(t.TempDir(), "nats")
	for _, dir := range []string{"jetstream/ACCOUNT/streams/TS_CONTROL_LOG/msgs", "jetstream/$SYS/_js_/_meta_"} {
		if err := os.MkdirAll(filepath.Join(store, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, data := range map[string]string{
		"jetstream/ACCOUNT/streams/TS_CONTROL_LOG/meta.inf":   `{"name":"TS_CONTROL_LOG"}`,
		"jetstream/ACCOUNT/streams/TS_CONTROL_LOG/msgs/1.blk": "block",
		"jetstream/$SYS/_js_/_meta_/peers.idx":                "peers",
	} {
		if err := os.WriteFile(filepath.Join(store, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return RecoveryTarget{Cell: "gru", Slot: "controller-a", StoreDir: store,
		ClientAddress: closedAddress(t), RouteAddress: closedAddress(t)}
}

// closedAddress is a loopback port that refuses connections.
func closedAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	return address
}

func TestBackupRequiresExactConfirmationAndVerifies(t *testing.T) {
	target := survivorStore(t)
	destination := filepath.Join(t.TempDir(), "backup")
	if err := Backup(t.Context(), target, destination, strings.NewReader("yes\n"), new(bytes.Buffer)); err == nil {
		t.Fatal("backup ran without the exact phrase")
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatal("aborted backup created its destination")
	}
	if err := Backup(t.Context(), target, filepath.Join(target.StoreDir, "inside"),
		strings.NewReader("back up gru/controller-a\n"), new(bytes.Buffer)); err == nil {
		t.Fatal("backup into the store itself was allowed")
	}
	if err := Backup(t.Context(), target, destination, strings.NewReader("back up gru/controller-a\n"),
		new(bytes.Buffer)); err != nil {
		t.Fatal(err)
	}
	if files, err := VerifyBackup(destination); err != nil || files != 3 {
		t.Fatalf("verify = %d, %v", files, err)
	}
	if err := Backup(t.Context(), target, destination, strings.NewReader("back up gru/controller-a\n"),
		new(bytes.Buffer)); err == nil {
		t.Fatal("backup overwrote an existing destination")
	}
	if err := os.WriteFile(filepath.Join(destination, "jetstream/ACCOUNT/streams/TS_CONTROL_LOG/msgs/1.blk"),
		[]byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBackup(destination); err == nil {
		t.Fatal("tampered backup verified")
	}
}
