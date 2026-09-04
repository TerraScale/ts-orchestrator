package security

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileStateStoreIsAtomicAndSecretFree(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rotation", "state.json")
	store, err := NewFileStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	want := PersistedState{
		OperationID: "op-1", NewVersion: 2, NewCapabilityID: "key-current",
		OldCapabilityID: "key-previous", PublicationReceipt: PublicationReceipt{ReceiptID: "receipt-1", Committed: true},
	}
	if err := store.Save(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.OperationID != want.OperationID || got.NewCapabilityID != want.NewCapabilityID || got.PublicationReceipt.ReceiptID != "receipt-1" {
		t.Fatalf("state mismatch: %+v", got)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "secret") {
		t.Fatalf("state contains secret-bearing field: %s", data)
	}
	if mode := func() os.FileMode { info, _ := os.Stat(path); return info.Mode().Perm() }(); mode != 0o600 {
		t.Fatalf("state mode=%o, want 0600", mode)
	}
}
