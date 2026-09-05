package nodeauthority

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestInitialSecretsRetireBeforeOldPinsAreRead(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "ts-node", "command-journal")
	calls := 0
	provision := func() error {
		calls++
		if other, err := NewEpochStore(directory, "gru-1"); err == nil {
			other.Close()
			t.Fatal("receiver ownership overlapped credential effects")
		}
		return nil
	}
	if err := WithInitialAuthority(directory, "gru-1", provision); err != nil {
		t.Fatal(err)
	}
	store, err := NewEpochStore(directory, "gru-1")
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Admit(CommandAuthorization{NodeID: "gru-1", AuthorityID: "gru-regional", Epoch: 7, CandidateID: "gru-controller-1", LeaseID: "actual-lease"}); err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	if err = WithInitialAuthority(directory, "gru-1", func() error { calls++; return errors.New("old initial pin differs from rotated credentials") }); err != nil {
		t.Fatalf("retired initial pin blocked startup: %v", err)
	}
	if calls != 1 {
		t.Fatal("retired initial secrets were inspected or rewritten")
	}
	if err = WithInitialAuthority(directory, "gru-2", provision); err == nil {
		t.Fatal("another host reused retirement proof")
	}
	if err = os.WriteFile(filepath.Join(directory, "authority-epoch.json"), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err = WithInitialAuthority(directory, "gru-1", provision); err == nil {
		t.Fatal("corrupt retirement silently provisioned credentials")
	}
	if calls != 1 {
		t.Fatal("invalid retirement caused provisioning")
	}
}
