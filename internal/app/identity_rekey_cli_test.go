package app

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"

	"golang.org/x/sys/unix"
)

func TestIdentityRekeyFinalInputsRecoverAfterInterruptedPublication(t *testing.T) {
	directory := t.TempDir()
	dir, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dir)
	proposal := bootstrapstart.IdentityRekeyJournal{Version: 1, AcceptedWire: []byte("reviewed acceptance"),
		ResetWire: []byte("reviewed floor"), CheckpointWire: []byte("reviewed checkpoint"), Values: [][]byte{[]byte("reviewed material")}}
	final := proposal
	final.AcceptedWire, final.ResetWire = []byte("final acceptance"), []byte("final signed floor")
	original, err := protocol.EncodeJSON(proposal)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"identity-rekey.json", ".identity-rekey.final.json", ".identity-rekey.final.abandoned.json"} {
		if err := os.WriteFile(filepath.Join(directory, name), original, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	expected, err := protocol.EncodeJSON(final)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := recoverFinalIdentityRekeyInput(dir, proposal, final); err != nil {
			t.Fatal(err)
		}
		actual, err := readExactControllerFile(dir, "identity-rekey.json", uint32(os.Getuid()), uint32(os.Getgid()), 0o600, bootstrapstart.MaxIdentityRekeyJournalBytes)
		if err != nil || !bytes.Equal(actual, expected) {
			t.Fatalf("finalized journal not recovered exactly: %v", err)
		}
	}
	for _, fault := range []string{"checkpoint", "material"} {
		changed := final
		if fault == "checkpoint" {
			changed.CheckpointWire = []byte("another checkpoint")
		} else {
			changed.Values = [][]byte{[]byte("another material")}
		}
		if err := recoverFinalIdentityRekeyInput(dir, proposal, changed); !errors.Is(err, bootstrapstart.ErrIdentityRekeyJournal) {
			t.Fatalf("different %s recovered: %v", fault, err)
		}
		actual, err := os.ReadFile(filepath.Join(directory, "identity-rekey.json"))
		if err != nil || !bytes.Equal(actual, expected) {
			t.Fatal("refused recovery changed finalized journal")
		}
	}
}
