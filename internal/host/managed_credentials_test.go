//go:build linux

package host

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"

	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManagedCredentialOverlayRejectsDowngradeAndSameGenerationReplay(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership is required for the managed overlay contract")
	}
	directory := t.TempDir()
	identity := WorkloadIdentity{GID: uint32(os.Getegid())}
	stateWire := func(generation uint64, registry string) []byte {
		t.Helper()
		sum := sha256.Sum256([]byte(registry))
		state := managedCredentialState{Version: 1, Generation: generation,
			InitialReceiptSHA256: strings.Repeat("a", 64), RegistrySHA256: hex.EncodeToString(sum[:]),
			Registry: []byte(registry), Signature: "signed-state"}
		wire, err := json.Marshal(state)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	second := stateWire(2, `{"version":1,"keys":[2]}`)
	third := stateWire(3, `{"version":1,"keys":[3]}`)
	if _, changed, err := installManagedCredentialState(directory, second, identity); err != nil || !changed {
		t.Fatalf("install generation two: changed=%t err=%v", changed, err)
	}
	if _, changed, err := installManagedCredentialState(directory, third, identity); err != nil || !changed {
		t.Fatalf("install generation three: changed=%t err=%v", changed, err)
	}
	if _, _, err := installManagedCredentialState(directory, second, identity); err == nil {
		t.Fatal("older credential generation replaced the durable floor")
	}
	if _, _, err := installManagedCredentialState(directory, stateWire(3, `{"version":1,"keys":[4]}`), identity); err == nil {
		t.Fatal("same-generation changed bytes replaced the durable floor")
	}
	stored, err := os.ReadFile(filepath.Join(directory, managedCredentialFileName))
	if err != nil || string(stored) != string(third) {
		t.Fatalf("durable generation changed after rejected replay: %v", err)
	}
}
