//go:build linux

package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
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

func TestManagedCredentialFloorRejectsOldHostSessionAndReadOutage(t *testing.T) {
	controller, _, _, _, _ := testControllerWithVerifier(t,
		managedRegistrationVerifierFunc(func(context.Context, Registration) error { return nil }))
	registration, _, hostKey := managedContractFixture()
	registration.ManagedPlacement = &ManagedPlacementBinding{
		DatabaseID: "database-a", PartitionID: "partition-a", SeatID: "seat-a",
		IntentGeneration: 1, IntentPayloadDigest: strings.Repeat("a", 64),
		CanonicalRosterDigest: strings.Repeat("b", 64), ManagedHostProfileDigest: strings.Repeat("c", 64),
	}
	if _, err := controller.Register(t.Context(), registration); err != nil {
		t.Fatal(err)
	}
	controller.credentialFloor = func(context.Context, Registration) (uint64, error) { return 1, nil }
	sessionID := "0123456789abcdef0123456789abcdef"
	acquire := signedHostRequest(t, hostKey, "session", sessionID, 0, struct {
		Kind string `json:"kind"`
	}{"acquire"})
	acquired, err := controller.handleSession(t.Context(), acquire)
	if err != nil {
		t.Fatalf("generation one session failed: %v", err)
	}
	epoch := acquired.(session).Epoch
	renew := signedHostRequest(t, hostKey, "session", sessionID, epoch, struct {
		Kind string `json:"kind"`
	}{"renew"})
	controller.credentialFloor = func(context.Context, Registration) (uint64, error) { return 2, nil }
	if _, err := controller.handleSession(t.Context(), renew); err == nil {
		t.Fatal("old host renewed after a revoked credential generation was committed")
	}
	renew.CredentialProtocol = 1
	if err := signRequest(&renew, hostKey, "gru"); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.handleSession(t.Context(), renew); err != nil {
		t.Fatalf("capable host could not renew: %v", err)
	}
	controller.credentialFloor = func(context.Context, Registration) (uint64, error) {
		return 0, errors.New("R3 read unavailable")
	}
	outageRenew := signedHostRequest(t, hostKey, "session", sessionID, epoch, struct {
		Kind string `json:"kind"`
	}{"renew"})
	outageRenew.CredentialProtocol = 1
	if err := signRequest(&outageRenew, hostKey, "gru"); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.handleSession(t.Context(), outageRenew); err == nil {
		t.Fatal("host renewed while R3 credential floor was unreadable")
	}
}
