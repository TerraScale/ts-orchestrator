package app

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostboot"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostenroll"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

func TestPersistedHostRequestRecoveryAcrossReplayWindow(t *testing.T) {
	root := t.TempDir()
	descriptor := hostboot.Descriptor{
		SchemaVersion: hostboot.SchemaVersion, Cell: "gru", Region: "GRU",
		Node: "host-0123456789abcdef01234567", Owner: "terrascale",
		CreateKey: "th-0123456789abcdef0123456789abcdef0123456789abcdef",
		ImageID:   "ocid1.image.oc1.sa-saopaulo-1.image-a", FleetGeneration: 7,
		HostAttempt: 2, IntentGeneration: 9,
		DatabaseID: "database-a", PartitionID: "partition-a", SeatID: "permanent-a",
		IntentPayloadDigest: strings.Repeat("a", 64), CanonicalRosterDigest: strings.Repeat("b", 64),
		ManagedHostProfileDigest: strings.Repeat("c", 64), RuntimeManifestDigest: strings.Repeat("d", 64),
	}
	descriptorWire, err := descriptor.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	pending, err := readOrCreateHostEnrollment(t.Context(), root, hostenroll.InstanceMetadata{
		InstanceID: "ocid1.instance.oc1.sa-saopaulo-1.host-a", Descriptor: descriptor, Wire: descriptorWire,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	original, err := parsePersistedHostRequest(pending.Request)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := base64.StdEncoding.DecodeString(pending.IdentityKey)
	if err != nil {
		t.Fatal(err)
	}
	original.IssuedAt = time.Now().UTC().Add(-49 * time.Hour)
	if err := original.Sign(ed25519.PrivateKey(identity)); err != nil {
		t.Fatal(err)
	}
	oldWire, err := protocol.EncodeJSON(original)
	if err != nil {
		t.Fatal(err)
	}
	pending.Request = oldWire
	pendingWire, err := protocol.EncodeJSON(pending)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, pendingHostEnrollmentFile), pendingWire, 0o600); err != nil {
		t.Fatal(err)
	}
	parsed, err := parsePersistedHostRequest(oldWire)
	if err != nil || parsed != original {
		t.Fatalf("persisted old request: request=%+v err=%v", parsed, err)
	}
	if _, _, err := hostenroll.ParseRequest(oldWire, time.Now()); err == nil {
		t.Fatal("controller freshness check accepted an ungranted old request")
	}
	initialWire, err := createFreshInitialRequest(t.Context(), root, pending, original, nil)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := parsePersistedHostRequest(initialWire)
	if err != nil || initial.Operation != "enroll" || initial.Nonce == original.Nonce ||
		initial.IdentityPublicKey != original.IdentityPublicKey || initial.NATSUserPublicKey != original.NATSUserPublicKey ||
		initial.CSRPEM != original.CSRPEM || initial.Descriptor != original.Descriptor || initial.InstanceID != original.InstanceID {
		t.Fatalf("refreshed initial request lost persisted bindings: request=%+v err=%v", initial, err)
	}
	if _, _, err := hostenroll.ParseRequest(initialWire, time.Now()); err != nil {
		t.Fatalf("refreshed initial request is not fresh and signed: %v", err)
	}
	storedWire, err := os.ReadFile(filepath.Join(root, pendingHostEnrollmentFile))
	if err != nil {
		t.Fatal(err)
	}
	var stored pendingHostEnrollment
	if err := json.Unmarshal(storedWire, &stored, json.RejectUnknownMembers(true)); err != nil ||
		!bytes.Equal(stored.Request, initialWire) || stored.IdentityKey != pending.IdentityKey ||
		stored.NATSUserSeed != pending.NATSUserSeed || stored.TLSPrivateKey != pending.TLSPrivateKey {
		t.Fatalf("refreshed initial request was not durably stored with the same private keys: %v", err)
	}
	renewalWire, err := createFreshRenewalRequest(root, pending, original)
	if err != nil {
		t.Fatal(err)
	}
	renewal, err := parsePersistedHostRequest(renewalWire)
	if err != nil || renewal.Operation != "renew" || renewal.Nonce == original.Nonce ||
		renewal.IdentityPublicKey != original.IdentityPublicKey || renewal.NATSUserPublicKey != original.NATSUserPublicKey ||
		renewal.CSRPEM != original.CSRPEM || renewal.Descriptor != original.Descriptor || renewal.InstanceID != original.InstanceID {
		t.Fatalf("refreshed renewal lost persisted bindings: request=%+v err=%v", renewal, err)
	}
	if _, _, err := hostenroll.ParseRequest(renewalWire, time.Now()); err != nil {
		t.Fatalf("refreshed renewal is not fresh and signed: %v", err)
	}
	cachedRenewal, err := createRenewalRequest(root, pending, original)
	if err != nil || !bytes.Equal(cachedRenewal, renewalWire) {
		t.Fatalf("retry did not reuse exact renewal request: %v", err)
	}
	refreshedRenewal, err := createFreshRenewalRequest(root, pending, original)
	if err != nil || bytes.Equal(refreshedRenewal, renewalWire) {
		t.Fatalf("renewal refresh did not replace stale request: %v", err)
	}
	storedRenewal, err := os.ReadFile(filepath.Join(root, ".host-enrollment-renewal.json"))
	if err != nil || !bytes.Equal(storedRenewal, refreshedRenewal) {
		t.Fatalf("refreshed renewal was not durably stored: %v", err)
	}
}
