package bootstrapstart

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nkeys"
	"golang.org/x/sys/unix"
)

func acceptedPublicKey(t *testing.T, operator bool) string {
	t.Helper()
	var pair nkeys.KeyPair
	var err error
	if operator {
		pair, err = nkeys.CreateOperator()
	} else {
		pair, err = nkeys.CreateAccount()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer pair.Wipe()
	key, err := pair.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func acceptedReferences(slot string) []bootstrap.SecretReference {
	roles := map[string]bootstrap.SecretPurpose{
		"operator.jwt": bootstrap.SecretRegionalShared, "system.jwt": bootstrap.SecretRegionalShared,
		"cell.jwt": bootstrap.SecretRegionalShared, "system.creds": bootstrap.SecretRegionalShared,
		"ca.pem": bootstrap.SecretRegionalShared, "route-password": bootstrap.SecretRegionalShared,
		"ticket.pub": bootstrap.SecretRegionalShared, "ticket.key": bootstrap.SecretRegionalShared,
		"host-nats-issuer.seed": bootstrap.SecretHostIssuer, "host-tls-issuer-cert.pem": bootstrap.SecretHostIssuer,
		"host-tls-issuer-key.pem": bootstrap.SecretHostIssuer,
		slot + ".creds":           bootstrap.SecretController, slot + "-tls-cert.pem": bootstrap.SecretController,
		slot + "-tls-key.pem": bootstrap.SecretController, slot + "-response.key": bootstrap.SecretController,
	}
	var references []bootstrap.SecretReference
	for _, name := range slices.Sorted(maps.Keys(roles)) {
		ref := bootstrap.SecretReference{Purpose: roles[name], SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1." + slot + "-material",
			VersionNumber: 7, SHA256: digest([]byte(name)), MaxBytes: 65536, TargetFile: name}
		if ref.Purpose == bootstrap.SecretController {
			ref.Slot = slot
		}
		references = append(references, ref)
	}
	return references
}

func acceptedLaunchPinFixture() map[string]string {
	pins := make(map[string]string, 4)
	for _, name := range acceptedLaunchNames {
		pins[name] = digest([]byte(name))
	}
	return pins
}

func acceptedIdentityFixture(t *testing.T) AcceptedIdentity {
	t.Helper()
	storeDir := filepath.Join(t.TempDir(), "nats")
	if err := os.Mkdir(storeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	serverWire, nodeWire := []byte("gru-1-ctl-1\n"), []byte(`{"version":1,"cell":"gru","instance":"controller-a","node_id":"NODE0000"}`)
	for name, wire := range map[string][]byte{"server-name": serverWire, "node-identity.json": nodeWire} {
		if err := os.WriteFile(filepath.Join(storeDir, name), wire, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	identity := AcceptedIdentity{SchemaVersion: 1, Origin: identityrekey.AcceptanceOriginInitial, OperationID: entityid.Derive("accepted-operation"),
		DeploymentID: entityid.Derive("accepted-deployment"), ClusterID: entityid.Derive("accepted-cluster"),
		Environment: "canary", Cell: "GRU", Slot: "controller-a", SeedSlot: "controller-b",
		ControllerSlots: []string{"controller-a", "controller-b", "controller-c"},
		InstanceOCID:    "ocid1.instance.oc1.sa-saopaulo-1.existing0", ImageOCID: "ocid1.image.oc1.sa-saopaulo-1.existing",
		PrimaryVNICOCID: "ocid1.vnic.oc1.sa-saopaulo-1.existing0", PrimaryPrivateIP: "10.251.0.11",
		Binary: identityrekey.BinaryPin{SHA256: digest([]byte("executable")), Size: 4096, Architecture: "amd64"},
		Broker: identityrekey.BrokerIdentity{Operator: acceptedPublicKey(t, true), SystemAccount: acceptedPublicKey(t, false),
			CellAccount: acceptedPublicKey(t, false), HostSigner: acceptedPublicKey(t, false), RoleSigner: acceptedPublicKey(t, false)},
		Store: identityrekey.StoreIdentity{Directory: storeDir, ServerName: "gru-1-ctl-1", RaftNodeID: "NODE0000",
			ServerNameSHA256: digest(serverWire), NodeIdentitySHA256: digest(nodeWire)},
		ConfigSHA256: map[string]string{"controller.json": digest([]byte("controller config")),
			"oci-region.json": digest([]byte("region")), "oci-region-intent.json": digest([]byte("intent")), "placement.json": digest([]byte("placement"))},
		LaunchMaterialSHA256: acceptedLaunchPinFixture(), MaterialReferences: acceptedReferences("controller-a"),
		AcceptedAt: time.Now().UTC().Truncate(time.Second)}
	identity.ControllerBindings = []ControllerBinding{identity.localBinding()}
	if err := identity.Validate(); err != nil {
		t.Fatal(err)
	}
	return identity
}

func acceptedCheckpoint(t *testing.T, identity AcceptedIdentity, previous []byte) (identityrekey.AcceptedIdentityCheckpoint, ed25519.PrivateKey, trust.Keyring) {
	t.Helper()
	checkpoint := identityrekey.AcceptedIdentityCheckpoint{SchemaVersion: 1, OperationID: identity.OperationID,
		DeploymentID: identity.DeploymentID, ClusterID: identity.ClusterID, Environment: identity.Environment, Cell: identity.Cell,
		SeedSlot: identity.SeedSlot, Broker: identity.Broker, ManagedMaterial: identity.ManagedMaterial,
		MaterialGenerationSHA256: digest([]byte("material generation"))}
	for i, slot := range identity.ControllerSlots {
		store := identity.Store
		store.ServerName, store.RaftNodeID = fmt.Sprintf("gru-1-ctl-%d", i+1), fmt.Sprintf("NODE000%d", i)
		checkpoint.Slots = append(checkpoint.Slots, identityrekey.SlotBinding{Slot: slot, PreviousAcceptanceSHA256: digest(previous),
			PreviousMaterialSHA256: map[string]string{"installed": digest([]byte("old material chain")), "durable": digest([]byte("old material chain"))},
			InstanceOCID:           fmt.Sprintf("ocid1.instance.oc1.sa-saopaulo-1.existing%d", i), ImageOCID: identity.ImageOCID,
			PrimaryVNICOCID: fmt.Sprintf("ocid1.vnic.oc1.sa-saopaulo-1.existing%d", i), PrimaryPrivateIP: fmt.Sprintf("10.251.0.%d", 11+i),
			Binary: identity.Binary, Store: store, ConfigSHA256: maps.Clone(identity.ConfigSHA256), LaunchMaterialSHA256: maps.Clone(identity.LaunchMaterialSHA256), MaterialReferences: acceptedReferences(slot)})
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(public)
	if err != nil {
		t.Fatal(err)
	}
	return checkpoint, private, roots
}

func verifyAcceptedCheckpoint(t *testing.T, checkpoint identityrekey.AcceptedIdentityCheckpoint,
	private ed25519.PrivateKey, roots trust.Keyring, now time.Time,
) identityrekey.VerifiedIdentityCheckpoint {
	t.Helper()
	envelope, err := identityrekey.IssueAcceptedIdentityCheckpoint(checkpoint, now.Add(-time.Minute), now.Add(time.Hour), private)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := identityrekey.VerifyAcceptedIdentityCheckpoint(wire, roots, trust.RootChain{Version: 1}, identityrekey.CheckpointExpectation{
		OperationID: checkpoint.OperationID, DeploymentID: checkpoint.DeploymentID, ClusterID: checkpoint.ClusterID,
		Environment: checkpoint.Environment, Cell: checkpoint.Cell, SeedSlot: checkpoint.SeedSlot, ManagedMaterial: checkpoint.ManagedMaterial,
		Broker: checkpoint.Broker, MaterialGenerationSHA256: checkpoint.MaterialGenerationSHA256, Slot: checkpoint.Slots[0]}, now)
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

func acceptedObservation(identity AcceptedIdentity) (identityrekey.BrokerIdentity, identityrekey.StoreIdentity, error) {
	return identity.Broker, identity.Store, nil
}

func TestAcceptedIdentityPublicationPredecessorAndNoReplace(t *testing.T) {
	identity := acceptedIdentityFixture(t)
	store := testMarkerStore(t)
	old := []byte("retired arbitrary bytes that cannot be decoded as JSON\n")
	path := filepath.Join(store.directory, markerName)
	if err := os.WriteFile(path, old, 0o644); err != nil {
		t.Fatal(err)
	}
	checkpoint, key, roots := acceptedCheckpoint(t, identity, old)
	verified := verifyAcceptedCheckpoint(t, checkpoint, key, roots, identity.AcceptedAt)
	if err := store.ReplaceIdentity(identityrekey.VerifiedIdentityCheckpoint{}, identity.Slot, identity.AcceptedAt, acceptedObservation); err == nil {
		t.Fatal("zero proof changed disk")
	}
	wrong := bytes.TrimSpace(old)
	if err := os.WriteFile(path, wrong, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceIdentity(verified, identity.Slot, identity.AcceptedAt, acceptedObservation); !errors.Is(err, ErrAcceptancePredecessor) {
		t.Fatalf("wrong predecessor: %v", err)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, wrong) {
		t.Fatal("wrong predecessor was overwritten")
	}
	if err := os.WriteFile(path, old, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceIdentity(verified, identity.Slot, identity.AcceptedAt, acceptedObservation); err != nil {
		t.Fatal(err)
	}
	read, err := store.ReadIdentity()
	if err != nil || read.OperationID != identity.OperationID || len(read.ControllerBindings) != 3 {
		t.Fatalf("replacement unreadable: %+v, %v", read, err)
	}
	if _, err := store.ReadInitialFormation(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement invented initial formation: %v", err)
	}
	if err := store.WriteNewIdentity(identity, acceptedObservation); !errors.Is(err, unix.EEXIST) {
		t.Fatalf("write-new replaced acceptance: %v", err)
	}
	if err := store.ReplaceIdentity(verified, identity.Slot, identity.AcceptedAt, acceptedObservation); !errors.Is(err, ErrAcceptancePredecessor) {
		t.Fatalf("replay replaced different predecessor: %v", err)
	}
}
