package bootstrapstart

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
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

func TestAcceptedIdentityStrictV1(t *testing.T) {
	identity := acceptedIdentityFixture(t)
	wire, err := EncodeAcceptedIdentity(identity)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeAcceptedIdentity(wire)
	if err != nil || !reflect.DeepEqual(decoded, identity) {
		t.Fatalf("round trip: %+v, %v", decoded, err)
	}
	oldWire, err := protocol.EncodeJSON(testMarker())
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]byte{oldWire, append(bytes.Clone(wire), '\n'), []byte(`{"schemaVersion":1}`),
		bytes.Replace(wire, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1,"schemaVersion":1`), 1),
		bytes.Replace(wire, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1,"checkpointWire":"anything"`), 1)} {
		if _, err := DecodeAcceptedIdentity(invalid); err == nil {
			t.Fatalf("accepted invalid v1 wire: %.80s", invalid)
		}
	}
	var fields map[string]jsontext.Value
	if err := json.Unmarshal(wire, &fields); err != nil {
		t.Fatal(err)
	}
	for field := range fields {
		missing := maps.Clone(fields)
		delete(missing, field)
		data, err := protocol.EncodeJSON(missing)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeAcceptedIdentity(data); err == nil {
			t.Errorf("accepted missing field %s", field)
		}
	}
}

func TestAcceptedIdentityRejectsInvalidScopeAndInventories(t *testing.T) {
	identity := acceptedIdentityFixture(t)
	for _, test := range []struct {
		name string
		edit func(*AcceptedIdentity)
	}{
		{"schema", func(i *AcceptedIdentity) { i.SchemaVersion = 2 }},
		{"absent origin", func(i *AcceptedIdentity) { i.Origin = "" }},
		{"unknown origin", func(i *AcceptedIdentity) { i.Origin = "other" }},
		{"old deployment ID", func(i *AcceptedIdentity) { i.DeploymentID = strings.Repeat("a", 64) }},
		{"lowercase cell", func(i *AcceptedIdentity) { i.Cell = "gru" }},
		{"foreign seed", func(i *AcceptedIdentity) { i.SeedSlot = "controller-d" }},
		{"intended topology", func(i *AcceptedIdentity) { i.ControllerSlots = i.ControllerSlots[:1] }},
		{"invented peer", func(i *AcceptedIdentity) { i.ControllerBindings[0].Slot = "controller-c" }},
		{"mismatched local physical", func(i *AcceptedIdentity) { i.InstanceOCID += "other" }},
		{"foreign reference", func(i *AcceptedIdentity) { i.MaterialReferences[0].Slot = "controller-b" }},
		{"foreign Vault", func(i *AcceptedIdentity) {
			i.MaterialReferences[0].SecretOCID = "ocid1.vaultsecret.oc1.us-sanjose-1.foreign"
		}},
		{"missing ticket", func(i *AcceptedIdentity) {
			i.MaterialReferences = slices.DeleteFunc(i.MaterialReferences, func(r bootstrap.SecretReference) bool { return r.TargetFile == "ticket.key" })
		}},
		{"missing config", func(i *AcceptedIdentity) { delete(i.ConfigSHA256, "placement.json") }},
		{"unknown config", func(i *AcceptedIdentity) { i.ConfigSHA256["extra.json"] = digest([]byte("extra")) }},
		{"unknown material", func(i *AcceptedIdentity) { i.MaterialReferences[0].TargetFile = "unreviewed.seed" }},
		{"offline material", func(i *AcceptedIdentity) { i.MaterialReferences[0].TargetFile = "issuer-operator.seed" }},
		{"wrong purpose", func(i *AcceptedIdentity) { i.MaterialReferences[0].Purpose = bootstrap.SecretController }},
		{"missing version", func(i *AcceptedIdentity) { i.MaterialReferences[0].VersionNumber = 0 }},
		{"duplicate reference", func(i *AcceptedIdentity) {
			i.MaterialReferences = append(i.MaterialReferences, i.MaterialReferences[0])
		}},
		{"non-UTC time", func(i *AcceptedIdentity) { i.AcceptedAt = i.AcceptedAt.In(time.FixedZone("other", 3600)) }},
		{"partial launch inventory", func(i *AcceptedIdentity) { delete(i.LaunchMaterialSHA256, "operator-ssh-key.pub") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := identity.Clone()
			test.edit(&changed)
			if changed.Validate() == nil {
				t.Fatal("accepted invalid identity")
			}
		})
	}
}

func TestAcceptedIdentityCheckpointProjectionAndProof(t *testing.T) {
	identity := acceptedIdentityFixture(t)
	checkpoint, key, roots := acceptedCheckpoint(t, identity, []byte("opaque predecessor"))
	checkpoint.ManagedMaterial = new(bootstrap.ManagedMaterialDomain{Namespace: "namespace", Bucket: "managed-bucket",
		KMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.key", MemberCompartmentOCID: "ocid1.compartment.oc1..member",
		MemberSubnetOCID: "ocid1.subnet.oc1.sa-saopaulo-1.member", MemberSubnetCIDR: "10.251.1.0/24",
		RecipientSignerPublicKey: base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), NativeVerifierSHA256: digest([]byte("native"))})
	for j := range checkpoint.Slots {
		for _, name := range []string{"terrabase-member-ca.pem", "terrabase-member-ca.key"} {
			checkpoint.Slots[j].MaterialReferences = append(checkpoint.Slots[j].MaterialReferences,
				bootstrap.SecretReference{Purpose: bootstrap.SecretHostIssuer, SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.member",
					VersionNumber: 9, TargetFile: name, SHA256: digest([]byte(name)), MaxBytes: 4096})
		}
	}
	verified := verifyAcceptedCheckpoint(t, checkpoint, key, roots, identity.AcceptedAt)
	accepted, err := AcceptedIdentityFromCheckpoint(verified, identity.Slot, identity.AcceptedAt)
	if err != nil {
		t.Fatal(err)
	}
	binding := checkpoint.Slots[0]
	if accepted.Origin != identityrekey.AcceptanceOriginRekey || accepted.localBinding() != identity.localBinding() || len(accepted.ControllerBindings) != 3 ||
		!reflect.DeepEqual(accepted.ConfigSHA256, binding.ConfigSHA256) || !reflect.DeepEqual(accepted.MaterialReferences, binding.MaterialReferences) ||
		!reflect.DeepEqual(accepted.LaunchMaterialSHA256, binding.LaunchMaterialSHA256) ||
		accepted.ManagedMaterial == nil || *accepted.ManagedMaterial != *checkpoint.ManagedMaterial ||
		accepted.MaterialGenerationSHA256 != checkpoint.MaterialGenerationSHA256 {
		t.Fatal("projection lost exact signed pins")
	}
	want, err := checkpoint.AcceptanceSHA256(identity.Slot)
	if err != nil {
		t.Fatal(err)
	}
	got, err := accepted.AcceptanceSHA256()
	if err != nil || got != want {
		t.Fatalf("acceptance digest = %s, %v; checkpoint %s", got, err, want)
	}
	downgraded := accepted.Clone()
	downgraded.Origin = identityrekey.AcceptanceOriginInitial
	if got, err := downgraded.AcceptanceSHA256(); err != nil || got == want {
		t.Fatal("rekey evidence requirement missing from signed acceptance digest")
	}
	accepted.ConfigSHA256["controller.json"] = digest([]byte("changed config"))
	accepted.LaunchMaterialSHA256["operator-ssh-key.pub"] = digest([]byte("changed launch material"))
	accepted.MaterialReferences[0].SHA256 = digest([]byte("changed material"))
	accepted.ManagedMaterial.Bucket = "different-bucket"
	if verified.Checkpoint().Slots[0].ConfigSHA256["controller.json"] != binding.ConfigSHA256["controller.json"] ||
		verified.Checkpoint().Slots[0].LaunchMaterialSHA256["operator-ssh-key.pub"] != binding.LaunchMaterialSHA256["operator-ssh-key.pub"] ||
		verified.Checkpoint().Slots[0].MaterialReferences[0] != binding.MaterialReferences[0] ||
		verified.Checkpoint().ManagedMaterial.Bucket != checkpoint.ManagedMaterial.Bucket {
		t.Fatal("projection mutated opaque verified checkpoint")
	}
	got, err = accepted.AcceptanceSHA256()
	if err != nil || got != want {
		t.Fatal("config/material changed acyclic identity")
	}
	accepted.SeedSlot = "controller-c"
	got, err = accepted.AcceptanceSHA256()
	if err != nil || got == want {
		t.Fatal("seed designation missing from acceptance")
	}
	for _, slot := range []string{"controller-b", "controller-d", ""} {
		if _, err := AcceptedIdentityFromCheckpoint(verified, slot, identity.AcceptedAt); err == nil {
			t.Fatalf("projected checkpoint verified for A into %q", slot)
		}
	}
	if _, err := AcceptedIdentityFromCheckpoint(identityrekey.VerifiedIdentityCheckpoint{}, identity.Slot, identity.AcceptedAt); err == nil {
		t.Fatal("zero proof accepted")
	}
	if _, err := AcceptedIdentityFromCheckpoint(verified, identity.Slot, verified.ExpiresAt()); err == nil {
		t.Fatal("expired proof accepted")
	}
	if _, err := AcceptedIdentityFromCheckpoint(verified, identity.Slot, identity.AcceptedAt.Add(-2*time.Minute)); err == nil {
		t.Fatal("proof accepted before its issue time")
	}
}

func TestAcceptedIdentityConcurrentReplacementChecksExactPredecessor(t *testing.T) {
	identity := acceptedIdentityFixture(t)
	store := testMarkerStore(t)
	old := []byte("opaque predecessor")
	if err := os.WriteFile(filepath.Join(store.directory, markerName), old, 0o644); err != nil {
		t.Fatal(err)
	}
	checkpoint, key, roots := acceptedCheckpoint(t, identity, old)
	verified := verifyAcceptedCheckpoint(t, checkpoint, key, roots, identity.AcceptedAt)
	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			results <- store.ReplaceIdentity(verified, identity.Slot, identity.AcceptedAt, acceptedObservation)
		}()
	}
	close(start)
	successes, refused := 0, 0
	for range 2 {
		err := <-results
		if err == nil {
			successes++
		} else if errors.Is(err, ErrAcceptancePredecessor) {
			refused++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || refused != 1 {
		t.Fatalf("concurrent results: %d published, %d refused", successes, refused)
	}
	if _, err := store.ReadIdentity(); err != nil {
		t.Fatal(err)
	}
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

func TestAcceptedIdentityReaderRequiresOwnedDirectCanonicalFile(t *testing.T) {
	for _, kind := range []string{"mode", "hardlink", "symlink", "owner"} {
		t.Run(kind, func(t *testing.T) {
			identity := acceptedIdentityFixture(t)
			store := testMarkerStore(t)
			if err := store.WriteNewIdentity(identity, acceptedObservation); err != nil {
				t.Fatal(err)
			}
			if _, err := store.ReadIdentity(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(store.directory, markerName)
			var err error
			switch kind {
			case "mode":
				err = os.Chmod(path, 0o664)
			case "hardlink":
				err = os.Link(path, path+".link")
			case "symlink":
				err = os.Rename(path, path+".original")
				if err == nil {
					err = os.Symlink(path+".original", path)
				}
			case "owner":
				store.ownerUID++
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.ReadIdentity(); err == nil {
				t.Fatal("unsafe valid identity file accepted")
			}
		})
	}
}

func TestAcceptedIdentityPublicationRejectsIndirectOrWritableFiles(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "writable", "special mode", "FIFO", "directory", "owner", "parent symlink", "lock symlink", "lock hardlink", "lock writable"} {
		t.Run(kind, func(t *testing.T) {
			identity := acceptedIdentityFixture(t)
			store := testMarkerStore(t)
			old := []byte("predecessor bytes")
			path := filepath.Join(store.directory, markerName)
			if err := os.WriteFile(path, old, 0o644); err != nil {
				t.Fatal(err)
			}
			checkpoint, key, roots := acceptedCheckpoint(t, identity, old)
			verified := verifyAcceptedCheckpoint(t, checkpoint, key, roots, identity.AcceptedAt)
			var err error
			switch kind {
			case "symlink":
				err = os.Rename(path, path+".original")
				if err == nil {
					err = os.Symlink(path+".original", path)
				}
			case "hardlink":
				err = os.Link(path, path+".link")
			case "writable":
				err = os.Chmod(path, 0o666)
			case "special mode":
				err = unix.Chmod(path, 0o4644)
			case "FIFO":
				err = os.Remove(path)
				if err == nil {
					err = unix.Mkfifo(path, 0o644)
				}
			case "directory":
				err = os.Remove(path)
				if err == nil {
					err = os.Mkdir(path, 0o644)
				}
			case "owner":
				store.ownerUID++
			case "parent symlink":
				err = os.Symlink(store.directory, store.directory+".link")
				store.directory += ".link"
			case "lock symlink":
				err = os.Symlink(path, filepath.Join(store.directory, ".accepted-identity.lock"))
			case "lock hardlink":
				err = os.Link(path, filepath.Join(store.directory, ".accepted-identity.lock"))
			case "lock writable":
				err = os.WriteFile(filepath.Join(store.directory, ".accepted-identity.lock"), nil, 0o666)
				if err == nil {
					err = os.Chmod(filepath.Join(store.directory, ".accepted-identity.lock"), 0o666)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := store.ReplaceIdentity(verified, identity.Slot, identity.AcceptedAt, acceptedObservation); err == nil {
				t.Fatal("unsafe replacement accepted")
			}
			if _, err := store.ReadIdentity(); err == nil {
				t.Fatal("unsafe/opaque predecessor decoded")
			}
		})
	}
}

func TestAcceptedIdentityRequiresObservedExistingStore(t *testing.T) {
	for _, kind := range []string{"missing store", "missing pin", "symlink pin", "hardlink pin", "writable pin", "changed pin", "no observer", "foreign broker", "foreign raft"} {
		t.Run(kind, func(t *testing.T) {
			identity := acceptedIdentityFixture(t)
			store := testMarkerStore(t)
			observe := IdentityObservation(acceptedObservation)
			path := filepath.Join(identity.Store.Directory, "server-name")
			var err error
			switch kind {
			case "missing store":
				identity.Store.Directory = filepath.Join(t.TempDir(), "absent")
				identity.ControllerBindings[0].Store = identity.Store
			case "missing pin":
				err = os.Remove(path)
			case "symlink pin":
				err = os.Rename(path, path+".original")
				if err == nil {
					err = os.Symlink(path+".original", path)
				}
			case "hardlink pin":
				err = os.Link(path, path+".link")
			case "writable pin":
				err = os.Chmod(path, 0o644)
			case "changed pin":
				err = os.WriteFile(path, []byte("other-name\n"), 0o600)
			case "no observer":
				observe = nil
			case "foreign broker":
				observe = func(i AcceptedIdentity) (identityrekey.BrokerIdentity, identityrekey.StoreIdentity, error) {
					i.Broker.HostSigner = acceptedPublicKey(t, false)
					return i.Broker, i.Store, nil
				}
			case "foreign raft":
				observe = func(i AcceptedIdentity) (identityrekey.BrokerIdentity, identityrekey.StoreIdentity, error) {
					i.Store.RaftNodeID = "OTHER000"
					return i.Broker, i.Store, nil
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := store.WriteNewIdentity(identity, observe); err == nil {
				t.Fatal("unobserved installation published")
			}
			if _, err := os.Lstat(filepath.Join(store.directory, markerName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed observation created acceptance")
			}
			if kind == "missing store" {
				if _, err := os.Lstat(identity.Store.Directory); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("absent store initialized")
				}
			}
		})
	}
}

func TestAcceptedIdentityInitialUsesCurrentFreshProofs(t *testing.T) {
	fixture := newAdmissionFlowFixture(t)
	base := acceptedIdentityFixture(t)
	state := fixture.ledger.state
	manifestWire, err := trust.DecodeEnvelope(state.ManifestRecord.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := bootstrap.ManifestPayload(manifestWire.Payload)
	if err != nil {
		t.Fatal(err)
	}
	payload.ControllerSlots = []string{"controller-a", "controller-b", "controller-c"}
	profile := payload.Profiles[0]
	payload.Profiles = nil
	for _, slot := range payload.ControllerSlots {
		copy := profile
		copy.Slot = slot
		payload.Profiles = append(payload.Profiles, copy)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	delegationWire := signTestDelegation(t, fixture.rootPrivate, public, []string{"terrascale.bootstrap.peer-receipt"},
		[]string{"controller-a", "controller-c"}, fixture.now.Add(-time.Minute), fixture.now.Add(time.Hour))
	delegation, err := trust.DecodeEnvelope(delegationWire)
	if err != nil {
		t.Fatal(err)
	}
	payload.PeerReceiptDelegation = &delegation
	payload.Secrets = acceptedReferences(payload.Slot)
	for name, purpose := range map[string]bootstrap.SecretPurpose{"founder-peer.key": bootstrap.SecretSeedFounder, "founder-ledger.key": bootstrap.SecretSeedLedgerSigner} {
		payload.Secrets = append(payload.Secrets, bootstrap.SecretReference{Purpose: purpose, Slot: payload.SeedSlot,
			TargetFile: name, SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.seed", VersionNumber: 1,
			SHA256: digest([]byte(name)), MaxBytes: bootstrap.MaxSecretBytes})
	}
	signed, err := bootstrap.SignManifest(payload, fixture.now.Add(-time.Minute), fixture.now.Add(time.Hour), fixture.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := bootstrap.VerifyManifest(signed, fixture.gate.Roots, bootstrap.ManifestExpectation{
		DeploymentID: payload.DeploymentID, Environment: payload.Environment, ClusterID: payload.ClusterID, Cell: payload.Cell,
		Slot: payload.Slot, ImageOCID: payload.ImageOCID, StorageDomain: payload.StorageDomain, ControllerSlots: payload.ControllerSlots,
		IntentGeneration: payload.IntentGeneration, IntentSHA256: payload.IntentSHA256}, *fixture.now, bootstrap.ManifestTrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	anchorEnvelope, err := trust.DecodeEnvelope(fixture.gate.AnchorWire)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := bootstrap.VerifyBootstrapAnchor(anchorEnvelope, fixture.gate.Roots, fixture.gate.Expected, *fixture.now, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	observed, err := fixture.gate.observe(t.Context(), state.Result.InstanceOCID, state, anchor.Anchor())
	if err != nil {
		t.Fatal(err)
	}
	receiptEnvelope, err := bootstrap.SignSeedReceipt(manifest, observed.Facts, fixture.now.Add(-time.Minute), fixture.now.Add(time.Hour), fixture.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := bootstrap.VerifySeedReceipt(receiptEnvelope, manifest, fixture.gate.Roots, observed.Facts, *fixture.now, bootstrap.ManifestTrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	image, err := release.VerifyImageCurrent(payload.ReleaseImageReceiptWire, payload.ReleaseDelegationWire, fixture.gate.Roots,
		release.ImageExpectation{Environment: payload.Environment, LogicalRegion: string(payload.Cell), OCIImageOCID: payload.ImageOCID, Architecture: "amd64"}, *fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	imageReceipt := image.Receipt()
	inputs := InitialAcceptedIdentityInputs{OperationID: entityid.Derive("fresh-operation"), Manifest: manifest, Receipt: receipt, Image: image,
		Observed: observed, Binary: RunningBinary{SHA256: imageReceipt.BinarySHA256, Bytes: imageReceipt.BinaryBytes, Architecture: imageReceipt.Architecture},
		Broker: base.Broker, Store: base.Store, LaunchMaterialSHA256: acceptedLaunchPinFixture(), AcceptedAt: *fixture.now,
		VerifyCurrent: func(at time.Time) error {
			if at != *fixture.now {
				t.Fatal("wrong recheck instant")
			}
			return nil
		}}
	accepted, err := AcceptedIdentityFromInitial(inputs)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.Origin != identityrekey.AcceptanceOriginInitial || len(accepted.ControllerBindings) != 1 || accepted.ControllerBindings[0].Slot != payload.Slot || len(accepted.ControllerSlots) != 3 ||
		accepted.SeedSlot != "controller-b" || accepted.MaterialGenerationSHA256 != "" || !reflect.DeepEqual(accepted.MaterialReferences, payload.Secrets) {
		t.Fatal("initial acceptance invented peer facts or lost current inputs")
	}
	for _, edit := range []func(*InitialAcceptedIdentityInputs){
		func(i *InitialAcceptedIdentityInputs) { i.Manifest = bootstrap.VerifiedManifest{} },
		func(i *InitialAcceptedIdentityInputs) { i.Receipt = bootstrap.VerifiedReceipt{} },
		func(i *InitialAcceptedIdentityInputs) { i.Image = release.VerifiedImage{} },
		func(i *InitialAcceptedIdentityInputs) { i.Observed.InstanceOCID += "foreign" },
		func(i *InitialAcceptedIdentityInputs) { i.Binary.SHA256 = digest([]byte("wrong")) },
		func(i *InitialAcceptedIdentityInputs) { i.VerifyCurrent = nil },
		func(i *InitialAcceptedIdentityInputs) {
			i.VerifyCurrent = func(time.Time) error { return ErrAdmission }
		},
	} {
		changed := inputs
		edit(&changed)
		if _, err := AcceptedIdentityFromInitial(changed); err == nil {
			t.Fatal("unverified/foreign initial inputs accepted")
		}
	}
}
