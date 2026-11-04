package fixturegen

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"

	"encoding/hex"

	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func packetFixture(t *testing.T) (string, Manifest, ed25519.PrivateKey, trust.Keyring) {
	t.Helper()
	root := t.TempDir()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := trust.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	manifest := Manifest{SchemaVersion: ManifestVersion, DeploymentID: "0000000000F9PR1WNVDTEXS31Z", Cell: "GRU",
		Environment: "production", FixtureNow: time.Now().UTC().Truncate(time.Second),
		Binary: BinaryInput{Path: "input/orchestrator", GuestPath: "/usr/local/bin/terrascale-orchestrator", Architecture: "amd64"}}
	for _, name := range RequiredSourcePaths() {
		manifest.SourcePins = append(manifest.SourcePins, SourcePin{Path: name, SHA256: strings.Repeat("a", 64)})
	}
	add := func(name string, body []byte) {
		t.Helper()
		owner, mode := expectedOwnership(name, map[string]string{
			"controller-a": "a", "controller-b": "b", "controller-c": "0000000000SF1REEJJX6TC691V",
		})
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, filepath.FromSlash(name))), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), body, os.FileMode(mode)); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(body)
		manifest.Files = append(manifest.Files, FileEntry{Path: name, SHA256: hex.EncodeToString(digest[:]),
			Size: int64(len(body)), Mode: mode, OwnerRole: owner})
	}
	add("input/orchestrator", []byte("ELF fixture bytes"))
	manifest.Binary.SHA256 = manifest.Files[0].SHA256
	manifest.Binary.Size = manifest.Files[0].Size
	var directoryPlan []GuestDirectory
	for _, slot := range []string{"controller-a", "controller-b", "controller-c"} {
		imdsRoot := "simulator/imds/" + slot + "/"
		for _, name := range []string{"tenancy.txt", "leaf.pem", "leaf.key", "intermediate.pem"} {
			add(imdsRoot+name, []byte(name))
		}
		manifest.Controllers = append(manifest.Controllers, Controller{Slot: slot,
			InstanceOCID: "ocid1.instance.oc1.sa-saopaulo-1." + slot,
			GuestRoot:    "controllers/" + slot + "/guest-root"})
		guest := "controllers/" + slot + "/guest-root/"
		add(guest+"etc/terrascale-orchestrator/bootstrap/identity.json", []byte(slot))
		add(guest+"etc/terrascale-orchestrator/bootstrap/anchor.json", []byte("anchor"))
		add(guest+"etc/terrascale-orchestrator/bootstrap/trust-roots/001.pem", []byte("public root"))
		add(guest+"etc/terrascale-orchestrator/controller.json", []byte("controller config"))
		add(guest+"usr/local/share/ca-certificates/ts-fixture-oci.crt", []byte("public CA"))
		add(guest+"etc/systemd/network/20-terrascale-production.network", []byte("network"))
		add(guest+"etc/systemd/timesyncd.conf.d/99-terrascale-orchestrator.conf", []byte("NTP"))
		add(guest+"etc/hosts", []byte("hosts"))
		add(guest+"etc/cloud/cloud-init.disabled", []byte{})
		add(guest+"etc/ssh/sshd_config.d/99-terrascale-production.conf", []byte("ssh"))
		add(guest+"var/lib/terrascale-orchestrator-bootstrap/accepted-install.json", []byte("marker"))
		add(guest+"var/lib/terrascale-orchestrator-secrets/controller.creds", []byte("credential"))
		add(guest+"var/lib/terrascale-orchestrator-secrets/operator.jwt", []byte("operator JWT"))
		state := "var/lib/terrascale-orchestrator-controller/"
		add(guest+state+"founder-selection-floor.json", []byte("floor"))
		add(guest+state+".founder-selection-floor.lock", []byte{})
		for _, guestPath := range []string{"/var/lib/terrascale-orchestrator-controller", serviceSecretsGuestDir} {
			directoryPlan = append(directoryPlan, GuestDirectory{ControllerSlot: slot,
				GuestPath: guestPath, Mode: 0o700, OwnerRole: "service:" + slot, UID: 1000, GID: 1000})
		}
	}
	directoryWire, err := protocol.EncodeJSON(directoryPlan)
	if err != nil {
		t.Fatal(err)
	}
	add(guestDirectoryPlanPath, directoryWire)
	add("simulator/tls/oci.crt", []byte("simulator certificate"))
	add("simulator/tls/oci.key", []byte("simulator private key"))
	add("simulator/responses/instance.json", []byte(`{"id":"fixture"}`))
	add("signing/root.key", []byte("offline private key placeholder"))
	slices.SortFunc(manifest.Files, func(a, b FileEntry) int { return strings.Compare(a.Path, b.Path) })
	manifest.Routes = []Route{{ControllerSlot: "controller-c", InstanceOCID: "ocid1.instance.oc1.sa-saopaulo-1.controller-c",
		Host: "iaas.sa-saopaulo-1.oraclecloud.com", RequestURI: "/20160918/instances/ocid1.instance.oc1.sa-saopaulo-1.controller-c",
		Status: 200, BodyPath: "simulator/responses/instance.json", ETag: "etag", LastModified: manifest.FixtureNow}}
	writeManifest(t, root, manifest, private)
	return root, manifest, private, trust.Keyring{keyID: public}
}

func writeManifest(t *testing.T, root string, manifest Manifest, key ed25519.PrivateKey) {
	t.Helper()
	wire, err := trust.EncodePayload(manifest)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.Sign(wire, manifest.scope(), manifest.FixtureNow.Add(-time.Minute),
		manifest.FixtureNow.Add(time.Hour), key)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), wire, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "manifest.sig"), signed, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestPacketRejectsChangedExecutable(t *testing.T) {
	root, _, _, roots := packetFixture(t)
	if err := os.WriteFile(filepath.Join(root, "input", "orchestrator"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidatePacket(root, roots, time.Now().UTC()); err == nil {
		t.Fatal("changed executable accepted")
	}
}
