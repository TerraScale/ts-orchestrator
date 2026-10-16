package fixturegen

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
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
			"controller-a": "a", "controller-b": "b", "seed-a": "0000000000SF1REEJJX6TC691V",
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
	for _, slot := range []string{"controller-a", "controller-b", "seed-a"} {
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
	manifest.Routes = []Route{{ControllerSlot: "seed-a", InstanceOCID: "ocid1.instance.oc1.sa-saopaulo-1.seed-a",
		Host: "iaas.sa-saopaulo-1.oraclecloud.com", RequestURI: "/20160918/instances/ocid1.instance.oc1.sa-saopaulo-1.seed-a",
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

func TestPacketValidationAndControllerCopyBoundary(t *testing.T) {
	root, _, _, roots := packetFixture(t)
	packet, err := ValidatePacket(root, roots, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	for _, slot := range []string{"controller-a", "controller-b", "seed-a"} {
		files, err := packet.GuestFiles(slot)
		if err != nil || len(files) < 5 {
			t.Fatalf("guest files for %s: %d, %v", slot, len(files), err)
		}
		for _, file := range files {
			if !strings.HasPrefix(file.SourcePath, filepath.Join(root, "controllers", slot, "guest-root")+string(os.PathSeparator)) ||
				!strings.HasPrefix(file.GuestPath, "/") || strings.Contains(file.SourcePath, "signing/") ||
				strings.Contains(file.SourcePath, "simulator/") {
				t.Fatalf("cross-controller or host-only guest file: %+v", file)
			}
		}
	}
	if _, err := packet.GuestFiles("missing"); err == nil {
		t.Fatal("unknown guest accepted")
	}
	executable, err := packet.Executable()
	if err != nil || executable.GuestPath != "/usr/local/bin/terrascale-orchestrator" || executable.Mode != 0o755 ||
		string(executable.Body) != "ELF fixture bytes" {
		t.Fatalf("binary install contract mismatch: %+v, %v", executable, err)
	}
	if reads, missing, err := packet.SimulatorRoutes("controller-a"); err != nil || len(reads) != 0 || len(missing) != 0 {
		t.Fatalf("cross-instance simulator routes leaked: reads=%d missing=%d error=%v", len(reads), len(missing), err)
	}
	reads, missing, err := packet.SimulatorRoutes("seed-a")
	if err != nil || len(reads) != 1 || len(missing) != 0 || !strings.Contains(string(reads[0].Body), `"fixture"`) {
		t.Fatalf("seed simulator route mismatch: reads=%+v missing=%+v error=%v", reads, missing, err)
	}
	if err := os.WriteFile(filepath.Join(root, "simulator", "responses", "instance.json"), []byte(`{"id":"changed"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := packet.SimulatorRoutes("seed-a"); err == nil {
		t.Fatal("changed simulator response accepted after packet validation")
	}
	if err := os.WriteFile(filepath.Join(root, "input", "orchestrator"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := packet.Executable(); err == nil {
		t.Fatal("changed executable accepted after packet validation")
	}
}

func TestVerifiedPacketManifestCannotMutateAuthorizedViews(t *testing.T) {
	root, _, _, roots := packetFixture(t)
	packet, err := ValidatePacket(root, roots, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	manifest := packet.Manifest()
	manifest.Controllers[2].Slot = "controller-a"
	manifest.Files[0].Path = "signing/root.key"
	manifest.Files[0].OwnerRole = "root:controller-a"
	manifest.Files[0].Mode = 0o777
	manifest.Routes[0].ControllerSlot = "controller-a"
	manifest.Routes[0].Host = "untrusted.example"
	manifest.Routes[0].BodyPath = "signing/root.key"
	manifest.SourcePins[0].SHA256 = strings.Repeat("0", 64)
	again := packet.Manifest()
	if again.Controllers[2].Slot != "seed-a" || again.Files[0].Path == "signing/root.key" ||
		again.Files[0].Mode == 0o777 || again.Routes[0].Host != "iaas.sa-saopaulo-1.oraclecloud.com" ||
		again.Routes[0].ControllerSlot != "seed-a" || again.SourcePins[0].SHA256 == strings.Repeat("0", 64) {
		t.Fatal("verified packet manifest exposed mutable authorization state")
	}
	files, err := packet.GuestFiles("controller-a")
	if err != nil || len(files) == 0 || files[0].File.OwnerRole != "root:controller-a" {
		t.Fatalf("manifest mutation changed guest copy list: %+v, %v", files, err)
	}
	reads, _, err := packet.SimulatorRoutes("seed-a")
	if err != nil || len(reads) != 1 || reads[0].Host != "iaas.sa-saopaulo-1.oraclecloud.com" {
		t.Fatalf("manifest mutation changed simulator inventory: %+v, %v", reads, err)
	}
}

func TestPacketRejectsUnlistedTamperSymlinkAndWrongRoot(t *testing.T) {
	t.Run("unlisted guest file", func(t *testing.T) {
		root, _, _, roots := packetFixture(t)
		name := filepath.Join(root, "controllers", "seed-a", "guest-root", "etc", "terrascale-orchestrator", "bootstrap", "extra")
		if err := os.WriteFile(name, []byte("unlisted"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := ValidatePacket(root, roots, time.Now().UTC()); err == nil {
			t.Fatal("unlisted guest file accepted")
		}
	})
	t.Run("listed body changed", func(t *testing.T) {
		root, _, _, roots := packetFixture(t)
		if err := os.WriteFile(filepath.Join(root, "input", "orchestrator"), []byte("changed"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ValidatePacket(root, roots, time.Now().UTC()); err == nil {
			t.Fatal("changed executable accepted")
		}
	})
	t.Run("symlink", func(t *testing.T) {
		root, _, _, roots := packetFixture(t)
		if err := os.Symlink("orchestrator", filepath.Join(root, "input", "alias")); err != nil {
			t.Fatal(err)
		}
		if _, err := ValidatePacket(root, roots, time.Now().UTC()); err == nil {
			t.Fatal("symlink accepted")
		}
	})
	t.Run("wrong trusted root", func(t *testing.T) {
		root, _, _, _ := packetFixture(t)
		if _, err := ValidatePacket(root, trust.Keyring{}, time.Now().UTC()); err == nil {
			t.Fatal("untrusted manifest accepted")
		}
	})
}

func TestPacketRequiresTrustedCurrentRunClock(t *testing.T) {
	root, manifest, _, roots := packetFixture(t)
	if _, err := ValidatePacket(root, roots, time.Time{}); err == nil {
		t.Fatal("packet accepted missing trusted clock")
	}
	if _, err := ValidatePacket(root, roots, manifest.FixtureNow.Add(-6*time.Minute)); err == nil {
		t.Fatal("future-dated packet accepted before fixture clock")
	}
	if _, err := ValidatePacket(root, roots, manifest.FixtureNow.Add(6*time.Minute)); err == nil {
		t.Fatal("stale fixture clock accepted")
	}
	if _, err := ValidatePacket(root, roots, manifest.FixtureNow.Add(2*time.Hour)); err == nil {
		t.Fatal("expired signature accepted at run time")
	}
}

func TestPacketRejectsEmptyOrOversizedSimulatorInventory(t *testing.T) {
	_, manifest, _, _ := packetFixture(t)
	index := slices.IndexFunc(manifest.Files, func(file FileEntry) bool {
		return file.Path == "simulator/responses/instance.json"
	})
	if index < 0 {
		t.Fatal("fixture lacks simulator response")
	}
	empty := manifest
	empty.Files = slices.Clone(manifest.Files)
	empty.Files[index].Size = 0
	if err := empty.Validate(); err == nil {
		t.Fatal("empty 200 response accepted")
	}
	large := manifest
	large.Files = slices.Clone(manifest.Files)
	large.Files[index].Size = 4 << 20
	large.Routes = nil
	for index := range 9 {
		large.Routes = append(large.Routes, Route{ControllerSlot: "seed-a",
			InstanceOCID: manifest.Controllers[2].InstanceOCID, Host: "objectstorage.sa-saopaulo-1.oraclecloud.com",
			RequestURI: fmt.Sprintf("/n/namespace-a/b/ledger-bucket/o/item-%02d", index), Status: 200,
			BodyPath: "simulator/responses/instance.json", ETag: "etag", LastModified: manifest.FixtureNow})
	}
	if err := large.Validate(); err == nil || !strings.Contains(err.Error(), "response bytes exceed") {
		t.Fatalf("oversized per-controller route inventory = %v", err)
	}
}

func TestPacketBoundsSignedSourceInventory(t *testing.T) {
	root, manifest, key, roots := packetFixture(t)
	for index := len(manifest.SourcePins); index < maxSourcePins; index++ {
		manifest.SourcePins = append(manifest.SourcePins, SourcePin{
			Path: fmt.Sprintf("internal/app/source-%03d.go", index), SHA256: strings.Repeat("a", 64),
		})
	}
	slices.SortFunc(manifest.SourcePins, func(a, b SourcePin) int { return strings.Compare(a.Path, b.Path) })
	writeManifest(t, root, manifest, key)
	if _, err := ValidatePacket(root, roots, manifest.FixtureNow); err != nil {
		t.Fatalf("signed packet at source inventory limit rejected: %v", err)
	}
	manifest.SourcePins = append(manifest.SourcePins, SourcePin{Path: "internal/app/source-overflow.go", SHA256: strings.Repeat("a", 64)})
	slices.SortFunc(manifest.SourcePins, func(a, b SourcePin) int { return strings.Compare(a.Path, b.Path) })
	writeManifest(t, root, manifest, key)
	if _, err := ValidatePacket(root, roots, manifest.FixtureNow); err == nil || !strings.Contains(err.Error(), "inventory bound") {
		t.Fatalf("oversized signed source inventory: %v", err)
	}
}

func TestPacketRejectsPathIdentityAndSignatureConfusion(t *testing.T) {
	root, manifest, key, roots := packetFixture(t)
	mutations := []struct {
		name   string
		change func(*Manifest)
	}{
		{"traversal", func(m *Manifest) { m.Files[0].Path = "controllers/seed-a/guest-root/../signing/root.key" }},
		{"duplicate", func(m *Manifest) { m.Files = append(m.Files, m.Files[0]) }},
		{"guest signing", func(m *Manifest) {
			m.Files[0].Path = "controllers/seed-a/guest-root/signing/root.key"
		}},
		{"route identity", func(m *Manifest) { m.Routes[0].InstanceOCID += "-other" }},
		{"overlapping guest root", func(m *Manifest) {
			m.Controllers = slices.Clone(m.Controllers)
			m.Controllers[0].Slot = "controller-a/guest-root/peer"
			m.Controllers[0].GuestRoot = "controllers/controller-a/guest-root/peer/guest-root"
		}},
		{"duplicate instance identity", func(m *Manifest) {
			m.Controllers = slices.Clone(m.Controllers)
			m.Controllers[1].InstanceOCID = m.Controllers[0].InstanceOCID
		}},
		{"compute request identity", func(m *Manifest) {
			m.Routes[0].RequestURI = "/20160918/instances/ocid1.instance.oc1.sa-saopaulo-1.other"
		}},
		{"binary hash", func(m *Manifest) { m.Binary.SHA256 = strings.Repeat("0", 64) }},
		{"binary guest path", func(m *Manifest) { m.Binary.GuestPath = "/tmp/orchestrator" }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			changed := manifest
			changed.Files = slices.Clone(manifest.Files)
			changed.Routes = slices.Clone(manifest.Routes)
			mutation.change(&changed)
			writeManifest(t, root, changed, key)
			if _, err := ValidatePacket(root, roots, time.Now().UTC()); err == nil {
				t.Fatal("invalid signed packet accepted")
			}
		})
	}
	writeManifest(t, root, manifest, key)
	wire, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	wire = append(wire, ' ')
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), wire, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidatePacket(root, roots, time.Now().UTC()); err == nil {
		t.Fatal("noncanonical signed manifest accepted")
	}
}

func TestEmitPacketDerivesExactBinaryAndSignsOnce(t *testing.T) {
	source, manifest, key, roots := packetFixture(t)
	material := make(map[string][]byte, len(manifest.Files))
	for _, file := range manifest.Files {
		body, err := os.ReadFile(filepath.Join(source, filepath.FromSlash(file.Path)))
		if err != nil {
			t.Fatal(err)
		}
		material[file.Path] = body
	}
	manifest.Files = nil
	manifest.Binary.SHA256 = ""
	manifest.Binary.Size = 0
	sourceRoot, pins := sourceFixture(t)
	manifest.SourcePins = pins
	destination := filepath.Join(t.TempDir(), "packet")
	packet, err := EmitPacket(destination, sourceRoot, manifest, material, key, roots, manifest.FixtureNow.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if packet.Manifest().Binary.SHA256 == "" || packet.Manifest().Binary.Size != int64(len(material["input/orchestrator"])) {
		t.Fatal("emitter did not derive binary identity")
	}
	if _, err := EmitPacket(destination, sourceRoot, manifest, material, key, roots, manifest.FixtureNow.Add(time.Hour)); err == nil {
		t.Fatal("emitter overwrote existing packet")
	}
}

func TestEmitPacketNeverInstallsOfflineRootKey(t *testing.T) {
	source, manifest, key, roots := packetFixture(t)
	material := make(map[string][]byte, len(manifest.Files))
	for _, file := range manifest.Files {
		body, err := os.ReadFile(filepath.Join(source, filepath.FromSlash(file.Path)))
		if err != nil {
			t.Fatal(err)
		}
		material[file.Path] = body
	}
	sourceRoot, pins := sourceFixture(t)
	manifest.SourcePins = pins
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	for _, bad := range []struct {
		name string
		path string
		body []byte
	}{
		{"guest key PEM", "controllers/seed-a/guest-root/var/lib/terrascale-orchestrator-secrets/root.pem", pemKey},
		{"binary embedded seed", "input/orchestrator", append([]byte("ELF"), key.Seed()...)},
	} {
		t.Run(bad.name, func(t *testing.T) {
			changed := make(map[string][]byte, len(material)+1)
			for name, body := range material {
				changed[name] = body
			}
			changed[bad.path] = bad.body
			out := filepath.Join(t.TempDir(), "packet")
			if _, err := EmitPacket(out, sourceRoot, manifest, changed, key, roots, manifest.FixtureNow.Add(time.Hour)); err == nil {
				t.Fatal("root signing secret crossed packet guest boundary")
			}
			if _, err := os.Lstat(out); !os.IsNotExist(err) {
				t.Fatalf("rejected key emitted packet anyway: %v", err)
			}
		})
	}
	_, guestPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	guestDER, err := x509.MarshalPKCS8PrivateKey(guestPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	allowed := make(map[string][]byte, len(material))
	for name, body := range material {
		allowed[name] = body
	}
	allowed["controllers/seed-a/guest-root/var/lib/terrascale-orchestrator-secrets/controller.creds"] =
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: guestDER})
	if _, err := EmitPacket(filepath.Join(t.TempDir(), "packet"), sourceRoot, manifest, allowed,
		key, roots, manifest.FixtureNow.Add(time.Hour)); err != nil {
		t.Fatalf("unrelated guest private credential was rejected: %v", err)
	}
}
