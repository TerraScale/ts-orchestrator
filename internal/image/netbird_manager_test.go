package image

import (
	"encoding/json/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/netbird/foundation"
	"github.com/TerraScale/ts-orchestrator/internal/release"
)

func managerTestInputs(t *testing.T) (string, Inputs) {
	t.Helper()
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	inputs, err := loadManagerInputs(filepath.Join(repo, "deploy/image/image-inputs.json"))
	if err != nil {
		t.Fatal(err)
	}
	return repo, inputs
}

func TestNetBirdManagerRecipeHasOnlyDedicatedBootAndDeferredEnrollment(t *testing.T) {
	repo, inputs := managerTestInputs(t)
	if slices.Contains(managerImageUnits, "netbird.service") || slices.Contains(managerImageUnits, "terrascale-netbird-enroll.service") || slices.Contains(managerImageUnits, "terrascale-orchestrator-controller.service") || slices.Contains(managerImageUnits, "terrascale-orchestrator-host.service") {
		t.Fatal("dedicated recipe starts client enrollment or an ordinary serving role")
	}
	stage := t.TempDir()
	unitPath := filepath.Join(repo, "deploy/netbird/manager/systemd", managerFoundationUnit)
	wire, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(wire), "ExecStart=/usr/local/bin/ts-orch netbird foundation serve\n") || !strings.Contains(string(wire), "Requires=containerd.service\n") {
		t.Fatal("manager unit bypasses its own authenticated foundation dispatcher or runtime")
	}
	if err := os.MkdirAll(filepath.Join(stage, "etc/systemd/system"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "etc/systemd/system", managerFoundationUnit), wire, 0644); err != nil {
		t.Fatal(err)
	}
	links, err := expectedInstallLinks(stage, []string{managerFoundationUnit})
	if err != nil || len(links) != 1 || links["multi-user.target.wants/"+managerFoundationUnit] != "/etc/systemd/system/"+managerFoundationUnit {
		t.Fatalf("manager unit has unexpected boot links: %v, %v", links, err)
	}
	destinations := map[string]upload{}
	for _, artifact := range managerUploads(repo, t.TempDir(), inputs) {
		if _, exists := destinations[artifact.destination]; exists {
			t.Fatalf("manager recipe repeats destination %s", artifact.destination)
		}
		destinations[artifact.destination] = artifact
		if slices.Contains(managerDeliveredPaths, artifact.destination) || strings.Contains(artifact.destination, "netbird-enroll") || strings.Contains(artifact.destination, "orchestrator-controller") || strings.Contains(artifact.destination, "orchestrator-host") {
			t.Fatalf("manager recipe bakes runtime authority or ordinary role artifact %s", artifact.destination)
		}
	}
	for _, name := range []string{"/usr/local/bin/ts-orch", NetBird, NetBirdFallback, NetBirdPin, NetBirdConfig, "/etc/systemd/system/netbird.service", "/etc/systemd/system/" + managerFoundationUnit} {
		if _, exists := destinations[name]; !exists {
			t.Fatalf("manager recipe omits required artifact %s", name)
		}
	}
	if destinations[NetBird].source != destinations[NetBirdFallback].source || destinations[NetBird].mode != 0755 || destinations[NetBirdFallback].mode != 0755 || destinations[NetBirdPin].mode != 0644 {
		t.Fatal("managed client and fallback do not share the exact pinned executable with checked modes")
	}
	if err := managerPublicConfig(destinations[NetBirdConfig].source); err != nil {
		t.Fatal(err)
	}
}

func TestNetBirdManagerPublicConfigRejectsSecretAndForeignRegion(t *testing.T) {
	name := filepath.Join(t.TempDir(), "netbird.json")
	for _, wire := range []string{`{"management_url":"https://netbird.terrascale.tech","region":"sa-saopaulo-1","setup_key_secret_id":"manual"}`, `{"management_url":"https://other.invalid","region":"sa-saopaulo-1"}`, `{"management_url":"https://netbird.terrascale.tech","region":"us-sanjose-1"}`} {
		if err := os.WriteFile(name, []byte(wire), 0644); err != nil {
			t.Fatal(err)
		}
		if err := managerPublicConfig(name); err == nil {
			t.Fatal("manager public image config accepted secret placement or foreign origin/region")
		}
	}
}

func TestNetBirdManagerArtifactRejectsSameSizeSubstitutionAndLinks(t *testing.T) {
	directory := t.TempDir()
	name := filepath.Join(directory, "artifact")
	if err := os.WriteFile(name, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	digest, err := fileHash(name)
	if err != nil {
		t.Fatal(err)
	}
	pin := Asset{8, digest}
	if err := managerArtifact(name, pin); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte("replaced"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := managerArtifact(name, pin); err == nil {
		t.Fatal("same-size replacement accepted as original retained artifact")
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(name, link); err != nil {
		t.Fatal(err)
	}
	if err := managerArtifact(link, pin); err == nil {
		t.Fatal("symlink accepted as retained image artifact")
	}
}

func TestNetBirdManagerSourceSnapshotRejectsChangedQualifiedAsset(t *testing.T) {
	repo, target := t.TempDir(), t.TempDir()
	if _, err := Execute(t.Context(), repo, nil, "git", "init"); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(repo, "asset")
	if err := os.WriteFile(name, []byte("original"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(t.Context(), repo, nil, "git", "add", "asset"); err != nil {
		t.Fatal(err)
	}
	tree, err := Execute(t.Context(), repo, nil, "git", "write-tree")
	if err != nil {
		t.Fatal(err)
	}
	if err := snapshotManagerSource(t.Context(), repo, target, tree, "asset"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte("replaced"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := snapshotManagerSource(t.Context(), repo, target, tree, "asset"); err == nil {
		t.Fatal("deployment asset changed outside qualified source tree")
	}
	if err := snapshotManagerSource(t.Context(), repo, target, tree, "../asset"); err == nil {
		t.Fatal("source snapshot escaped qualified source root")
	}
}

func TestNetBirdManagerManifestBindsActualImageKernelAndRuntime(t *testing.T) {
	repo, inputs := managerTestInputs(t)
	work, artifacts := t.TempDir(), t.TempDir()
	for _, item := range []struct{ root, name, data string }{{work, "ts-orch", "qualified binary"}, {work, "image-builder", "qualified native builder"}, {artifacts, managerImageName, "dedicated qcow2"}, {artifacts, "guest-kernel", "native arm64 kernel"}} {
		if err := os.WriteFile(filepath.Join(item.root, item.name), []byte(item.data), 0644); err != nil {
			t.Fatal(err)
		}
	}
	qualification := release.Qualification{SourceRevision: strings.Repeat("a", 40), SourceTree: strings.Repeat("b", 40), GoVersion: "go1.27.1", Verification: release.QualificationCheck{RunID: 1, RunNumber: 2}}
	expected := []string{"/usr/local/bin/ts-orch=" + strings.Repeat("c", 64)}
	if err := managerManifest(repo, work, artifacts, qualification, strings.Repeat("d", 64), inputs, expected); err != nil {
		t.Fatal(err)
	}
	wire, err := os.ReadFile(filepath.Join(artifacts, "image-qualification.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Schema         string `json:"schema"`
		SourceRevision string `json:"source_revision"`
		Image          struct {
			Name, Architecture, SHA256 string
			Bytes                      int64
		}
		Kernel struct {
			Name, Architecture, SHA256 string
			Bytes                      int64
		}
		Manager struct {
			Role, Runtime, Cell string
			ComponentImages     []string `json:"component_images"`
			Readback            []string
		}
	}
	if err := json.Unmarshal(wire, &manifest, json.MatchCaseInsensitiveNames(true)); err != nil {
		t.Fatal(err)
	}
	images, err := foundation.PinnedComponentImages("arm64")
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Schema != "terrascale.image.qualification.v2" || manifest.SourceRevision != qualification.SourceRevision || manifest.Manager.Role != "netbird-manager" || manifest.Manager.Runtime != release.NetBirdProductionRuntime || manifest.Manager.Cell != "GRU" || !slices.Equal(manifest.Manager.ComponentImages, images) || !slices.Equal(manifest.Manager.Readback, expected) {
		t.Fatal("archive lost exact source, dedicated role, runtime pins or readback identity")
	}
	for _, artifact := range []struct {
		Name, Architecture, SHA256 string
		Bytes                      int64
	}{manifest.Image, manifest.Kernel} {
		if artifact.Architecture != "arm64" {
			t.Fatal("archive substituted another native architecture")
		}
		if err := managerArtifact(filepath.Join(artifacts, artifact.Name), Asset{artifact.Bytes, artifact.SHA256}); err != nil {
			t.Fatal(err)
		}
	}
	sums, err := os.ReadFile(filepath.Join(artifacts, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{managerImageName, "guest-kernel", "image-qualification.json"} {
		digest, err := fileHash(filepath.Join(artifacts, name))
		if err != nil || !strings.Contains(string(sums), digest+"  "+name+"\n") {
			t.Fatalf("archive checksums omitted actual artifact %s: %v", name, err)
		}
	}
}
