package fixturegen

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

func TestGuestMaterialRejectsMalformedOrIncompleteTrustRoot(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	recipe := syntheticSignedHistoryRecipe(t, now, []byte("synthetic orchestrator executable"))
	input := GuestMaterialInputs{Binary: []byte("synthetic orchestrator executable"),
		Credentials: map[string]map[string][]byte{"controller-a": {}, "controller-b": {}, "seed-a": {}},
		VNICs:       map[string]GuestObservation{"controller-a": {}, "controller-b": {}, "seed-a": {}},
		ServiceUID:  1000, ServiceGID: 1000}
	shortKey := recipe
	shortKey.RootPrivateKey = ed25519.PrivateKey{1}
	if _, err := BuildVerifiedGuestMaterial(t.Context(), shortKey, CompletedHistories{}, input); err == nil {
		t.Fatal("short offline root key reached guest material staging")
	}
	extraPublic, _ := historyTestKey(t)
	extraID, err := trust.KeyID(extraPublic)
	if err != nil {
		t.Fatal(err)
	}
	multipleRoots := recipe
	multipleRoots.Roots = make(trust.Keyring, len(recipe.Roots)+1)
	for id, key := range recipe.Roots {
		multipleRoots.Roots[id] = bytes.Clone(key)
	}
	multipleRoots.Roots[extraID] = extraPublic
	if _, err := BuildVerifiedGuestMaterial(t.Context(), multipleRoots, CompletedHistories{}, input); err == nil {
		t.Fatal("one PEM was staged for a two-root verification keyring")
	}
}

func TestCompletedPacketEmitsSignedThreeSlotCaptureAndVerifiedFloors(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	binary := []byte("synthetic orchestrator executable")
	inputs := productionGuestTestInputs(t, now, binary)
	recipe := syntheticSignedHistoryRecipeWithMaterials(t, now, binary, inputs.Credentials)
	capture, err := NewCapturingObjectStorage(now)
	if err != nil {
		t.Fatal(err)
	}
	sourceRoot, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	pins, err := CurrentCompletedSourcePins(sourceRoot)
	if err != nil {
		t.Fatal(err)
	}
	anchor := recipe.Anchor.Anchor()
	manifest := Manifest{SchemaVersion: ManifestVersion, DeploymentID: anchor.DeploymentID,
		Cell: string(anchor.Cell), Environment: anchor.Environment, FixtureNow: now,
		Binary: BinaryInput{Path: "input/orchestrator", GuestPath: "/usr/local/bin/terrascale-orchestrator",
			Architecture: "amd64"}, SourcePins: pins}
	for _, slot := range anchor.ControllerSlots {
		manifest.Controllers = append(manifest.Controllers, Controller{Slot: slot,
			InstanceOCID: recipe.Observed[slot].InstanceOCID,
			GuestRoot:    "controllers/" + slot + "/guest-root"})
	}
	compute, err := BuildComputeInventory(recipe, inputs)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Routes = compute.Routes
	destination := filepath.Join(t.TempDir(), "completed-packet")
	packet, completed, err := EmitCompletedRestartPacket(t.Context(), destination, sourceRoot,
		manifest, func(ctx context.Context, completed CompletedHistories) (map[string][]byte, error) {
			material, err := BuildVerifiedGuestMaterial(ctx, recipe, completed, inputs)
			if err != nil {
				return nil, err
			}
			for name, body := range compute.Bodies {
				material[name] = bytes.Clone(body)
			}
			return material, nil
		}, recipe.Anchor, capture, recipe.Prepare, recipe.RootPrivateKey, recipe.Roots, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("emit complete synthetic restart packet: %v", err)
	}
	if completed.Seed.Result == nil || len(completed.Peers) != 2 || capture.PutCount() == 0 {
		t.Fatal("completed packet did not capture three positive histories")
	}
	executable, err := packet.Executable()
	if err != nil || executable.GuestPath != "/usr/local/bin/terrascale-orchestrator" ||
		executable.Mode != 0o755 || !bytes.Equal(executable.Body, binary) {
		t.Fatalf("signed packet executable differs: %+v, %v", executable, err)
	}
	for _, slot := range anchor.ControllerSlots {
		directories, err := packet.GuestDirectories(slot)
		if err != nil || len(directories) != 2 || directories[0].GuestPath !=
			"/var/lib/terrascale-orchestrator-controller" || directories[0].Mode != 0o700 ||
			directories[0].OwnerRole != "service:"+slot || directories[0].UID != 1000 ||
			directories[0].GID != 1000 || directories[1].GuestPath != serviceSecretsGuestDir ||
			directories[1].Mode != 0o700 || directories[1].OwnerRole != "service:"+slot ||
			directories[1].UID != 1000 || directories[1].GID != 1000 {
			t.Fatalf("controller %q lacks signed service directory install: %+v, %v", slot, directories, err)
		}
		files, err := packet.GuestFiles(slot)
		if err != nil {
			t.Fatal(err)
		}
		var floor, lock bool
		for _, file := range files {
			switch file.GuestPath {
			case "/var/lib/terrascale-orchestrator-controller/founder-selection-floor.json":
				floor = len(file.Body) > 0 && file.File.Mode == 0o600 && file.File.OwnerRole == "service:"+slot
			case "/var/lib/terrascale-orchestrator-controller/.founder-selection-floor.lock":
				lock = len(file.Body) == 0 && file.File.Mode == 0o600 && file.File.OwnerRole == "service:"+slot
			}
		}
		if !floor || !lock {
			t.Fatalf("controller %q has no verified service-owned floor and lock", slot)
		}
		reads, _, err := packet.SimulatorRoutes(slot)
		if err != nil || len(reads) < 3 {
			t.Fatalf("controller %q lacks captured ledger routes: %d, %v", slot, len(reads), err)
		}
		for _, read := range reads {
			if strings.Contains(read.RequestURI, "founder-selection") {
				t.Fatal("restart simulator exposed the host-only current selector")
			}
		}
		assertPacketComputeSDK(t, packet, slot, recipe.Observed[slot], inputs.VNICs[slot])
	}
	if _, err := VerifyPacketEmbeddedImage(packet, recipe.Roots,
		completed.Seed.Manifest.ImageOCID, now); err != nil {
		t.Fatalf("emitted packet image receipt does not bind synthetic executable: %v", err)
	}
}
