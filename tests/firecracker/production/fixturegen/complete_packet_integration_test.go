package fixturegen

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/naming"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func TestGuestMaterialRejectsMalformedOrIncompleteTrustRoot(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	recipe := syntheticSignedHistoryRecipe(t, now, []byte("synthetic orchestrator executable"))
	input := GuestMaterialInputs{Binary: []byte("synthetic orchestrator executable"),
		Credentials: map[string]map[string][]byte{"controller-a": {}, "controller-b": {}, "controller-c": {}},
		VNICs:       map[string]GuestObservation{"controller-a": {}, "controller-b": {}, "controller-c": {}},
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

func TestCompletedControllerCSeedPacketEmitsSignedCaptureAndVerifiedFloors(t *testing.T) {
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
	seed := completed.Seed
	if seed.Intent.Slot != "controller-c" || seed.Intent.Mode != bootstrap.IntentModeExternalSeed ||
		seed.Intent.RetryToken != "" || seed.Manifest == nil || seed.Manifest.SeedSlot != "controller-c" ||
		seed.ManifestRecord == nil || seed.ResultRecord == nil || seed.SeedReceiptRecord == nil ||
		seed.PeerReceiptRecord != nil || seed.Result.Slot != "controller-c" ||
		seed.Result.Mode != bootstrap.IntentModeExternalSeed ||
		seed.Result.InstanceOCID != "ocid1.instance.oc1.sa-saopaulo-1.controller-c" ||
		seed.Result.SeedReceiptDigest != seed.SeedReceiptRecord.SHA256 ||
		seed.Head.ResultDigest != seed.ResultRecord.SHA256 {
		t.Fatal("public ledger replay did not verify controller-c as the external seed")
	}
	plan, err := bootstrap.VerifyFounderPlan(recipe.FounderPlanWire, recipe.Roots, recipe.Anchor.Wire(),
		recipe.ManifestWires, now, trust.Policy{MaxLifetime: 24 * time.Hour, ClockSkew: bootstrap.ManifestClockSkew})
	if err != nil || plan.Plan().SeedSlot != "controller-c" ||
		plan.Plan().SeedPrivateIP != "10.44.0.10" || plan.Plan().SeedManifestSHA256 != seed.ManifestRecord.SHA256 {
		t.Fatal("verified founder plan differs from completed controller-c seed", err)
	}
	name, err := naming.RegionCell("GRU").ControllerSlot("controller-c")
	if err != nil || name != "gru-1-ctl-3" || naming.NATSServer("gru", "controller-c") != name {
		t.Fatal("external seed has no matching production controller and broker name", err)
	}
	legacy := packet.Manifest()
	legacy.Controllers[2] = Controller{Slot: "seed-a", InstanceOCID: "ocid1.instance.oc1.sa-saopaulo-1.seed-a",
		GuestRoot: "controllers/seed-a/guest-root"}
	if err := legacy.Validate(); err == nil || !strings.Contains(err.Error(), "fixed three-slot topology") {
		t.Fatal("legacy seed-a topology was not refused by the fixed packet validator", err)
	}
	t.Log("verified public ledger/plan bind external seed controller-c at .10 to gru-1-ctl-3; legacy seed-a packet topology refused")

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
		state := seed
		receipt := seed.SeedReceiptRecord
		if slot != "controller-c" {
			state = completed.Peers[slot]
			receipt = state.PeerReceiptRecord
			if state.Intent.Slot != slot || state.Intent.Mode != bootstrap.IntentModeManaged ||
				state.Intent.RetryToken == "" || state.Result == nil || state.ResultRecord == nil ||
				state.ManifestRecord == nil || state.CandidateRecord == nil || state.ProgressRecord == nil ||
				receipt == nil || state.SeedReceiptRecord != nil || state.Result.Mode != bootstrap.IntentModeManaged ||
				state.Result.PeerReceiptDigest != receipt.SHA256 {
				t.Fatalf("public ledger replay lost managed peer authority for %s", slot)
			}
		}
		var floor, lock, markerSeen, credentialSeen bool
		var marker bootstrapstart.AcceptedInstall
		for _, file := range files {
			switch file.GuestPath {
			case "/var/lib/terrascale-orchestrator-bootstrap/accepted-install.json":
				if err := protocol.DecodeStrict(file.Body, &marker, 1<<20); err != nil ||
					marker.Slot != slot || marker.SeedSlot != "controller-c" ||
					marker.InstanceOCID != state.Result.InstanceOCID || marker.ReceiptSHA256 != receipt.SHA256 ||
					marker.ManifestSHA256 != state.ManifestRecord.SHA256 ||
					marker.ResultSHA256 != state.ResultRecord.SHA256 || marker.HeadAttempt != state.Head.Attempt ||
					marker.HeadGeneration != state.Head.Generation {
					t.Fatalf("%s extracted marker differs from independently verified ledger state: %v", slot, err)
				}
				markerSeen = true
			case serviceSecretsGuestDir + "/" + slot + ".creds":
				if err := natscell.ValidateBrokerControllerCredentialBytes(file.Body, "gru", slot); err != nil {
					t.Fatalf("%s extracted JWT lost its production broker scope: %v", slot, err)
				}
				if slot == "controller-c" {
					if err := natscell.ValidateBrokerControllerCredentialBytes(file.Body, "gru", "seed-a"); err == nil {
						t.Fatal("controller-c credentials authorize legacy seed-a broker scope")
					}
				}
				credentialSeen = true
			case "/var/lib/terrascale-orchestrator-controller/founder-selection-floor.json":
				floor = len(file.Body) > 0 && file.File.Mode == 0o600 && file.File.OwnerRole == "service:"+slot
			case "/var/lib/terrascale-orchestrator-controller/.founder-selection-floor.lock":
				lock = len(file.Body) == 0 && file.File.Mode == 0o600 && file.File.OwnerRole == "service:"+slot
			}
		}
		if !floor || !lock || !markerSeen || !credentialSeen {
			t.Fatalf("controller %q lacks verified floor, lock, marker or broker credential", slot)
		}
		config, err := packet.SimulatorConfig(slot)
		if err != nil || config.DescriptorSlot != slot || config.InstanceID != marker.InstanceOCID ||
			config.PrimaryPrivateIP != marker.PrimaryPrivateIP ||
			(slot == "controller-c" && config.PrimaryPrivateIP != "10.44.0.10") {
			t.Fatalf("%s simulator identity differs from its extracted marker: %v", slot, err)
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
		t.Logf("%s signed marker, scoped broker JWT and packet simulator match public ledger replay; existing SDK socket witnesses completed", slot)
	}
	if !slices.Equal(packet.Manifest().Controllers, manifest.Controllers) {
		t.Fatal("signed packet changed the coherent controller-a/controller-b/controller-c inventory")
	}
	for _, file := range packet.Manifest().Files {
		if strings.Contains(file.Path, "seed-a") {
			t.Fatalf("new packet retained a legacy seed-a file path: %s", file.Path)
		}
	}
	for _, route := range packet.Manifest().Routes {
		if route.ControllerSlot == "seed-a" || strings.Contains(route.RequestURI, "seed-a") {
			t.Fatal("new packet retained a legacy seed-a route")
		}
	}
	if _, err := VerifyPacketEmbeddedImage(packet, recipe.Roots,
		completed.Seed.Manifest.ImageOCID, now); err != nil {
		t.Fatalf("emitted packet image receipt does not bind synthetic executable: %v", err)
	}
}
