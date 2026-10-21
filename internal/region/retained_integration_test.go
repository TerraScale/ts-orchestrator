package region

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/objectstorage"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
)

func (f *currentDiscoveryScenario) export(t *testing.T) RetainedFoundation {
	t.Helper()
	_, snapshot, err := resolveCurrentFoundation(t.Context(), f.client, f.grant.TenancyID, f.genesis, nil)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func (f *currentDiscoveryScenario) snapshot() RetainedFoundation {
	f.mu.Lock()
	defer f.mu.Unlock()
	return RetainedFoundation{TenancyID: f.grant.TenancyID, Namespace: "ns", RootChainWire: bytes.Clone(f.objects[foundationRootChainObject]),
		AnchorWire: bytes.Clone(f.objects[foundationDiscoveryObject]), GrantWire: bytes.Clone(f.objects["bootstrap/"+foundationGrantObject])}
}

func TestRetainedFoundationHTTPFilesystemOffline(t *testing.T) {
	f := newCurrentDiscoveryScenario(t)
	config := bootstrapmaterial.Config{Environment: "production", Region: foundationHomeRegion, Cell: "gru", DeploymentID: f.anchor.DeploymentID, ClusterID: f.anchor.ClusterID,
		SubnetCIDR: "10.251.0.0/24", ValidityHours: 24, Slots: []bootstrapmaterial.Slot{{Name: "controller-a", PrivateIP: "10.251.0.11"}, {Name: "controller-b", PrivateIP: "10.251.0.12"}, {Name: "controller-c", PrivateIP: "10.251.0.13"}}}
	configWire, err := json.Marshal(config, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(configWire)
	f.anchor.InitialSourceRegistration.PlanSHA256 = hex.EncodeToString(digest[:])
	registration := f.anchor.InitialSourceRegistration.Clone()
	startup, _ := foundationImageRecipe(t, f.root, f.genesis, f.now, config)
	for i, name := range bootstrap.ControllerConfigFileNames {
		wire := []byte(`{"schemaVersion":1}`)
		if i == 0 {
			wire = f.anchor.InitialRegionIntentWire
		}
		sum := sha256.Sum256(wire)
		startup.ControllerFiles = append(startup.ControllerFiles, bootstrap.ControllerConfigFile{Name: name, Bytes: wire, SHA256: hex.EncodeToString(sum[:])})
	}
	target := bootstrapmaterial.VaultTarget{CompartmentOCID: "ocid1.compartment.oc1..control", VaultOCID: "ocid1.vault.oc1.sa-saopaulo-1.test", KMSKeyOCID: f.anchor.StorageDomain.HeadKMSKeyOCID}
	f.grant.Regions[0].BootstrapMaterial = &BootstrapMaterialIntent{InstallationID: f.grant.InstallationID, PlanSHA256: registration.PlanSHA256, Config: config, SourceVaultTarget: target, SourceRegistration: &registration, Startup: &startup}
	f.grant.Regions[0].Plan["resource_ids"] = map[string]any{"control_compartment": target.CompartmentOCID, "vault": target.VaultOCID, "key": target.KMSKeyOCID, "subnet": startup.Profiles[0].SubnetOCID, "network_security_group": startup.Profiles[0].NetworkSecurityGroupOCIDs[0]}
	f.publish()
	snapshot := f.export(t)
	original := f.snapshot()
	if !bytes.Equal(snapshot.RootChainWire, original.RootChainWire) || !bytes.Equal(snapshot.AnchorWire, original.AnchorWire) || !bytes.Equal(snapshot.GrantWire, original.GrantWire) {
		t.Fatal("export changed signed object bytes")
	}
	path := filepath.Join(t.TempDir(), "foundation-discovery.json")
	wire, err := json.Marshal(snapshot, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, wire, 0600); err != nil {
		t.Fatal(err)
	}
	wire, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var restored RetainedFoundation
	if err := json.Unmarshal(wire, &restored, json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	// No source SDK endpoint remains reachable after transport to the candidate.
	f.client.(*objectstorage.ObjectStorageClient).Host = "http://127.0.0.1:1"
	resolver, err := verifyRetainedFoundation(t.Context(), restored, f.genesis)
	if err != nil {
		t.Fatal(err)
	}
	if resolver.Store != nil {
		t.Fatal("offline scope acquired a cloud foundation store")
	}
	footprint, err := resolver.Footprint.AuthorizedRegions(t.Context())
	if err != nil || footprint.TenancyID != snapshot.TenancyID {
		t.Fatalf("offline scope: %+v %v", footprint, err)
	}
	material, err := resolver.BootstrapMaterial(t.Context(), "GRU")
	if err != nil || !material.IsVerified() || material.Generation() != 1 || material.Config().DeploymentID != config.DeploymentID {
		t.Fatalf("offline bootstrap material: %+v %v", material, err)
	}
	if _, err := material.Startup(); err != nil {
		t.Fatal(err)
	}
	if _, err := material.Image(); err != nil {
		t.Fatal(err)
	}
	if _, err := material.SourceRegistration(); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.BootstrapMaterial(t.Context(), "FRA"); err == nil {
		t.Fatal("retained scope authorized absent region")
	}
	restored.GrantWire[0] ^= 1
	if _, err := resolver.Footprint.AuthorizedRegions(t.Context()); err != nil {
		t.Fatalf("caller modified retained reader authority: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := resolver.Footprint.AuthorizedRegions(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("offline read ignored cancellation: %v", err)
	}
	if _, err := VerifyRetainedFoundation(t.Context(), snapshot); err == nil {
		t.Fatal("downloaded fixture signer replaced embedded production genesis")
	}
}

func TestRetainedFoundationHTTPRejectsInvalidAndRollback(t *testing.T) {
	for _, name := range []string{"tampered grant", "wrong tenancy", "wrong namespace", "unknown root", "expired", "missing grant", "retired chain", "lower generation"} {
		t.Run(name, func(t *testing.T) {
			f := newCurrentDiscoveryScenario(t)
			snapshot := f.export(t)
			switch name {
			case "tampered grant":
				snapshot.GrantWire[len(snapshot.GrantWire)-1] ^= 1
			case "wrong tenancy":
				snapshot.TenancyID = "ocid1.tenancy.oc1..foreign"
			case "wrong namespace":
				snapshot.Namespace = "foreign"
			case "unknown root":
				_, key, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				f.root = key
				f.publish()
				snapshot = f.snapshot()
			case "expired":
				f.now = f.now.Add(-2 * time.Hour)
				f.publish()
				snapshot = f.snapshot()
			case "missing grant":
				snapshot.GrantWire = nil
			case "retired chain":
				f.rotate()
				f.grant.Generation = 2
				f.grant.Regions[0].Generation = 2
				f.publish()
				f.export(t)
			case "lower generation":
				f.grant.Generation = 2
				f.grant.Regions[0].Generation = 2
				f.publish()
				f.export(t)
			}
			before, err := os.ReadFile(f.floorPath())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := verifyRetainedFoundation(t.Context(), snapshot, f.genesis); err == nil {
				t.Fatal("offline verifier accepted invalid or stale retained authority")
			}
			after, err := os.ReadFile(f.floorPath())
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("rejected snapshot changed adopted floor: %v", err)
			}
		})
	}
}
