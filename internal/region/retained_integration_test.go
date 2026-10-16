package region

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/objectstorage"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
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
	for _, schema := range []int{1, 2} {
		t.Run(fmt.Sprintf("schema%d", schema), func(t *testing.T) {
			f := newCurrentDiscoveryScenario(t)
			f.grant.SchemaVersion = schema
			config := bootstrapmaterial.Config{Environment: "production", Region: foundationHomeRegion, Cell: "gru", DeploymentID: f.anchor.DeploymentID, ClusterID: f.anchor.ClusterID,
				SubnetCIDR: "10.251.0.0/24", ValidityHours: 24, Slots: []bootstrapmaterial.Slot{{Name: "controller-a", PrivateIP: "10.251.0.11"}, {Name: "controller-b", PrivateIP: "10.251.0.12"}, {Name: "controller-c", PrivateIP: "10.251.0.13"}}}
			configWire, err := json.Marshal(config, json.Deterministic(true))
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(configWire)
			f.anchor.InitialSourceRegistration.PlanSHA256 = hex.EncodeToString(digest[:])
			registration := f.anchor.InitialSourceRegistration.Clone()
			startup, _ := retainedQualifiedImageRecipe(t, f, config)
			for i, name := range bootstrap.ControllerConfigFileNames {
				wire := []byte(`{"schemaVersion":1}`)
				if i == 0 {
					wire = f.anchor.InitialRegionIntentWire
				}
				sum := sha256.Sum256(wire)
				startup.ControllerFiles = append(startup.ControllerFiles, bootstrap.ControllerConfigFile{Name: name, Bytes: wire, SHA256: hex.EncodeToString(sum[:])})
			}
			if schema == 2 {
				ref, err := FoundationResourceReference("GRU", "control_compartment")
				if err != nil {
					t.Fatal(err)
				}
				for i := range startup.Profiles {
					startup.Profiles[i].CompartmentOCID = ref
				}
				configWire, err := json.Marshal(oci.RegionConfig{Region: oci.RegionGRU, CompartmentID: ref, ImageCompartmentID: ref,
					SubnetID: startup.Profiles[0].SubnetOCID, NetworkSecurityGroupIDs: startup.Profiles[0].NetworkSecurityGroupOCIDs}, json.Deterministic(true))
				if err != nil {
					t.Fatal(err)
				}
				digest := sha256.Sum256(configWire)
				startup.ControllerFiles[1].Bytes = configWire
				startup.ControllerFiles[1].SHA256 = hex.EncodeToString(digest[:])
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
			material, err := resolver.BootstrapIntent(t.Context(), "GRU")
			if err != nil || !material.IsVerified() || material.Generation() != 1 || material.Config().DeploymentID != config.DeploymentID {
				t.Fatalf("offline bootstrap material: %+v %v", material, err)
			}
			logical, err := material.Startup()
			if err != nil {
				t.Fatal(err)
			}
			if schema == 2 && logical.Profiles[0].CompartmentOCID != startup.Profiles[0].CompartmentOCID {
				t.Fatal("offline intent projected logical resources")
			}
			if !bytes.Equal(material.FoundationGrantWire(), original.GrantWire) {
				t.Fatal("intent changed original signed grant")
			}
			logical.Profiles[0].CompartmentOCID = "changed"
			again, err := material.Startup()
			if err != nil || again.Profiles[0].CompartmentOCID != startup.Profiles[0].CompartmentOCID {
				t.Fatal("intent getter leaked mutable signed recipe")
			}
			production, productionErr := resolver.BootstrapMaterial(t.Context(), "GRU")
			if schema == 2 {
				if productionErr == nil || production.IsVerified() {
					t.Fatal("offline logical intent acquired production material authority")
				}
			} else {
				if productionErr != nil {
					t.Fatal(productionErr)
				}
				if _, err := production.SourceRegistration(); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := material.Image(); err != nil {
				t.Fatal(err)
			}
			if _, err := resolver.BootstrapIntent(t.Context(), "FRA"); err == nil {
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
			if schema == 2 {
				foreign, err := FoundationResourceReference("FRA", "control_compartment")
				if err != nil {
					t.Fatal(err)
				}
				f.grant.Regions[0].BootstrapMaterial.Startup.Profiles[0].CompartmentOCID = foreign
			} else {
				logical, err := FoundationResourceReference("GRU", "control_compartment")
				if err != nil {
					t.Fatal(err)
				}
				f.grant.Regions[0].BootstrapMaterial.Startup.Profiles[0].CompartmentOCID = logical
			}
			f.publish()
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			invalid, err := verifyRetainedFoundation(t.Context(), f.snapshot(), f.genesis)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := invalid.BootstrapIntent(t.Context(), "GRU"); err == nil {
				t.Fatal("offline intent admitted a foreign role or schema-1 logical reference")
			}
		})
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

func retainedQualifiedImageRecipe(t *testing.T, f *currentDiscoveryScenario, config bootstrapmaterial.Config) (bootstrap.StartupTemplate, release.ImageReceipt) {
	t.Helper()
	root, roots, now := f.root, f.genesis, f.now
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := trust.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := trust.EncodeDelegatedPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("a", 64)
	receipt := release.ImageReceipt{Schema: release.ImageSchema, SourceRevision: strings.Repeat("a", 40), GoVersion: release.DefaultGoVersion, Architecture: "amd64", BinaryBytes: 13, BinarySHA256: digest, QualificationSHA256: digest, BaseImageOCID: "ocid1.image.oc1.sa-saopaulo-1.base", BaseImageRegion: "GRU", BaseImageSHA256: digest, KernelRelease: "6.1.0", KernelSHA256: digest, ImageFormat: "qcow2", ImageBytes: 1024, ImageSHA256: digest, OCIImageOCID: "ocid1.image.oc1.sa-saopaulo-1.custom", OCIRegion: "GRU"}
	qualification := release.ProductionQualification{Schema: release.ProductionQualificationSchema,
		Candidate: release.ProductionExpectation{SourceRevision: receipt.SourceRevision, ArtifactSHA256: receipt.ImageSHA256,
			QualificationSHA256: receipt.QualificationSHA256, Cell: receipt.OCIRegion, Environment: "production",
			Runtime: release.ProductionRuntime, Architecture: receipt.Architecture, Role: "orchestrator"}}
	for _, gate := range []string{"runtime-ha", "workload-safety"} {
		evidence := []byte("test-only independent " + gate + " image qualification")
		evidenceSHA := sha256.Sum256(evidence)
		qualification.Evidence = append(qualification.Evidence, release.ProductionGateEvidence{Gate: gate,
			SHA256: hex.EncodeToString(evidenceSHA[:]), Bytes: int64(len(evidence)), CompletedAt: now.Add(-2 * time.Minute)})
	}
	payload, err := trust.EncodePayload(qualification)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := trust.Sign(payload, release.ProductionQualificationScope(qualification.Candidate), now.Add(-time.Minute), now.Add(time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	proofWire, err := trust.EncodeEnvelope(proof)
	if err != nil {
		t.Fatal(err)
	}
	receipt.Production = &release.ProductionProof{Qualification: proofWire}
	scope := release.ImageScope(receipt, "production")
	delegation, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: encoded, Capabilities: []trust.Capability{{Domain: scope.Domain, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: scope.Environment, Role: scope.Role, Slots: []string{scope.Slot}, Actions: []string{"sign"}}}}, now.Add(-time.Minute), now.Add(time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	image, err := release.SignImageReceipt(receipt, "production", delegation, roots, private, now, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	imageWire, err := trust.EncodeEnvelope(image)
	if err != nil {
		t.Fatal(err)
	}
	delegationWire, err := trust.EncodeEnvelope(delegation)
	if err != nil {
		t.Fatal(err)
	}
	signers, err := json.Marshal([]map[string]any{{"actor": "ops", "public_key": base64.StdEncoding.EncodeToString(public), "roles": []string{"terrabase"}, "environments": []string{"production"}}})
	if err != nil {
		t.Fatal(err)
	}
	template := bootstrap.StartupTemplate{SeedSlot: config.Slots[0].Name, ImageOCID: receipt.OCIImageOCID, ImageArchitecture: "linux-amd64", ReleaseImageReceiptWire: imageWire, ReleaseDelegationWire: delegationWire, TrustedSigners: signers, ControllerConfigDerivation: bootstrap.ControllerConfigDerivationV1}
	for _, slot := range config.Slots {
		template.Profiles = append(template.Profiles, bootstrap.LaunchProfile{Slot: slot.Name, CompartmentOCID: "ocid1.compartment.oc1..control", AvailabilityDomain: "test:SA-SAOPAULO-1-AD-1", FaultDomain: "FAULT-DOMAIN-1", SubnetOCID: "ocid1.subnet.oc1.sa-saopaulo-1.test", NetworkSecurityGroupOCIDs: []string{"ocid1.networksecuritygroup.oc1.sa-saopaulo-1.test"}, Shape: "VM.Standard.E5.Flex"})
	}
	return template, receipt
}
