//go:build fixturetest

package materialsource

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func sourceImageRecipe(t *testing.T, root ed25519.PrivateKey, roots trust.Keyring, now time.Time, config bootstrapmaterial.Config, ids map[string]any, initialIntent []byte) (bootstrap.StartupTemplate, release.ImageReceipt) {
	t.Helper()
	return sourceImageRecipeForDerivation(t, root, roots, now, config, ids, initialIntent, bootstrap.ControllerConfigDerivationV1)
}

func sourceImageRecipeForDerivation(t *testing.T, root ed25519.PrivateKey, roots trust.Keyring, now time.Time, config bootstrapmaterial.Config, ids map[string]any, initialIntent []byte, derivation string) (bootstrap.StartupTemplate, release.ImageReceipt) {
	t.Helper()
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
	binary, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("a", 64)
	receipt := release.ImageReceipt{Schema: release.ImageSchema, SourceRevision: strings.Repeat("a", 40), GoVersion: release.DefaultGoVersion, Architecture: runtime.GOARCH, BinaryBytes: int64(len(binary)), BinarySHA256: digestWire(binary), QualificationSHA256: digest, BaseImageOCID: "ocid1.image.oc1." + config.Region + ".base", BaseImageRegion: strings.ToUpper(config.Cell), BaseImageSHA256: digest, KernelRelease: "6.1.0", KernelSHA256: digest, ImageFormat: "qcow2", ImageBytes: 1024, ImageSHA256: digest, OCIImageOCID: "ocid1.image.oc1." + config.Region + ".custom", OCIRegion: strings.ToUpper(config.Cell)}
	qualification := release.ProductionQualification{Schema: release.ProductionQualificationSchema,
		Candidate: release.ProductionExpectation{SourceRevision: receipt.SourceRevision, ArtifactSHA256: receipt.ImageSHA256,
			QualificationSHA256: receipt.QualificationSHA256, Cell: receipt.OCIRegion, Environment: "production",
			Runtime: release.ProductionRuntime, Architecture: receipt.Architecture, Role: "orchestrator"}}
	evidenceDirectory := t.TempDir()
	for _, gate := range []string{"runtime-ha", "workload-safety"} {
		body := []byte("test-only source fixture image evidence: " + gate)
		path := filepath.Join(evidenceDirectory, digestWire(body))
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		retained, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(retained, body) {
			t.Fatal("retained source image evidence changed", err)
		}
		qualification.Evidence = append(qualification.Evidence, release.ProductionGateEvidence{Gate: gate,
			SHA256: digestWire(retained), Bytes: int64(len(retained)), CompletedAt: now.Add(-time.Second)})
	}
	payload, err := trust.EncodePayload(qualification)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := trust.Sign(payload, release.ProductionQualificationScope(qualification.Candidate), now, now.Add(time.Hour), root)
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
	template := bootstrap.StartupTemplate{SeedSlot: config.Slots[0].Name, ImageOCID: receipt.OCIImageOCID, ImageArchitecture: "linux-" + runtime.GOARCH, ReleaseImageReceiptWire: imageWire, ReleaseDelegationWire: delegationWire, TrustedSigners: signers, ControllerConfigDerivation: derivation}
	template.FounderResources = &bootstrap.StartupFounderResources{LaunchDeadline: now.Add(15 * time.Minute)}
	for index, slot := range config.Slots {
		template.FounderResources.Slots = append(template.FounderResources.Slots, bootstrap.StartupSlotResources{Slot: slot.Name, ImageCompartmentOCID: ids["control_compartment"].(string), WholeOCPUs: 1, MemoryInGB: 8, BootVolumeGB: 50, BootVolumeTier: bootstrap.FounderBootVolumeTierBalanced})
		template.Profiles = append(template.Profiles, bootstrap.LaunchProfile{Slot: slot.Name, CompartmentOCID: ids["control_compartment"].(string), AvailabilityDomain: "test:" + strings.ToUpper(config.Region) + "-AD-1", FaultDomain: fmt.Sprintf("FAULT-DOMAIN-%d", index+1), SubnetOCID: ids["subnet"].(string), NetworkSecurityGroupOCIDs: []string{ids["network_security_group"].(string)}, Shape: "VM.Standard.E5.Flex"})
	}
	for index, name := range bootstrap.ControllerConfigFileNames {
		body := []byte(`{}`)
		if index == 0 {
			body = bytes.Clone(initialIntent)
		}
		if name == "oci-region.json" {
			intent, err := oci.ParseRegionIntent(initialIntent)
			if err != nil {
				t.Fatal(err)
			}
			body, err = json.Marshal(oci.RegionConfig{Region: oci.Region(strings.ToUpper(config.Cell)), Generation: intent.Generation, Endpoint: "https://iaas." + config.Region + ".oraclecloud.com", CompartmentID: ids["control_compartment"].(string), ImageCompartmentID: ids["control_compartment"].(string), AvailabilityDomain: template.Profiles[0].AvailabilityDomain, FaultDomains: []string{"FAULT-DOMAIN-1", "FAULT-DOMAIN-2", "FAULT-DOMAIN-3"}, SubnetID: ids["subnet"].(string), NetworkSecurityGroupIDs: []string{ids["network_security_group"].(string)}, ImageID: receipt.OCIImageOCID, Shape: template.Profiles[0].Shape, BootVolumeGB: 50, BootVolumeVPUsPerGB: 10, DataVolumeVPUsPerGB: 10, MaxDataVolumeGB: 32768, Owner: "ts-orchestrator"})
			if err != nil {
				t.Fatal(err)
			}
		}
		template.ControllerFiles = append(template.ControllerFiles, bootstrap.ControllerConfigFile{Name: name, Bytes: body, SHA256: digestWire(body)})
	}
	if err := template.Validate(); err != nil {
		t.Fatal(err)
	}
	return template, receipt
}

func sourcePinnedLedger(t *testing.T, root ed25519.PrivateKey, record bootstrapmaterial.Record, now time.Time) []byte {
	t.Helper()
	public, err := base64.StdEncoding.Strict().DecodeString(record.Public.LedgerSignerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := trust.KeyID(ed25519.PublicKey(public))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := trust.EncodeDelegatedPublicKey(ed25519.PublicKey(public))
	if err != nil {
		t.Fatal(err)
	}
	var slots []string
	for _, slot := range record.Config.Slots {
		slots = append(slots, slot.Name)
	}
	var capabilities []trust.Capability
	for _, domain := range bootstrap.BootstrapLedgerCapabilityDomains() {
		capabilities = append(capabilities, trust.Capability{Domain: domain, DeploymentID: record.Config.DeploymentID, Cell: strings.ToUpper(record.Config.Cell), Environment: record.Config.Environment, Role: "controller", Slots: slots, Actions: []string{"sign"}})
	}
	delegation, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: encoded, Capabilities: capabilities}, now.Add(-time.Minute), now.Add(time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(delegation)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
