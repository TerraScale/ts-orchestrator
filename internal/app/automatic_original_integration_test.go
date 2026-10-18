package app

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

func TestOriginalStartupRendersAllSlotsThroughGeneratedLinkAndConfigStore(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	accepted, files, _ := identityRekeyConfigFixture(t)
	sourceDirectory := filepath.Join(t.TempDir(), "source")
	input := bootstrapmaterial.Config{
		Environment: accepted.Environment, Cell: "gru", Region: "sa-saopaulo-1",
		DeploymentID: accepted.DeploymentID, ClusterID: accepted.ClusterID,
		SubnetCIDR: "10.251.0.0/24", ValidityHours: 48,
		Slots: []bootstrapmaterial.Slot{
			{Name: "controller-a", PrivateIP: "10.251.0.11"},
			{Name: "controller-b", PrivateIP: "10.251.0.12"},
			{Name: "controller-c", PrivateIP: "10.251.0.13"},
		},
	}
	if _, err := bootstrapmaterial.Generate(sourceDirectory, input, now.Add(-2*time.Second)); err != nil {
		t.Fatal(err)
	}
	record, err := bootstrapmaterial.Load(sourceDirectory)
	if err != nil {
		t.Fatal(err)
	}
	linkDirectory := filepath.Join(t.TempDir(), "link")
	waitForLinkHomeClaimSecond(t, sourceDirectory)
	linkRecord, err := bootstrapmaterial.GenerateLink(sourceDirectory, sourceDirectory, linkDirectory, linkDirectory, now)
	if err != nil {
		t.Fatal(err)
	}
	manifest := bootstrap.Manifest{DeploymentID: input.DeploymentID, ClusterID: input.ClusterID,
		Environment: input.Environment, Cell: oci.RegionGRU, OCIRegion: input.Region,
		SeedSlot: "controller-a", ControllerSlots: slices.Clone(accepted.ControllerSlots), IntentGeneration: 7}
	for _, name := range bootstrap.ControllerConfigFileNames {
		wire := files[name]
		manifest.ControllerFiles = append(manifest.ControllerFiles, bootstrap.ControllerConfigFile{Name: name, Bytes: wire, SHA256: controllerSHA256(wire)})
	}
	manifest.IntentSHA256 = controllerSHA256(files["oci-region-intent.json"])
	var regional, linked []bootstrap.SecretReference
	for _, file := range record.Files {
		if file.Purpose != "owner-only" {
			regional = append(regional, bootstrap.SecretReference{Purpose: file.Purpose, Slot: file.Slot, TargetFile: file.Name, SHA256: file.SHA256, MaxBytes: file.MaxBytes})
		}
	}
	for _, file := range linkRecord.Files {
		if file.Purpose == "owner-only" {
			continue
		}
		name := file.Name
		if name == "link-cell.jwt" {
			name = "cell.jwt"
		}
		linked = append(linked, bootstrap.SecretReference{Purpose: file.Purpose, Slot: file.Slot, TargetFile: name, SHA256: file.SHA256, MaxBytes: file.MaxBytes})
	}
	prior := slices.Clone(regional)
	manifest.Secrets, err = originalStartupLinkReferences(oci.RegionGRU, regional, linked)
	if err != nil || !slices.Equal(regional, prior) {
		t.Fatalf("original Link changed its selected regional inventory: %v", err)
	}
	signerWire, err := protocol.EncodeJSON([]TrustedSignerConfig{{Actor: "operator", PublicKey: record.Public.ControllerResponsePublicKey,
		Roles: []string{"terrabase"}, Environments: []string{input.Environment}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, slot := range accepted.ControllerSlots {
		t.Run(slot, func(t *testing.T) {
			candidate := manifest
			candidate.Slot = slot
			rendered, err := automaticControllerConfigWithLink(candidate, record, linkRecord, signerWire, now)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "controller.json")
			if err := os.WriteFile(path, rendered.ControllerConfig, 0o600); err != nil {
				t.Fatal(err)
			}
			loaded, err := LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := loaded.signedWire()
			if err != nil || !bytes.Equal(wire, rendered.ControllerConfig) || loaded.NATS.Instance != slot || loaded.NATS.Embedded.Link == nil {
				t.Fatalf("original slot configuration lost exact bytes or Link through the config store: %v", err)
			}
			cert, _ := bootstrap.InterRegionTLSFiles(slot)
			candidate.Secrets = slices.DeleteFunc(slices.Clone(candidate.Secrets), func(reference bootstrap.SecretReference) bool { return reference.TargetFile == cert })
			if _, err := automaticControllerConfigWithLink(candidate, record, linkRecord, signerWire, now); err == nil {
				t.Fatal("original startup rendered a slot without its Link certificate")
			}
		})
	}
	if _, err := originalStartupLinkReferences(oci.RegionSFO, regional, linked); err == nil {
		t.Fatal("spoke replaced the regional cell JWT")
	}
	conflicting := append(slices.Clone(linked), regional[0])
	if _, err := originalStartupLinkReferences(oci.RegionGRU, regional, conflicting); err == nil {
		t.Fatal("original Link replaced an unrelated regional credential")
	}
}
