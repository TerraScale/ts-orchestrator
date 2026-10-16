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
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

func TestAutomaticControllerConfigLoadsFromGeneratedSource(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	sourceDirectory := filepath.Join(t.TempDir(), "source")
	input := bootstrapmaterial.Config{
		Environment: "canary", Cell: "gru", Region: "sa-saopaulo-1",
		DeploymentID: "0000000000SX9TG05TQEFG0XF3", ClusterID: "0000000000QARJ92HJ6PVP4S4P",
		SubnetCIDR: "10.251.0.0/24", ValidityHours: 48,
		Slots: []bootstrapmaterial.Slot{
			{Name: "controller-a", PrivateIP: "10.251.0.10"},
			{Name: "controller-b", PrivateIP: "10.251.0.11"},
			{Name: "controller-c", PrivateIP: "10.251.0.12"},
		},
	}
	if _, err := bootstrapmaterial.Generate(sourceDirectory, input, now); err != nil {
		t.Fatal(err)
	}
	record, err := bootstrapmaterial.Load(sourceDirectory)
	if err != nil {
		t.Fatal(err)
	}
	linkDirectory := filepath.Join(t.TempDir(), "link")
	linkRecord, err := bootstrapmaterial.GenerateLink(sourceDirectory, sourceDirectory, linkDirectory, linkDirectory, now)
	if err != nil {
		t.Fatal(err)
	}
	manifest := bootstrap.Manifest{DeploymentID: input.DeploymentID, ClusterID: input.ClusterID,
		Environment: input.Environment, Cell: oci.RegionGRU, OCIRegion: input.Region,
		SeedSlot: input.Slots[0].Name, ControllerSlots: []string{"controller-a", "controller-b", "controller-c"},
		IntentGeneration: 1}
	intent := oci.RegionIntent{SchemaVersion: 1, Generation: 1, BootstrapRegion: oci.RegionGRU,
		Regions: []oci.RegionMapping{{Cell: oci.RegionGRU, OCIRegion: input.Region}}}
	region := oci.RegionConfig{Region: oci.RegionGRU, Generation: 1,
		Endpoint:      "https://iaas.sa-saopaulo-1.oraclecloud.com",
		CompartmentID: "ocid1.compartment.oc1..controller", ImageCompartmentID: "ocid1.compartment.oc1..images",
		AvailabilityDomain: "fixture:SA-SAOPAULO-1-AD-1", FaultDomains: []string{"FAULT-DOMAIN-1"},
		SubnetID: "ocid1.subnet.oc1.sa-saopaulo-1.controller", NetworkSecurityGroupIDs: []string{"ocid1.networksecuritygroup.oc1.sa-saopaulo-1.controller"},
		ImageID: "ocid1.image.oc1.sa-saopaulo-1.controller", Shape: "VM.Standard.E4.Flex", Owner: "controller",
		BootVolumeGB: 50, BootVolumeVPUsPerGB: 10, DataVolumeVPUsPerGB: 10, MaxDataVolumeGB: 50}
	for index, value := range []any{intent, region, managedPlacementSettings{Environment: input.Environment, MemberRole: "terrabase"}} {
		wire, err := protocol.EncodeJSON(value)
		if err != nil {
			t.Fatal(err)
		}
		manifest.ControllerFiles = append(manifest.ControllerFiles, bootstrap.ControllerConfigFile{
			Name: bootstrap.ControllerConfigFileNames[index], Bytes: wire, SHA256: controllerSHA256(wire)})
	}
	manifest.IntentSHA256 = manifest.ControllerFiles[0].SHA256
	for _, file := range record.Files {
		if file.Purpose == "owner-only" {
			continue
		}
		manifest.Secrets = append(manifest.Secrets, bootstrap.SecretReference{Purpose: file.Purpose,
			Slot: file.Slot, SHA256: file.SHA256, MaxBytes: file.MaxBytes, TargetFile: file.Name})
	}
	grant := TrustedSignerConfig{Actor: "ops", PublicKey: record.Public.ControllerResponsePublicKey,
		Roles: []string{"terrabase"}, Environments: []string{"canary"}}
	secondGrant := grant
	secondGrant.Actor, secondGrant.PublicKey = "ops-two", record.Public.LedgerSignerPublicKey
	signerWire, err := protocol.EncodeJSON([]TrustedSignerConfig{grant, secondGrant})
	if err != nil {
		t.Fatal(err)
	}
	for _, slot := range input.Slots {
		t.Run(slot.Name, func(t *testing.T) {
			manifest.Slot = slot.Name
			rendered, err := automaticControllerConfig(manifest, record, signerWire, now)
			if err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(t.TempDir(), "controller.json")
			if err := os.WriteFile(configPath, rendered.ControllerConfig, 0o600); err != nil {
				t.Fatal(err)
			}
			loaded, err := LoadConfig(configPath)
			if err != nil {
				t.Fatal(err)
			}
			loadedWire, err := loaded.signedWire()
			if err != nil || !bytes.Equal(loadedWire, rendered.ControllerConfig) {
				t.Fatalf("loaded controller configuration changed its exact bytes: %v", err)
			}
			var routes []string
			for _, peer := range input.Slots {
				if peer.Name != slot.Name {
					routes = append(routes, "nats-route://"+peer.PrivateIP+":6222")
				}
			}
			if loaded.NATS.Cell != input.Cell || loaded.NATS.Instance != slot.Name || loaded.NATS.Replicas != 3 ||
				loaded.NATS.URL != "tls://"+slot.PrivateIP+":4222" || loaded.NATS.Embedded == nil ||
				!slices.Equal(loaded.NATS.Embedded.Routes, routes) ||
				len(loaded.Controller.TrustedSigners) != 2 || loaded.Controller.TrustedSigners[0].PublicKey != grant.PublicKey ||
				loaded.Controller.TrustedSigners[1].PublicKey != secondGrant.PublicKey {
				t.Fatal("generated source lost its slot, routes or complete operator grants through config loading")
			}
		})
		t.Run(slot.Name+"-link", func(t *testing.T) {
			linked := manifest
			linked.Slot, linked.Secrets = slot.Name, slices.Clone(manifest.Secrets)
			for _, file := range linkRecord.Files {
				if file.Purpose == "owner-only" {
					continue
				}
				name := file.Name
				if name == "link-cell.jwt" {
					name = "cell.jwt"
				}
				linked.Secrets = slices.DeleteFunc(linked.Secrets, func(ref bootstrap.SecretReference) bool {
					return ref.TargetFile == name
				})
				linked.Secrets = append(linked.Secrets, bootstrap.SecretReference{Purpose: file.Purpose,
					Slot: file.Slot, SHA256: file.SHA256, MaxBytes: file.MaxBytes, TargetFile: name})
			}
			rendered, err := automaticControllerConfigWithLink(linked, record, linkRecord, signerWire, now)
			if err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(t.TempDir(), "controller.json")
			if err := os.WriteFile(configPath, rendered.ControllerConfig, 0o600); err != nil {
				t.Fatal(err)
			}
			loaded, err := LoadConfig(configPath)
			if err != nil {
				t.Fatal(err)
			}
			cert, key := bootstrap.InterRegionTLSFiles(slot.Name)
			link := loaded.NATS.Embedded.Link
			if link == nil || link.CredentialsFile != "" ||
				link.TLS.CAFile != filepath.Join(bootstrapstart.MaterialDirectory, "interregion-ca.pem") ||
				link.TLS.CertFile != filepath.Join(bootstrapstart.MaterialDirectory, cert) ||
				link.TLS.KeyFile != filepath.Join(bootstrapstart.MaterialDirectory, key) ||
				len(loaded.Controller.TrustedSigners) != 2 {
				t.Fatal("home Link lost its exact TLS paths or operator grants through config loading")
			}
			linked.Secrets = slices.DeleteFunc(linked.Secrets, func(ref bootstrap.SecretReference) bool {
				return ref.TargetFile == cert
			})
			if _, err := automaticControllerConfigWithLink(linked, record, linkRecord, signerWire, now); err == nil {
				t.Fatal("startup Link accepted a missing slot certificate reference")
			}
		})
	}
}
