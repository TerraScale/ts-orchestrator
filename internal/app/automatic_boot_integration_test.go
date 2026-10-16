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
	manifest := bootstrap.Manifest{DeploymentID: input.DeploymentID, ClusterID: input.ClusterID,
		Environment: input.Environment, Cell: oci.RegionGRU, OCIRegion: input.Region,
		Slot: input.Slots[0].Name, ControllerSlots: []string{"controller-a", "controller-b", "controller-c"}}
	for _, file := range record.Files {
		manifest.Secrets = append(manifest.Secrets, bootstrap.SecretReference{Purpose: file.Purpose,
			Slot: file.Slot, SHA256: file.SHA256, MaxBytes: file.MaxBytes, TargetFile: file.Name})
	}
	grant := TrustedSignerConfig{Actor: "ops", PublicKey: record.Public.ControllerResponsePublicKey,
		Roles: []string{"terrabase"}, Environments: []string{"canary"}}
	config, err := ControllerConfigFromRecord(manifest, record, grant, now)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := protocol.EncodeJSON(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "controller.json")
	if err := os.WriteFile(configPath, wire, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	loadedWire, err := loaded.signedWire()
	if err != nil || !bytes.Equal(loadedWire, wire) {
		t.Fatalf("loaded controller configuration changed its exact bytes: %v", err)
	}
	if loaded.NATS.Cell != input.Cell || loaded.NATS.Instance != manifest.Slot || loaded.NATS.Replicas != 3 ||
		loaded.NATS.URL != "tls://10.251.0.10:4222" || loaded.NATS.Embedded == nil ||
		!slices.Equal(loaded.NATS.Embedded.Routes, []string{"nats-route://10.251.0.11:6222", "nats-route://10.251.0.12:6222"}) ||
		len(loaded.Controller.TrustedSigners) != 1 || loaded.Controller.TrustedSigners[0].PublicKey != grant.PublicKey {
		t.Fatal("generated source did not retain its cell, slot, routes and operator grant through config loading")
	}
}
