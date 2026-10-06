package app

import (
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/cellspec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
)

// A spec's artifact store quota replaces the signed one only within what
// the controller's embedded NATS store holds beside control state, and the
// leader raises it only while the disk has room for the store to fill.
func TestArtifactStoreQuotaFromTheCellSpec(t *testing.T) {
	cfg := Config{NATS: natscell.Config{Cell: "gru", Lab: true, Embedded: &natscell.Embedded{StoreMaxBytes: 4 << 30}},
		Controller: ControllerConfig{ArtifactStoreMaxBytes: 512 << 20}}
	registry, err := newSpecRegistry(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	if quota := registry.artifactStoreMaxBytes(); quota != 512<<20 {
		t.Fatalf("generation 0 quota = %d", quota)
	}
	set := cellspec.Spec{Schema: cellspec.Schema, Generation: 1, RequiresBinary: 10,
		ArtifactStore: &cellspec.ArtifactStore{MaxBytes: 4<<30 - controlStoreHeadroomBytes + 1}}
	if err := registry.validate(set); err == nil || !strings.Contains(err.Error(), "store_max_bytes") {
		t.Fatalf("quota beyond the embedded store: %v", err)
	}
	set.ArtifactStore.MaxBytes = 2 << 30
	if err := registry.validate(set); err != nil {
		t.Fatal(err)
	}
	registry.adopt(set, 1)
	if quota := registry.artifactStoreMaxBytes(); quota != 2<<30 {
		t.Fatalf("adopted quota = %d", quota)
	}
	// Restating the signed quota changes nothing.
	restated := set
	restated.ArtifactStore = &cellspec.ArtifactStore{MaxBytes: 512 << 20}
	if plan, err := cellspec.Diff(registry.withSigned(cellspec.Spec{}), registry.withSigned(restated), nil); err != nil || plan.ArtifactStore != "" {
		t.Fatalf("restated signed quota: plan %+v, %v", plan, err)
	}

	if err := quotaFits(2<<30, 1<<30, 1<<30); err != nil {
		t.Fatalf("raise with room on disk: %v", err)
	}
	if err := quotaFits(2<<30, 1<<30, 1<<30-1); err == nil {
		t.Fatal("raise past the free disk accepted")
	}
	if err := quotaFits(1<<30, 2<<30, 0); err != nil {
		t.Fatalf("quota below the bytes held needs no disk: %v", err)
	}
}
