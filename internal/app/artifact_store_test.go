package app

import (
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
)

// A spec's artifact store quota replaces the signed one only within what
// the controller's embedded NATS store holds beside control state, and the
// leader raises it only while the disk has room for the store to fill.
func TestArtifactStoreQuotaFromTheCellSpec(t *testing.T) {
	cfg := Config{NATS: natscell.Config{Cell: "gru", Embedded: &natscell.Embedded{StoreMaxBytes: 6 << 30}},
		Controller: ControllerConfig{ArtifactStoreMaxBytes: 512 << 20}}
	newAcceptedSpecTrust(t, &cfg)
	registry, err := newSpecRegistry(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	if quota := registry.artifactStoreMaxBytes(); quota != 512<<20 {
		t.Fatalf("generation 0 quota = %d", quota)
	}
	set := cellspec.Spec{Schema: cellspec.Schema, Generation: 1, RequiresBinary: 10,
		ArtifactStore: &cellspec.ArtifactStore{MaxBytes: cfg.NATS.Embedded.StoreMaxBytes - specStoreHeadroomBytes + 1}}
	if err := registry.validate(set); err == nil || !strings.Contains(err.Error(), "store_max_bytes") {
		t.Fatalf("quota beyond the embedded store: %v", err)
	}
	set.ArtifactStore.MaxBytes--
	if err := registry.validate(set); err != nil {
		t.Fatalf("quota exactly leaving spec headroom: %v", err)
	}
	set.ArtifactStore.MaxBytes = 2 << 30
	if err := registry.validate(set); err != nil {
		t.Fatal(err)
	}
	// The Machines API's buckets reserve their room too: sjc-1 went past
	// store_max_bytes with both (TS-662).
	withAPI := set
	withAPI.RequiresBinary, withAPI.MachinesAPI = 16, &cellspec.MachinesAPI{Issuer: "https://gru.auth.terrascale.tech/terrascale",
		Audience: "https://gru.orch.terrascale.tech", JWKSURLs: []string{"https://gru.auth.terrascale.tech/terrascale/.well-known/jwks.json"}, Clients: []string{"ts-orch-cli"}}
	withAPI.ArtifactStore = &cellspec.ArtifactStore{MaxBytes: cfg.NATS.Embedded.StoreMaxBytes - specStoreHeadroomBytes - machinesAPIStoreBytes + 1}
	if err := registry.validate(withAPI); err == nil || !strings.Contains(err.Error(), "store_max_bytes") {
		t.Fatalf("quota leaving no room for the Machines API: %v", err)
	}
	withAPI.ArtifactStore.MaxBytes--
	if err := registry.validate(withAPI); err != nil {
		t.Fatalf("quota exactly leaving Machines API headroom: %v", err)
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
