package ociresourcetest

import (
	"path/filepath"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
)

// Store opens the production OCI store against an isolated persistent NATS
// server. It belongs only in integration test binaries.
func Store(t *testing.T) *ociresource.KVStore {
	t.Helper()
	runtime, err := natscell.Start(t.Context(), natscell.Config{
		Cell: "lab", Instance: "oci-resource-store", Replicas: 1, Lab: true,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "jetstream")},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	store, err := ociresource.OpenKVStore(t.Context(), runtime.JetStream(), 1)
	if err != nil {
		t.Fatal(err)
	}
	return store
}
