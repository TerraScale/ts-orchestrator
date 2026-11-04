package app

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/storage"
	"github.com/TerraScale/ts-orchestrator/internal/storage/capacity"
)

func TestControllerCollectsStorageWithoutSettings(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cfg := Config{NATS: natscell.Config{Cell: "lab", Instance: "storage-controller", Replicas: 1,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "jetstream")}}}
	runtime, err := newAuthenticatedNATS(t, cfg.NATS.Cell).start(t, ctx, cfg.NATS)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	stop, err := startControllerStorageCapacity(ctx, cfg, runtime, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	store, err := capacity.OpenUsageStore(ctx, runtime.JetStream(), 1, storage.DefaultUsageTTL, capacity.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	for {
		usages, err := store.Usages(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(usages) == 2 {
			for _, usage := range usages {
				if usage.Node != cfg.NATS.Instance || usage.TotalBytes == 0 {
					t.Fatalf("invalid controller measurement: %+v", usage)
				}
			}
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("controller published no boot and JetStream measurements")
		case <-time.After(10 * time.Millisecond):
		}
	}
}
