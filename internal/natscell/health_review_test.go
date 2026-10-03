package natscell

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// A running server whose JetStream was shut down (as a store failure does)
// must not be reported as a healthy single-member metadata group.
func TestObserveClusterReportsDisabledJetStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	runtime, err := Start(ctx, Config{Cell: "lab", Instance: "solo", Replicas: 1, Lab: true,
		Embedded: &Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "solo")}})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	if err := runtime.server.ShutdownJetStream(); err != nil {
		t.Fatal(err)
	}
	observation, err := runtime.ObserveCluster()
	if !errors.Is(err, ErrJetStreamDisabled) || observation.MetaLeader != "" || observation.MetaSize != 0 {
		t.Fatalf("observation = %+v, %v", observation, err)
	}
	if _, err := runtime.Observe(ctx); !errors.Is(err, ErrJetStreamDisabled) {
		t.Fatalf("Observe error = %v", err)
	}
}
