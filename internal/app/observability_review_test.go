package app

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
)

// An unusable bearer token file fails closed for the listener only: the role
// keeps starting, exactly as when the port cannot be bound.
func TestUnusableObservabilityTokenDoesNotStopTheRole(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("shared-token-shared-token-shared-token\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tokenFile, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := Config{NATS: natscell.Config{Cell: "lab", Instance: "one"},
		Observability: observability.Config{ListenAddress: "127.0.0.1:9464", BearerTokenFile: tokenFile}}
	telemetry, err := startRuntimeObservability(t.Context(), cfg, "host", "one")
	if err != nil {
		t.Fatalf("an unusable token file stopped the role: %v", err)
	}
	defer telemetry.close()
	if telemetry.server != nil {
		t.Fatal("a listener was served without a usable token")
	}
}

func TestWatchObservabilityListenerReturnsOnTerminalResult(t *testing.T) {
	for _, result := range []error{nil, errors.New("accept failed")} {
		serveErrors := make(chan error, 1)
		serveErrors <- result
		done := make(chan struct{})
		go func() {
			watchObservabilityListener(serveErrors)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("watcher did not return on the terminal serve result")
		}
	}
	watchObservabilityListener(nil)
}
