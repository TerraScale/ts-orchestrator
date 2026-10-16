//go:build linux

package host

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

// Any native lifecycle call panics through the absent embedded runner.
type sessionOnlyRunner struct{ Runner }

func TestSessionRuntimeDeliversMaterialAndFencesRevokedHostWithoutNativeRunner(t *testing.T) {
	fixture := newFunctionMaterialTransport(t)
	fixture.controller.functionMaterial = fixture.current
	agent := fixture.start(t)
	agent.runner = sessionOnlyRunner{}
	ready := make(chan struct{})
	agent.cfg.Initialized = func() { close(ready) }
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- agent.RunSession(ctx) }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("session runtime exited before readiness: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("session runtime did not establish its signed host session")
	}
	files, _, err := agent.CurrentFunctionFiles(t.Context(), fixture.binding)
	if err != nil || !bytes.Equal(files["module.wasm"], fixture.files["module.wasm"]) {
		t.Fatalf("same session did not deliver admitted function material: %v", err)
	}
	statuses, err := fixture.controller.ListHosts(t.Context())
	if err != nil || len(statuses) != 1 {
		t.Fatalf("read real host before revocation: %v", err)
	}
	registration := statuses[0].Registration
	registration.Generation++
	if _, err := fixture.controller.Register(t.Context(), registration); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil || errors.Is(err, context.Canceled) {
			t.Fatalf("revoked host did not fail its session: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("session runtime did not fence the revoked registration")
	}
	if _, _, err := agent.CurrentFunctionFiles(t.Context(), fixture.binding); err == nil {
		t.Fatal("revoked session still delivered function material")
	}
}
