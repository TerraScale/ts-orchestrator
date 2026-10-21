package app

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
)

// A production controller serves the Machines API only while the adopted
// cell spec carries machines_api, on its broker address, and stops when the
// section goes, without a restart.
func TestMachinesAPIFollowsTheCellSpec(t *testing.T) {
	machinesAPICheck = 50 * time.Millisecond
	t.Cleanup(func() { machinesAPICheck = 5 * time.Second })
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	host := "127.0.0.42"
	auth := newAuthenticatedNATS(t, "gru")
	broker, err := auth.start(t, ctx, natscell.Config{Cell: "gru", Instance: "machines-spec", Replicas: 1,
		Embedded: &natscell.Embedded{Host: host, Port: -1, StoreDir: filepath.Join(t.TempDir(), "nats")}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
	control, err := authority.Start(ctx, broker.JetStream(), authority.Config{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Scope: "gru", CandidateID: "0000000000N8R21NWNZ7QZ2X0N", Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	cfg := Config{NATS: natscell.Config{Cell: "gru", Replicas: 1, Embedded: &natscell.Embedded{Host: host}}}
	var current atomic.Pointer[cellspec.MachinesAPI]
	loopCtx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		done <- machinesAPILoop(loopCtx, cfg, broker, control, func() bool { return true }, current.Load, nil)
	}()
	health := func() int {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://%s:%d/healthz", host, cellspec.MachinesAPIPort), nil)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			return 0
		}
		response.Body.Close()
		return response.StatusCode
	}
	await := func(want int) {
		t.Helper()
		for deadline := time.Now().Add(10 * time.Second); health() != want; {
			if time.Now().After(deadline) {
				t.Fatalf("health %d, want %d", health(), want)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	await(0)
	current.Store(&cellspec.MachinesAPI{Issuer: "https://gru.auth.terrascale.tech/terrascale", Audience: "https://gru.orch.terrascale.tech",
		JWKSURLs: []string{"http://127.0.0.1:1/jwks.json"}, Clients: []string{"00000000000000000000000001"}})
	await(http.StatusOK)
	current.Store(nil)
	await(0)
	stop()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
