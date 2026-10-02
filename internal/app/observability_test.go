package app

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
)

func TestSignedObservabilityStaysOnLoopbackOrBrokerAddress(t *testing.T) {
	t.Parallel()
	base := Config{NATS: natscell.Config{Embedded: &natscell.Embedded{Host: "10.0.1.5"}}}
	for name, settings := range map[string]observability.Config{
		"default":  {},
		"disabled": {ListenAddress: observability.DisabledListenAddress},
		"broker": {ListenAddress: "10.0.1.5:9464",
			BearerTokenFile: "/etc/terrascale-orchestrator/observability-token"},
	} {
		cfg := base
		cfg.Observability = settings
		if err := validateSignedObservability(cfg); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, settings := range map[string]observability.Config{
		"other private address": {ListenAddress: "10.0.1.6:9464",
			BearerTokenFile: "/etc/terrascale-orchestrator/observability-token"},
		"wildcard":          {ListenAddress: "0.0.0.0:9464"},
		"no token":          {ListenAddress: "10.0.1.5:9464"},
		"token outside":     {ListenAddress: "10.0.1.5:9464", BearerTokenFile: "/tmp/token"},
		"token traversal":   {ListenAddress: "10.0.1.5:9464", BearerTokenFile: "/etc/terrascale-orchestrator/../shadow"},
		"invalid log level": {LogLevel: "trace"},
	} {
		cfg := base
		cfg.Observability = settings
		if err := validateSignedObservability(cfg); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestLoadConfigRejectsPublicObservabilityListener(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"nats":{"cell":"lab"},"observability":{"listen_address":"8.8.8.8:9464"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "observability") {
		t.Fatalf("LoadConfig() error = %v", err)
	}
}

type observedAuthority struct{ snapshot authority.Snapshot }

func (fencer observedAuthority) Current() authority.Snapshot  { return fencer.snapshot }
func (observedAuthority) Guard(context.Context, uint64) error { return nil }

func freeLoopbackAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return address
}

// The controller wiring must expose readiness, metrics, its own snapshot and
// a cell-wide view through the private listener without touching state.
func TestControllerObservabilityServesSnapshotAndCluster(t *testing.T) {
	original := slog.Default()
	t.Cleanup(func() { slog.SetDefault(original) })
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	nats, err := natscell.Start(ctx, natscell.Config{Cell: "lab", Instance: "one", Replicas: 1, Lab: true,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "js")}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nats.Close() })
	address := freeLoopbackAddress(t)
	cfg := Config{NATS: natscell.Config{Cell: "lab", Instance: "one"},
		Observability: observability.Config{ListenAddress: address, ClusterAggregation: true, LogFormat: "logfmt"}}
	telemetry, err := startRuntimeObservability(ctx, cfg, "controller", "one")
	if err != nil {
		t.Fatal(err)
	}
	if telemetry.server == nil {
		t.Skipf("loopback port %s was taken before the listener bound", address)
	}
	get := func(path string) (int, string) {
		t.Helper()
		response, err := http.Get("http://" + address + path)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		return response.StatusCode, string(body)
	}
	if status, body := get("/readyz"); status != http.StatusServiceUnavailable || !strings.Contains(body, "startup failing") {
		t.Fatalf("/readyz before startup = %d %q", status, body)
	}
	lease := observedAuthority{snapshot: authority.Snapshot{Leader: true, Ready: true, Epoch: 3, Revision: 8,
		ExpiresAt: time.Now().Add(time.Minute)}}
	if err := telemetry.attachController(ctx, controllerObservation{nats: nats, replicas: 1,
		brokerIDs: []string{"one", "two"}, authority: lease}, nil); err != nil {
		t.Fatal(err)
	}
	telemetry.markStarted()
	if status, body := get("/readyz"); status != http.StatusOK {
		t.Fatalf("/readyz after startup = %d %q", status, body)
	}
	status, metrics := get("/metrics")
	if status != http.StatusOK || !strings.Contains(metrics, "ts_orch_authority_epoch 3") ||
		!strings.Contains(metrics, "ts_orch_js_meta_leader 1") || !strings.Contains(metrics, "go_goroutines") {
		t.Fatalf("/metrics = %d\n%s", status, metrics)
	}
	status, body := get("/v1/snapshot")
	var snapshot observability.MemberSnapshot
	if err := json.Unmarshal([]byte(body), &snapshot); err != nil || status != http.StatusOK ||
		snapshot.Member != "one" || snapshot.Authority == nil || !snapshot.Authority.CanMutate || snapshot.NATS == nil {
		t.Fatalf("/v1/snapshot = %d %s (%v)", status, body, err)
	}
	status, body = get("/v1/cluster")
	var cluster observability.ClusterSnapshot
	if err := json.Unmarshal([]byte(body), &cluster); err != nil || status != http.StatusOK ||
		len(cluster.Members) != 1 || cluster.Members[0].Member != "one" ||
		len(cluster.Missing) != 1 || cluster.Missing[0] != "two" {
		t.Fatalf("/v1/cluster = %d %s (%v)", status, body, err)
	}
	slog.Warn("synthetic warning", observability.ComponentKey, "test")
	status, body = get("/v1/events")
	if status != http.StatusOK || !strings.Contains(body, "synthetic warning") {
		t.Fatalf("/v1/events = %d %s", status, body)
	}
}
