package app

import (
	"encoding/json"

	"github.com/TerraScale/ts-orchestrator/internal/natscell"

	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

func TestNetBirdDashboardServesAuthenticatedResourceAPIs(t *testing.T) {
	original := slog.Default()
	t.Cleanup(func() { slog.SetDefault(original) })
	ctx := t.Context()
	auth := newAuthenticatedNATS(t, "lab")
	broker, err := auth.start(t, ctx, natscell.Config{Cell: "lab", Instance: "one", Replicas: 1,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "js")}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
	runtime, err := startRuntimeObservability(ctx, Config{NATS: natscell.Config{Cell: "lab", Instance: "one"},
		Observability: observability.Config{ListenAddress: freeLoopbackAddress(t)}}, "controller", "one")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.close)
	lease := observedAuthority{snapshot: authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Leader: true, Ready: true, Epoch: 1,
		ExpiresAt: time.Now().Add(time.Minute)}}
	if err := runtime.attachController(ctx, controllerObservation{nats: broker, replicas: 1, brokerIDs: []string{"one"}, authority: lease},
		[]observability.FilesystemRole{{Role: "boot", Path: t.TempDir()}}); err != nil {
		t.Fatal(err)
	}
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dashboardPort = uint16(probe.Addr().(*net.TCPAddr).Port)
	_ = probe.Close()
	t.Cleanup(func() { dashboardPort = cellspec.DashboardPort })
	token := strings.Repeat("r", 40)
	stop, _, err := runtime.startDashboard(ctx, dashboardListener{addresses: netbirdAddresses{netip.MustParseAddr("127.0.0.1")},
		token: vaultsecret.VersionedValue{Value: token, SecretID: "dashboard", Number: 1}, generation: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)
	base := "http://" + netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), dashboardPort).String()
	for _, path := range []string{"/v1/snapshot", "/v1/cluster", "/v1/history/metrics", "/v1/regions", "/v1/decisions", "/v1/insights", "/v1/summary"} {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+token)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || response.StatusCode != http.StatusOK || !json.Valid(body) {
			t.Fatalf("%s = %d %s (%v)", path, response.StatusCode, body, err)
		}
		if path == "/v1/snapshot" {
			var snapshot observability.MemberSnapshot
			if err := json.Unmarshal(body, &snapshot); err != nil {
				t.Fatal(err)
			}
			if snapshot.System == nil || snapshot.System.CPUCount == 0 || snapshot.System.MemTotalBytes == 0 ||
				len(snapshot.System.Filesystems) != 1 || snapshot.System.Filesystems[0].SizeBytes == 0 {
				t.Fatalf("node resource readings disappeared: %+v", snapshot)
			}
			if snapshot.OCI == nil {
				t.Fatal("OCI operation metrics must be observable independently of managed placement")
			}
		}
		request.Header.Del("Authorization")
		response, err = http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("unauthenticated %s = %d", path, response.StatusCode)
		}
	}
}
