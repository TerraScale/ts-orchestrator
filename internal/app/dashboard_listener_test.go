package app

import (
	"context"
	"encoding/json"
	"errors"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/cellspec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// The spec's dashboard section starts the NetBird listener behind the Vault
// token, a new token replaces the old one, a Vault outage keeps serving the
// token read last, and removing the section stops the listener.
func TestDashboardLoopFollowsTheSpec(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(probe.Addr().(*net.TCPAddr).Port)
	_ = probe.Close()
	dashboardPort, dashboardCheck, dashboardTokenRead = port, 10*time.Millisecond, 5*time.Minute
	t.Cleanup(func() {
		dashboardPort, dashboardCheck, dashboardTokenRead = cellspec.DashboardPort, 5*time.Second, 5*time.Minute
	})

	var mu sync.Mutex
	section := &cellspec.Dashboard{Token: vaultsecret.Ref{Vault: "v", Name: "gru-1-orch-dashboard-token"}}
	generation := uint64(1)
	tokenNumber := int64(1)
	netbirdAddress := netip.MustParseAddr("127.0.0.1")
	tokens := map[string]string{"gru-1-orch-dashboard-token": strings.Repeat("a", 32)}
	vaultDown := false
	current := func() (*cellspec.Dashboard, uint64) {
		mu.Lock()
		defer mu.Unlock()
		return section, generation
	}
	read := func(_ context.Context, ref vaultsecret.Ref) (vaultsecret.VersionedValue, error) {
		mu.Lock()
		defer mu.Unlock()
		if vaultDown {
			return vaultsecret.VersionedValue{}, errors.New("vault unavailable")
		}
		return vaultsecret.VersionedValue{Value: tokens[ref.Name], SecretID: ref.Name, Number: tokenNumber}, nil
	}
	address := func() (netbirdAddresses, bool) {
		mu.Lock()
		defer mu.Unlock()
		return netbirdAddresses{netbirdAddress}, true
	}
	broker, err := natscell.Start(t.Context(), natscell.Config{Cell: "lab", Instance: "one", Replicas: 1, Lab: true,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "js")}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
	runtime := &runtimeObservability{registry: observability.NewRegistry(false), health: new(observability.Health),
		events: observability.NewEventBus(16), sessionJS: broker.JetStream(), sessionReplicas: 1}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { runtime.dashboardLoop(ctx, current, address, read); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	base := "http://" + netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port).String()
	status := func(path, token string) int {
		request, _ := http.NewRequest(http.MethodGet, base+path, nil)
		// A DNS name, as operators use, is accepted behind a token.
		request.Host = "ts-gru-1.nb.ts.internal:9463"
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		response, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}).Do(request)
		if err != nil {
			return 0
		}
		_ = response.Body.Close()
		return response.StatusCode
	}
	eventually := func(what string, check func() bool) {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); !check(); time.Sleep(10 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatal(what)
			}
		}
	}
	first, second := strings.Repeat("a", 32), strings.Repeat("b", 32)
	eventually("the dashboard never served", func() bool { return status("/topology", first) == http.StatusOK })
	if got := status("/topology", ""); got != http.StatusUnauthorized && got != http.StatusSeeOther {
		t.Errorf("tokenless /topology = %d", got)
	}
	if got := status("/healthz", ""); got != http.StatusOK {
		t.Errorf("/healthz = %d", got)
	}

	mu.Lock()
	tokens["gru-1-orch-dashboard-token-2"] = second
	section = &cellspec.Dashboard{Token: vaultsecret.Ref{Vault: "v", Name: "gru-1-orch-dashboard-token-2"}}
	generation++
	mu.Unlock()
	eventually("the new token never served", func() bool { return status("/topology", second) == http.StatusOK })
	if got := status("/topology", first); got == http.StatusOK {
		t.Error("the old token still serves")
	}
	// Another controller learns a new version while this listener still has
	// five minutes of cached token. An address change must not roll it back.
	third := strings.Repeat("c", 32)
	store, err := observability.OpenSessionStore(t.Context(), broker.JetStream(), 1, "netbird")
	if err != nil {
		t.Fatal(err)
	}
	other, err := observability.NewTokenServer(observability.Config{Dashboard: true}, third, observability.ServerDeps{
		Registry: observability.NewRegistry(false), Health: new(observability.Health), Sessions: store,
		TokenVersion: observability.TokenVersion{Source: "gru-1-orch-dashboard-token-2", Number: 2, SpecGeneration: 2}})
	if err != nil {
		t.Fatal(err)
	}
	other.HandleLogin(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	login := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("token="+third))
	login.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	other.ServeHTTP(recorder, login)
	if recorder.Code != http.StatusSeeOther || len(recorder.Result().Cookies()) != 1 {
		t.Fatal("the current controller did not issue a session")
	}
	cookie := recorder.Result().Cookies()[0]
	mu.Lock()
	tokens["gru-1-orch-dashboard-token-2"], tokenNumber = third, 2
	netbirdAddress = netip.MustParseAddr("127.0.0.2")
	mu.Unlock()
	base = "http://" + netip.AddrPortFrom(netip.MustParseAddr("127.0.0.2"), port).String()
	eventually("a cached stale version prevented listener recovery", func() bool { return status("/topology", third) == http.StatusOK })
	if status("/topology", second) == http.StatusOK {
		t.Fatal("restarted listener serves its cached old token")
	}
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	request.AddCookie(cookie)
	recorder = httptest.NewRecorder()
	other.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatal("stale listener restart revoked the current controller's session")
	}

	mu.Lock()
	vaultDown = true
	generation++ // Force a read despite the cache, without changing the token ref.
	mu.Unlock()
	time.Sleep(50 * time.Millisecond)
	if got := status("/topology", third); got != http.StatusOK {
		t.Errorf("a Vault outage stopped the dashboard: %d", got)
	}

	mu.Lock()
	section = nil
	mu.Unlock()
	eventually("the listener kept serving without a section", func() bool { return status("/healthz", "") == 0 })
	eventually("dashboards are still fed after listener cleanup", func() bool {
		runtime.boardsMu.Lock()
		defer runtime.boardsMu.Unlock()
		return len(runtime.boards) == 0
	})
}

func TestDashboardStorageFailureHasSafeCleanup(t *testing.T) {
	runtime := &runtimeObservability{}
	stop, _, err := runtime.startDashboard(t.Context(), dashboardListener{})
	if err == nil || stop == nil {
		t.Fatal("storage failure must return an error and safe cleanup")
	}
	stop()
}

func TestNetBirdDashboardServesAuthenticatedResourceAPIs(t *testing.T) {
	original := slog.Default()
	t.Cleanup(func() { slog.SetDefault(original) })
	ctx := t.Context()
	broker, err := natscell.Start(ctx, natscell.Config{Cell: "lab", Instance: "one", Replicas: 1, Lab: true,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "js")}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
	runtime, err := startRuntimeObservability(ctx, Config{NATS: natscell.Config{Cell: "lab", Instance: "one"},
		Observability: observability.Config{ListenAddress: "off", ClusterAggregation: true}}, "controller", "one")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.close)
	lease := observedAuthority{snapshot: authority.Snapshot{Leader: true, Ready: true, Epoch: 1,
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
