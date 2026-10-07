package app

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

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
	// Every check re-reads the token, as after dashboardTokenRead.
	dashboardPort, dashboardCheck, dashboardTokenRead = port, 10*time.Millisecond, 0
	t.Cleanup(func() {
		dashboardPort, dashboardCheck, dashboardTokenRead = cellspec.DashboardPort, 5*time.Second, 5*time.Minute
	})

	var mu sync.Mutex
	section := &cellspec.Dashboard{Token: vaultsecret.Ref{Vault: "v", Name: "gru-1-orch-dashboard-token"}}
	tokens := map[string]string{"gru-1-orch-dashboard-token": strings.Repeat("a", 32)}
	vaultDown := false
	current := func() *cellspec.Dashboard {
		mu.Lock()
		defer mu.Unlock()
		return section
	}
	read := func(_ context.Context, ref vaultsecret.Ref) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		if vaultDown {
			return "", errors.New("vault unavailable")
		}
		return tokens[ref.Name], nil
	}
	address := func() (netbirdAddresses, bool) { return netbirdAddresses{netip.MustParseAddr("127.0.0.1")}, true }
	runtime := &runtimeObservability{registry: observability.NewRegistry(false), health: new(observability.Health),
		events: observability.NewEventBus(16)}
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
	mu.Unlock()
	eventually("the new token never served", func() bool { return status("/topology", second) == http.StatusOK })
	if got := status("/topology", first); got == http.StatusOK {
		t.Error("the old token still serves")
	}

	mu.Lock()
	vaultDown = true
	mu.Unlock()
	time.Sleep(50 * time.Millisecond)
	if got := status("/topology", second); got != http.StatusOK {
		t.Errorf("a Vault outage stopped the dashboard: %d", got)
	}

	mu.Lock()
	section = nil
	mu.Unlock()
	eventually("the listener kept serving without a section", func() bool { return status("/healthz", "") == 0 })
	runtime.boardsMu.Lock()
	boards := len(runtime.boards)
	runtime.boardsMu.Unlock()
	if boards != 0 {
		t.Errorf("%d dashboards are still fed after the listener closed", boards)
	}
}
