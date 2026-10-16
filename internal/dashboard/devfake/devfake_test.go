package devfake_test

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/dashboard"
	"github.com/TerraScale/ts-orchestrator/internal/dashboard/devfake"
)

func TestEveryPageAndStreamRendersTheFakeWorld(t *testing.T) {
	t.Parallel()
	world := devfake.New()
	go world.Run(t.Context())
	options := world.Options()
	options.Interval = 20 * time.Millisecond
	board := dashboard.New(options)
	server := httptest.NewServer(board.Handler())
	t.Cleanup(server.Close)
	for _, path := range []string{"/", "/region", "/region?r=sfo", "/insights", "/decisions", "/releases", "/rollouts",
		"/ci", "/topology", "/members", "/nats", "/terrabase", "/storage", "/oci", "/events", "/decisions?kind=held,hold_cleared", "/decisions?kind=leader_changed,quorum_degraded", "/releases?region=all"} {
		response, err := server.Client().Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		for _, want := range map[string][]string{
			"/": {"GRU", "SFO", "FRA"}, "/region?r=sfo": {"SFO"}, "/releases": {"v0.43.0", "v0.42.1"}, "/rollouts": {"complete", "canary-soak"}, "/terrabase": {"Time to full"}, "/decisions?kind=held,hold_cleared": {"held", "hold_cleared"}, "/decisions?kind=leader_changed,quorum_degraded": {"leader_changed", "quorum_degraded"},
		}[path] {
			if !strings.Contains(string(body), want) {
				t.Errorf("GET %s lacks %q", path, want)
			}
		}

		if response.StatusCode != http.StatusOK {
			t.Fatalf("GET %s = %d", path, response.StatusCode)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/global/stream?range=24h", nil)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	scanner := bufio.NewScanner(response.Body)
	scanner.Buffer(make([]byte, 0, 1<<20), 8<<20)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "region-switcher") {
			return
		}
	}
	t.Fatalf("the global stream never patched the page: %v", scanner.Err())
}

// TestProductionBinaryDoesNotLinkTheFake keeps fixtures confined to tests.
func TestProductionBinaryDoesNotLinkTheFake(t *testing.T) {
	t.Parallel()
	output, err := exec.Command("nice", "-n", "19", "go", "list", "-deps", "github.com/TerraScale/ts-orchestrator/cmd/terrascale-orchestrator").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, output)
	}
	if strings.Contains(string(output), "internal/dashboard/devfake") {
		t.Fatal("the orchestrator binary links the dev-only fake data provider")
	}
	if !strings.Contains(string(output), "internal/dashboard\n") {
		t.Fatal("go list did not list the dashboard; the check is not looking at the right binary")
	}
	sources, err := exec.Command("nice", "-n", "19", "go", "list", "-f", "{{join .GoFiles \"\\n\"}}", "github.com/TerraScale/ts-orchestrator/internal/dashboard/devfake").CombinedOutput()
	if err != nil {
		t.Fatalf("go list fixture sources: %v\n%s", err, sources)
	}
	if strings.TrimSpace(string(sources)) != "" {
		t.Fatalf("fake sources must be test-only: %s", sources)
	}
}
