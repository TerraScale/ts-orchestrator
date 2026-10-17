package app

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/globalview"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

func TestJournalAPIExposesRegionalResourceObservations(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	view := globalview.NewView("gru", func() []string { return []string{"sfo"} }, func() time.Time { return now })
	if !view.Accept(globalview.Rollup{Version: globalview.Version, Cell: "gru", ObservedAt: now,
		Nodes:               []globalview.Node{{Name: "node-a", Services: []globalview.Service{{Role: "gateway", State: "running"}}}},
		Volumes:             []globalview.Volume{{ID: "volume-a", Node: "node-a", State: "attached"}},
		ServicesObservedAt:  now,
		Services:            []swarmruntime.ServiceObservation{{ServiceID: "manager-api", RequestedReplicas: 2, Readiness: "unknown", ObservedAt: now}},
		FunctionsObservedAt: now,
		Functions:           []globalview.FunctionObservation{{TenantID: "tenant-a", FunctionID: "echo", State: "unplaced", ObservedAt: now}},
	}) {
		t.Fatal("regional observation was refused")
	}
	token := strings.Repeat("d", 40)
	server, err := observability.NewTokenServer(observability.Config{}, token, observability.ServerDeps{
		Registry: observability.NewRegistry(true), Health: new(observability.Health),
	})
	if err != nil {
		t.Fatal(err)
	}
	mountJournalAPI(server, journalProviders{Global: view})
	listener := httptest.NewServer(server)
	t.Cleanup(listener.Close)
	for _, scenario := range []struct {
		path, state, contains string
		status                int
	}{
		{"/v1/regions/gru/nodes", "current", "node-a", http.StatusOK},
		{"/v1/regions/gru/nodes/node-a", "current", "node-a", http.StatusOK},
		{"/v1/regions/gru/nodes/node-a/services", "current", "gateway", http.StatusOK},
		{"/v1/regions/gru/nodes/node-a/services/gateway", "current", "running", http.StatusOK},
		{"/v1/regions/gru/volumes", "current", "volume-a", http.StatusOK},
		{"/v1/regions/gru/volumes/volume-a", "current", "attached", http.StatusOK},
		{"/v1/regions/gru/services", "current", "manager-api", http.StatusOK},
		{"/v1/regions/gru/services/manager-api", "current", "unknown", http.StatusOK},
		{"/v1/regions/gru/functions", "current", "echo", http.StatusOK},
		{"/v1/regions/gru/functions/tenant-a/echo", "current", "unplaced", http.StatusOK},
		{"/v1/regions/gru/services/absent", "not_found", "", http.StatusNotFound},
		{"/v1/regions/gru/functions/tenant-b/echo", "not_found", "", http.StatusNotFound},
		{"/v1/regions/gru/nodes/absent", "not_found", "", http.StatusNotFound},
		{"/v1/regions/sfo/nodes", "missing", "", http.StatusServiceUnavailable},
	} {
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, listener.URL+scenario.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+token)
		response, err := listener.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		var result globalview.ResourceView
		if err := json.Unmarshal(body, &result); err != nil || response.StatusCode != scenario.status ||
			result.State != scenario.state || !strings.Contains(string(body), scenario.contains) {
			t.Fatalf("%s = %d %s: %v", scenario.path, response.StatusCode, body, err)
		}
	}
}
