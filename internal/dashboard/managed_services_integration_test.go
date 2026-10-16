package dashboard

import (
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/globalview"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

func TestDrillManagedServicesHTTP(t *testing.T) {
	global := globalview.NewView("gru", nil, func() time.Time { return testNow })
	rollup := globalview.Rollup{Version: globalview.Version, Cell: "gru", ObservedAt: testNow, ServicesObservedAt: testNow,
		Services: []swarmruntime.ServiceObservation{{ServiceID: "unplaced", IntentID: "intent-a", Role: "web", RequestedReplicas: 3, Readiness: "unknown", RequestedDigest: "sha256:requested", ObservedAt: testNow,
			Tasks: []swarmruntime.TaskObservation{{TaskID: "task-a", State: "PENDING"}}}}}
	if !global.Accept(rollup) {
		t.Fatal("source observation rejected")
	}
	handler := drillDashboard(t, global)
	for path, wants := range map[string][]string{
		"/regions/gru":                   {"Managed services", "unplaced", "/regions/gru/services/unplaced", "unknown", "sha256:requested"},
		"/regions/gru/services/unplaced": {"Requested replicas", "Ready replicas", "unknown", "task-a", "PENDING", "sha256:requested"},
		"/regions/gru/services/absent":   {"not_found", "absent only"},
	} {
		body := get(t, handler, path).Body.String()
		for _, want := range wants {
			if !strings.Contains(body, want) {
				t.Errorf("GET %s lacks %q", path, want)
			}
		}
	}
	rollup.ObservedAt = testNow.Add(time.Second)
	rollup.ServicesObservedAt = time.Time{}
	rollup.Services = nil
	if !global.Accept(rollup) {
		t.Fatal("unknown source observation rejected")
	}
	for _, path := range []string{"/regions/gru", "/regions/gru/services/unplaced"} {
		if body := get(t, handler, path).Body.String(); !strings.Contains(body, "unavailable") {
			t.Errorf("GET %s hides unavailable service source", path)
		}
	}
}
