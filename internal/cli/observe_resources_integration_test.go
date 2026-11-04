package cli

import (
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/globalview"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

func TestObserveRegionalResourceAPIs(t *testing.T) {
	f := newObserveFixture(t)
	now := time.Now().UTC()
	view := globalview.NewView("gru", func() []string { return []string{"gru", "sjc"} }, func() time.Time { return now })
	handler := globalview.Handler(view)
	f.server.HandleAuthenticated("/v1/regions", handler)
	f.server.HandleAuthenticated("/v1/regions/", handler)
	rollup := globalview.Rollup{Version: globalview.Version, Cell: "gru", ObservedAt: now,
		ServicesObservedAt: now,
		Services:           []swarmruntime.ServiceObservation{{ServiceID: "managed-a", Role: "web", RequestedReplicas: 3, RunningReplicas: 1, Readiness: "unknown", RequestedDigest: "sha256:requested", ObservedAt: now}},
		Health:             globalview.Health{Status: globalview.Healthy},
		Nodes:              []globalview.Node{{Name: "host-a", Health: globalview.NodeOK, ReportedAt: now, CPUCores: 8, MemoryBytes: (1 << 60) + 1, Services: []globalview.Service{{Role: "api", State: "running", Digest: "sha256:abc"}}}},
		Volumes:            []globalview.Volume{{ID: "volume-a", Node: "host-a", State: "attached"}},
	}
	if !view.Accept(rollup) {
		t.Fatal("regional producer rejected fixture")
	}
	for _, scenario := range []struct {
		view     string
		flags    []string
		contains string
		partial  bool
	}{
		{"regions", nil, "sjc", true},
		{"region", nil, "gru", false},
		{"nodes", nil, "host-a", false},
		{"node", []string{"--node", "host-a"}, "host-a", false},
		{"services", []string{"--node", "host-a"}, "sha256:abc", false},
		{"services", nil, "managed-a", false},
		{"service", []string{"--service", "managed-a"}, "sha256:requested", false},
		{"service", []string{"--node", "host-a", "--service", "api"}, "sha256:abc", false},
		{"volumes", nil, "volume-a", false},
		{"volume", []string{"--volume", "volume-a"}, "attached", false},
	} {
		t.Run(scenario.view+scenario.contains, func(t *testing.T) {
			for _, format := range []string{"json"} {
				output, err := f.run(t, scenario.view, append(append([]string{}, scenario.flags...), "--format", format)...)
				if (err != nil) != scenario.partial || !strings.Contains(output, scenario.contains) {
					t.Fatalf("%s output=%s error=%v", format, output, err)
				}
				if format == "json" {
					var result struct {
						Version int  `json:"version"`
						Partial bool `json:"partial"`
					}
					if err := json.Unmarshal([]byte(output), &result); err != nil || result.Version != 1 || result.Partial != scenario.partial {
						t.Fatalf("envelope=%s error=%v", output, err)
					}
				}
			}
		})
	}
}
