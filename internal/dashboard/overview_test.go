package dashboard

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/globalview"
	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
)

func floatPtr(value float64) *float64 { return &value }

// overviewRollup is one region's rollup with two nodes, one link to each of
// the given peers and enough rows to fill every overview list.
func overviewRollup(cell string, observed time.Time, peers []string) globalview.Rollup {
	rollup := globalview.Rollup{Version: globalview.Version, Cell: cell, ObservedAt: observed,
		Health:      globalview.Health{Status: globalview.Healthy},
		Controllers: globalview.Controllers{Expected: 3, Ready: 3, Leader: cell + "-ctl-1"},
		Totals: globalview.Totals{Nodes: 12, Ready: 12, CPUCores: 96, CPUUsedCores: 24,
			MemoryBytes: 384 << 30, MemoryUsedBytes: 192 << 30, DiskBytes: 6000 << 30, DiskUsedBytes: 1200 << 30,
			NetworkRxBps: 12000, NetworkTxBps: 6000, Load1: 6},
		Replication: globalview.Replication{LagSeconds: floatPtr(1.5)},
		Cost:        &globalview.Cost{Currency: "USD", PerHour: 12.5, MonthForecast: 9000, ObservedAt: observed},
		Autoscale: globalview.Autoscale{Services: []globalview.Scaling{
			{Service: "api", Replicas: 3, Goal: 3}, {Service: "worker", Replicas: 2, Goal: 4},
			{Service: "db", Replicas: 1, Goal: 1}, {Service: "cache", Replicas: 2, Goal: 2}}},
	}
	for index := range 12 {
		rollup.Nodes = append(rollup.Nodes, globalview.Node{Name: fmt.Sprintf("%s-n%02d", cell, index),
			Health: globalview.NodeOK, ReportedAt: observed, CPU: floatPtr(0.25), CPUCores: 8,
			MemoryBytes: 32 << 30, MemoryUsedBytes: 16 << 30, DiskBytes: 500 << 30, DiskUsedBytes: 100 << 30,
			NetworkRxBps: floatPtr(1000), NetworkTxBps: floatPtr(500), Load1: floatPtr(0.5),
			Services: []globalview.Service{{Role: "controller", State: "ready", Digest: "sha256:abc"},
				{Role: "terrabase", State: "serving"}, {Role: "nats", State: "ready"}},
			Filesystems: []globalview.Filesystem{{Role: "root", SizeBytes: 100 << 30, UsedBytes: 40 << 30},
				{Role: "state", SizeBytes: 400 << 30, UsedBytes: 60 << 30}}})
	}
	for index := range 4 {
		rollup.Volumes = append(rollup.Volumes, globalview.Volume{ID: fmt.Sprintf("%s-vol-%d", cell, index),
			Node: fmt.Sprintf("%s-n%02d", cell, index), State: "attached"})
	}
	for _, peer := range peers {
		rollup.Links = append(rollup.Links, globalview.Link{Region: peer, Reach: decisionlog.RegionOK,
			RTTMillis: floatPtr(40), LagSeconds: floatPtr(2), ObservedAt: observed})
	}
	for index := range 6 {
		rollup.Routes = append(rollup.Routes, globalview.Route{From: fmt.Sprintf("%s-ctl-%d", cell, index),
			To: cell + "-ctl-1", RTTMillis: floatPtr(0.4)})
	}
	for index := range 10 {
		rollup.Errors = append(rollup.Errors, globalview.Error{At: observed.Add(-time.Duration(index) * time.Minute),
			Level: "ERROR", Component: "orchestrator", Message: "lease renewal slow", Count: index + 1,
			Nodes: []string{cell + "-n01", cell + "-n02", cell + "-n03"}})
	}
	for index := range 10 {
		rollup.Databases = append(rollup.Databases, globalview.Database{ID: fmt.Sprintf("%s-db-%d", cell, index),
			Project: cell + "-project", ReplicationBytesPerSecond: float64(1000 * (index + 1)), LagSeconds: 1})
	}
	return rollup
}

func TestOverviewHTTPPreservesRegionalEvidence(t *testing.T) {
	t.Parallel()
	gru := overviewRollup("gru", testNow, []string{"sjc"})
	gru.Health = globalview.Health{Status: globalview.Degraded, Reasons: []string{"disk 90%", "lag"}}
	gru.Cost = &globalview.Cost{Currency: "USD", PerHour: 2, MonthForecast: 1000}
	gru.Totals = globalview.Totals{Nodes: 2, Ready: 1, CPUCores: 4, CPUUsedCores: 1.5}
	gru.Scale = &nodescale.Status{Nodes: 12, Want: 14, Action: nodescale.Up, Reason: "cpu above target", InFlight: &nodescale.InFlight{Kind: nodescale.Up}}
	stale := overviewRollup("sjc", testNow.Add(-time.Minute), nil)
	stale.Databases = []globalview.Database{{ID: "stale-database", ReplicationBytesPerSecond: 1 << 50}}
	stale.Errors = []globalview.Error{{At: testNow, Level: "ERROR", Message: "stale-error"}}
	current := view{Now: testNow, Global: []globalview.Region{{Cell: "gru", Rollup: &gru}, {Cell: "sjc", Rollup: &stale, Stale: true}, {Cell: "fra"}}}
	body := fixturePage(t, current, "/")
	for _, want := range []string{"1 stale · 1 no data", "2.00 USD", "1 of 1 fresh regions report cost", "disk 90%; lag", "stale · last seen", "no data", "12 → 14", "cpu above target", "Scaling", "40 ms, lag 2 s"} {
		if !strings.Contains(body, want) {
			t.Errorf("overview lacks %q", want)
		}
	}
	if strings.Contains(body, "stale-database") || strings.Contains(body, "stale-error") {
		t.Fatal("stale evidence leaked into current inventories")
	}
	gru.Cost = nil
	current.Global = []globalview.Region{{Cell: "gru", Rollup: &gru}}
	if body := fixturePage(t, current, "/"); !strings.Contains(body, "not reported") {
		t.Fatal("missing cost was reported as zero")
	}
	gru.Scale = &nodescale.Status{Nodes: 12, Want: 12, Action: nodescale.Hold, Saturated: true, Reason: "allowance spent"}
	if body := fixturePage(t, current, "/"); !strings.Contains(body, "allowance spent") || !strings.Contains(body, "12 nodes") {
		t.Fatal("saturated scaling lost allowance evidence")
	}
}
