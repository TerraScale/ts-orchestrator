package dashboard

import (
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/globalview"
	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
)

// drillView is the drill-down fixture: local gru and sjc report four nodes
// each, sjc a minute late so it is stale. fra is listed but has no rollup.
func drillView(now time.Time) *globalview.View {
	global := globalview.NewView("gru", func() []string { return []string{"sjc", "fra"} }, func() time.Time { return now })
	for _, cell := range []string{"gru", "sjc"} {
		observed := now
		if cell == "sjc" {
			observed = now.Add(-time.Minute)
		}
		peers := slices.DeleteFunc([]string{"gru", "sjc", "fra"}, func(peer string) bool { return peer == cell })
		rollup := overviewRollup(cell, observed, peers)
		rollup.Nodes = rollup.Nodes[:4]
		rollup.Totals.Nodes, rollup.Totals.Ready = 4, 4
		if cell == "gru" {
			rollup.Scale = &nodescale.Status{Nodes: 4, QuorumNodes: 3, PoolNodes: 1, Want: 5, Allowance: 6,
				Action: nodescale.Up, Pressure: 0.9, Signal: nodescale.SignalCPU, Reason: "cpu 0.90 at or above 0.80 for 5m0s",
				InFlight:   &nodescale.InFlight{ID: "launch-1", Kind: nodescale.Up, Step: "launch", Started: now},
				LastChange: now.Add(-2 * time.Minute), NodeMonthlyCents: 4500, ProjectedCents: 90000, Currency: "USD"}
		}
		global.Accept(rollup)
	}
	return global
}

func drillDashboard(t *testing.T, global *globalview.View) http.Handler {
	t.Helper()
	return newTestDashboard(Options{Snapshots: fixedSnapshots{snapshot: memberSnapshot()},
		Journal: &Journal{Global: global}}).Handler()
}

func TestDrillRegionPage(t *testing.T) {
	t.Parallel()
	body := get(t, drillDashboard(t, drillView(testNow)), "/regions/gru").Body.String()
	for _, want := range []string{"<h1>", "GRU", "Nodes ready", "4 / 4", "/regions/gru/nodes/gru-n00",
		"/regions/gru/volumes/gru-vol-0", "gru-ctl-0", "0.4 ms, lag 0", "lease renewal slow", "worker",
		`href="/regions/sjc"`, "40 ms"} {
		if !strings.Contains(body, want) {
			t.Errorf("GET /regions/gru lacks %q", want)
		}
	}
	if strings.Contains(body, "values are last-known") {
		t.Error("fresh region GRU shows the stale badge")
	}
}

func TestDrillNodeVolumeServicePages(t *testing.T) {
	t.Parallel()
	handler := drillDashboard(t, drillView(testNow))
	for path, wants := range map[string][]string{
		"/regions/gru/nodes/gru-n01": {"Report age", "Filesystems", "root", "sha256:abc",
			"/regions/gru/nodes/gru-n01/services/controller", "/regions/gru/volumes/gru-vol-1"},
		"/regions/sjc/nodes/sjc-n00": {"values are last-known", ">stale<"},
		"/regions/gru/volumes/gru-vol-0": {"attached", `href="/regions/gru/nodes/gru-n00"`,
			"/regions/gru/nodes/gru-n00/services/controller"},
		"/regions/gru/nodes/gru-n00/services/controller": {"sha256:abc", "not autoscaled",
			"/regions/gru/nodes/gru-n01/services/controller", "Other nodes running controller"},
	} {
		body := get(t, handler, path).Body.String()
		for _, want := range wants {
			if !strings.Contains(body, want) {
				t.Errorf("GET %s lacks %q", path, want)
			}
		}
	}
}
