package dashboard

import (
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/globalview"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/nodescale"
)

// drillView is the drill-down fixture: local gru and sfo report four nodes
// each, sfo a minute late so it is stale. fra is listed but has no rollup.
func drillView(now time.Time) *globalview.View {
	global := globalview.NewView("gru", func() []string { return []string{"sfo", "fra"} }, func() time.Time { return now })
	for _, cell := range []string{"gru", "sfo"} {
		observed := now
		if cell == "sfo" {
			observed = now.Add(-time.Minute)
		}
		peers := slices.DeleteFunc([]string{"gru", "sfo", "fra"}, func(peer string) bool { return peer == cell })
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
		`href="/regions/sfo"`, "40 ms"} {
		if !strings.Contains(body, want) {
			t.Errorf("GET /regions/gru lacks %q", want)
		}
	}
	if strings.Contains(body, "values are last-known") {
		t.Error("fresh region GRU shows the stale badge")
	}
}

func TestDrillRegionNodeScaling(t *testing.T) {
	t.Parallel()
	handler := drillDashboard(t, drillView(testNow))
	body := get(t, handler, "/regions/gru").Body.String()
	for _, want := range []string{"Node scaling", "4 (3 quorum, 1 pool)", "6 (stale)", "90.0% · cpu",
		"cpu 0.90 at or above 0.80 for 5m0s", "45.00 USD", "900.00 USD"} {
		if !strings.Contains(body, want) {
			t.Errorf("GET /regions/gru lacks scaling row %q", want)
		}
	}
	if body := get(t, handler, "/regions/sfo").Body.String(); !strings.Contains(body, "This region runs no node scaler yet.") {
		t.Error("GET /regions/sfo lacks the empty node scaling note")
	}
}

func TestDrillStaleAndNoDataRegions(t *testing.T) {
	t.Parallel()
	handler := drillDashboard(t, drillView(testNow))
	if body := get(t, handler, "/regions/sfo").Body.String(); !strings.Contains(body, "stale · last seen 1m ago") ||
		!strings.Contains(body, "values are last-known") {
		t.Errorf("GET /regions/sfo lacks its stale badge")
	}
	if body := get(t, handler, "/regions/fra").Body.String(); !strings.Contains(body, "No data from this region yet") {
		t.Errorf("GET /regions/fra lacks the no-data state")
	}
}

func TestDrillNodeVolumeServicePages(t *testing.T) {
	t.Parallel()
	handler := drillDashboard(t, drillView(testNow))
	for path, wants := range map[string][]string{
		"/regions/gru/nodes/gru-n01": {"Report age", "Filesystems", "root", "sha256:abc",
			"/regions/gru/nodes/gru-n01/services/controller", "/regions/gru/volumes/gru-vol-1"},
		"/regions/sfo/nodes/sfo-n00": {"values are last-known", ">stale<"},
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

func TestDrillUnknownEntitiesAreNotFound(t *testing.T) {
	t.Parallel()
	handler := drillDashboard(t, drillView(testNow))
	for path, want := range map[string]string{
		"/regions/xyz":                                "is not in the global view",
		"/regions/gru/nodes/nope":                     "does not report in GRU",
		"/regions/gru/volumes/nope":                   "is not in the GRU rollup",
		"/regions/gru/nodes/gru-n00/services/nope":    "is not placed on node gru-n00",
		"/regions/gru/nodes/nope/services/controller": "does not report in GRU",
		"/regions/fra/nodes/fra-n00":                  "does not report in FRA",
	} {
		response := get(t, handler, path)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), want) {
			t.Errorf("GET %s = %d, want the %q note", path, response.Code, want)
		}
	}
	if response := get(t, handler, "/regions/FRA%21"); response.Code != http.StatusNotFound {
		t.Errorf("GET /regions/FRA%%21 = %d, want 404", response.Code)
	}
}

func TestDrilldownNeverAsksRegions(t *testing.T) {
	t.Parallel()
	global := drillView(testNow)
	handler := newTestDashboard(Options{Snapshots: fixedSnapshots{snapshot: memberSnapshot()},
		Journal: &Journal{Local: neverLocal(t), Global: global}}).Handler()
	for _, path := range []string{"/nodes", "/nodes?region=gru&sort=cpu", "/volumes", "/regions/gru",
		"/regions/sfo", "/regions/fra", "/regions/gru/nodes/gru-n00", "/regions/gru/volumes/gru-vol-0",
		"/regions/gru/nodes/gru-n00/services/controller"} {
		if response := get(t, handler, path); response.Code != http.StatusOK {
			t.Fatalf("GET %s = %d", path, response.Code)
		}
	}
}

func TestUnreadVolumesAreNotShownAsNone(t *testing.T) {
	t.Parallel()
	global := drillView(testNow)
	rollup := overviewRollup("gru", testNow.Add(time.Second), []string{"sfo", "fra"})
	rollup.Volumes, rollup.VolumesUnavailable = nil, true
	global.Accept(rollup)
	handler := drillDashboard(t, global)
	if body := get(t, handler, "/regions/gru").Body.String(); !strings.Contains(body, "could not read its volume list") {
		t.Fatal("region page shows a failed volume read as no volumes")
	}
	if body := get(t, handler, "/volumes").Body.String(); !strings.Contains(body, "Volume list unavailable from GRU") {
		t.Fatal("/volumes hides the region whose volume read failed")
	}
}
