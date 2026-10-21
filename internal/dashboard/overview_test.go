package dashboard

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/globalview"
	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/regionview"
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

func TestGlobalMapPlacesKnownRegionsOnly(t *testing.T) {
	t.Parallel()
	gru := overviewRollup("gru", testNow, []string{"sjc", "lab"})
	gru.Links[0].RTTMillis = floatPtr(45)
	gru.Links[0].LagSeconds = floatPtr(2)
	sjc := overviewRollup("sjc", testNow, nil)
	sjc.Links = nil
	lab := overviewRollup("lab", testNow, nil)
	current := view{Now: testNow, Local: &observability.MemberSnapshot{Cell: "gru"}, Global: []globalview.Region{
		{Cell: "gru", Rollup: &gru}, {Cell: "sjc", Rollup: &sjc}, {Cell: "lab", Rollup: &lab}}}
	var spec mapSpec
	if err := json.Unmarshal([]byte(pageMapJSON(t, fixturePage(t, current, "/"))), &spec); err != nil {
		t.Fatal(err)
	}
	if len(spec.Regions) != 2 || spec.Regions[0].ID != "gru" || !spec.Regions[0].Current || spec.Regions[0].Href != "/regions/gru" {
		t.Fatalf("placed regions = %+v", spec.Regions)
	}
	if len(spec.Links) != 1 || spec.Links[0].Label != "GRU → SJC 45 ms, lag 2 s" || spec.Links[0].State != "ok" {
		t.Fatalf("links = %+v", spec.Links)
	}
}

func TestGlobalMapWorseDirectionWins(t *testing.T) {
	t.Parallel()
	gru := overviewRollup("gru", testNow, []string{"sjc"})
	sjc := overviewRollup("sjc", testNow, nil)
	sjc.Links = []globalview.Link{{Region: "gru", Reach: "error", Error: "tls handshake failed"}}
	current := view{Now: testNow, Global: []globalview.Region{{Cell: "gru", Rollup: &gru}, {Cell: "sjc", Rollup: &sjc}}}
	var spec mapSpec
	if err := json.Unmarshal([]byte(pageMapJSON(t, fixturePage(t, current, "/"))), &spec); err != nil {
		t.Fatal(err)
	}
	if len(spec.Links) != 1 || spec.Links[0].Label != "SJC → GRU tls handshake failed" || spec.Links[0].State != "bad" {
		t.Fatalf("links = %+v", spec.Links)
	}
}

// neverLocal fails the test when a page loads this region's summary.
func neverLocal(t *testing.T) func(context.Context) regionview.Summary {
	return func(context.Context) regionview.Summary {
		t.Error("the page loaded this region's summary")
		return regionview.Summary{}
	}
}

func TestOverviewNeverAsksRegions(t *testing.T) {
	t.Parallel()
	rollup := overviewRollup("gru", testNow, nil)
	global := globalview.NewView("gru", func() []string { return []string{"sjc"} }, func() time.Time { return testNow })
	global.Accept(rollup)
	dashboard := newTestDashboard(Options{Snapshots: fixedSnapshots{snapshot: memberSnapshot()},
		Journal: &Journal{Local: neverLocal(t), Global: global}})
	if body := get(t, dashboard.Handler(), "/").Body.String(); !strings.Contains(body, "GRU") {
		t.Fatal("the overview did not render the global view")
	}
	current := dashboard.load(t.Context(), pages[0], nil, nil)
	if len(current.Global) != 2 || current.LocalSummary != nil {
		t.Fatalf("overview loaded this region: global=%d local=%v", len(current.Global), current.LocalSummary != nil)
	}
}

// budgetCells are the twenty regions of the budget fixture, local gru first.
var budgetCells = strings.Fields("gru sjc fra lhr nrt iad phx ams cdg mad mil zrh arn sin bom syd mel icn yyz jnb")

// twentyRegionView is the TS-805 budget fixture: local gru and nineteen peers,
// each with a full rollup. mel is stale.
func twentyRegionView(now time.Time) *globalview.View {
	cells := budgetCells
	global := globalview.NewView("gru", func() []string { return cells }, func() time.Time { return now })
	for index, cell := range cells {
		var peers []string
		for _, peer := range cells {
			if peer != cell {
				peers = append(peers, peer)
			}
		}
		observed := now
		if cell == "mel" {
			observed = now.Add(-time.Minute)
		}
		rollup := overviewRollup(cell, observed, peers)
		rollup.Scale = budgetScale(cell, index, observed)
		global.Accept(rollup)
	}
	return global
}

// budgetScale is a region's node scaler: every fourth region grows, every
// fourth from the third is saturated, and the rest hold.
func budgetScale(cell string, index int, observed time.Time) *nodescale.Status {
	scale := &nodescale.Status{Schema: nodescale.StatusSchema, Cell: cell, At: observed, Nodes: 12, QuorumNodes: 3,
		PoolNodes: 9, Want: 12, Allowance: 16, AllowanceFresh: true, Action: nodescale.Hold, Pressure: 0.4,
		Signal: nodescale.SignalCPU, Signals: map[nodescale.Signal]float64{nodescale.SignalCPU: 0.4, nodescale.SignalMemory: 0.3},
		Reason: "every signal <= 0.50 on 11 nodes for 10m0s", LastChange: observed.Add(-time.Hour),
		NodeMonthlyCents: 45000, ProjectedCents: 900000, Currency: "USD"}
	switch index % 4 {
	case 1:
		scale.Action, scale.Want, scale.Pressure, scale.Signal = nodescale.Up, 14, 0.9, nodescale.SignalCPU
		scale.Reason = "cpu 0.90 >= 0.80 for 5m0s"
		scale.InFlight = &nodescale.InFlight{ID: cell + "-launch", Kind: nodescale.Up, Step: "launch", Started: observed}
	case 3:
		scale.Saturated, scale.Pressure = true, 0.95
		scale.Reason = "cpu 0.95 >= 0.80 but the allowance is spent"
	}
	return scale
}

func getGzipped(t *testing.T, handler http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Header.Set("Accept-Encoding", "gzip")
	handler.ServeHTTP(recorder, request)
	return recorder
}

func gunzip(t *testing.T, body []byte) []byte {
	t.Helper()
	reader, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestRegionPageBudgetTwentyRegions(t *testing.T) {
	t.Parallel()
	snapshot := memberSnapshot()
	snapshot.Cell = "gru"
	handler := newTestDashboard(Options{Snapshots: fixedSnapshots{snapshot: snapshot},
		Journal: &Journal{Global: twentyRegionView(testNow)}}).Handler()

	started := time.Now()
	response := getGzipped(t, handler, "/regions/gru")
	elapsed := time.Since(started)
	if response.Code != http.StatusOK || response.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("GET /regions/gru = %d, Content-Encoding %q", response.Code, response.Header().Get("Content-Encoding"))
	}
	htmlGzip := len(response.Body.Bytes())
	html := string(gunzip(t, response.Body.Bytes()))
	if !strings.Contains(html, "Node scaling") || !strings.Contains(html, "Recent errors") {
		t.Error("region page lacks its scaling or error section")
	}

	var cssGzip int
	for _, name := range []string{"dashboard.css"} {
		asset := getGzipped(t, handler, assetURL(name))
		if asset.Code != http.StatusOK {
			t.Fatalf("GET %s = %d", name, asset.Code)
		}
		cssGzip += len(asset.Body.Bytes())
	}

	t.Logf("region page (gru): raw %d bytes, gzip %d bytes; CSS gzip %d bytes; total gzip %d bytes; elapsed %s",
		len(html), htmlGzip, cssGzip, htmlGzip+cssGzip, elapsed)
	if elapsed >= 500*time.Millisecond {
		t.Errorf("region page took %s, budget is 500ms", elapsed)
	}
	if htmlGzip+cssGzip >= 100*1024 {
		t.Errorf("region page wire size %d bytes, budget is 100 KiB", htmlGzip+cssGzip)
	}
}

func TestOverviewBudgetTwentyRegions(t *testing.T) {
	t.Parallel()
	snapshot := memberSnapshot()
	snapshot.Cell = "gru"
	dashboard := newTestDashboard(Options{Snapshots: fixedSnapshots{snapshot: snapshot},
		Journal: &Journal{Global: twentyRegionView(testNow)}})
	handler := dashboard.Handler()

	started := time.Now()
	response := getGzipped(t, handler, "/")
	elapsed := time.Since(started)
	if response.Code != http.StatusOK || response.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("GET / = %d, Content-Encoding %q", response.Code, response.Header().Get("Content-Encoding"))
	}
	htmlGzip := len(response.Body.Bytes())
	html := string(gunzip(t, response.Body.Bytes()))
	for _, cell := range budgetCells {
		if !strings.Contains(html, strings.ToUpper(cell)) {
			t.Errorf("overview lacks region %s", strings.ToUpper(cell))
		}
	}
	if !strings.Contains(html, "stale · last seen") {
		t.Error("overview lacks the stale badge for mel")
	}

	var cssGzip int
	for _, name := range []string{"dashboard.css"} {
		asset := getGzipped(t, handler, assetURL(name))
		if asset.Code != http.StatusOK {
			t.Fatalf("GET %s = %d", name, asset.Code)
		}
		cssGzip += len(asset.Body.Bytes())
	}

	t.Logf("overview HTML: raw %d bytes, gzip %d bytes; CSS gzip %d bytes; total gzip %d bytes; elapsed %s",
		len(html), htmlGzip, cssGzip, htmlGzip+cssGzip, elapsed)
	if elapsed >= 500*time.Millisecond {
		t.Errorf("overview took %s, budget is 500ms", elapsed)
	}
	if htmlGzip+cssGzip >= 100*1024 {
		t.Errorf("overview wire size %d bytes, budget is 100 KiB", htmlGzip+cssGzip)
	}
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

func TestOverviewHTTPShowsDatabaseAndErrorFields(t *testing.T) {
	t.Parallel()
	gru := overviewRollup("gru", testNow, nil)
	gru.Databases = []globalview.Database{{ID: "01HZDB4Q7MXYABCDEFGHJKMNPQ", Project: "01HZPRJ0000000000000000000", ReplicationBytesPerSecond: 3072, SentBytesPerSecond: 2048, ReceivedBytesPerSecond: 1024, StorageBytes: 3 << 30, ReadsPerSecond: 12.5, WritesPerSecond: 2, LagSeconds: 1.5,
		Peers: []globalview.DatabasePeer{{Region: "sjc", SentBytesPerSecond: 2048, ReceivedBytesPerSecond: 1024}, {Region: "lhr", SentBytesPerSecond: 1024}, {Region: "gru", SentBytesPerSecond: 1024}, {Region: "nrt", SentBytesPerSecond: 1024}}}}
	gru.Errors = []globalview.Error{{At: testNow, Level: "WARN", Service: "terrabase", Component: "wan", Message: "lag rising", Count: 7, Nodes: []string{"gru-n01", "gru-n02"}}, {At: testNow.Add(-time.Minute), Level: "ERROR", Message: "boom", Count: 1}}
	body := fixturePage(t, view{Global: []globalview.Region{{Cell: "gru", Rollup: &gru}}}, "/")
	for _, want := range []string{"01HZDB4Q7MXY", "01HZDB4Q7MXYABCDEFGHJKMNPQ", "01HZPRJ00000", "2.0 KiB/s", "1.0 KiB/s", "3.0 GiB", "12.5 / 2", "1.5 s", "WARN", "ERROR", "lag rising", "boom", "gru-n01, gru-n02", "NRT 1.0 KiB/s"} {
		if !strings.Contains(body, want) {
			t.Errorf("overview fields lack %q", want)
		}
	}
}

func pageMapJSON(t *testing.T, body string) string {
	t.Helper()
	match := regexp.MustCompile(`<ts-map data-spec="([^"]*)"`).FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatal("overview map missing")
	}
	return html.UnescapeString(match[1])
}
