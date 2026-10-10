package dashboard

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/globalview"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionview"
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
			Node: cell + "-n01", Component: "orchestrator", Message: "lease renewal slow"})
	}
	for index := range 5 {
		rollup.Databases = append(rollup.Databases, globalview.Database{Name: fmt.Sprintf("%s-db-%d", cell, index),
			ReplicationBytesPerSecond: float64(1000 * (index + 1)), LagSeconds: 1})
	}
	return rollup
}

func TestOverviewTotalsCountOnlyFreshRegions(t *testing.T) {
	t.Parallel()
	fresh := overviewRollup("gru", testNow, nil)
	fresh.Totals = globalview.Totals{Nodes: 2, Ready: 1, CPUCores: 4, CPUUsedCores: 1.5, MemoryBytes: 8, MemoryUsedBytes: 2}
	fresh.Cost = &globalview.Cost{Currency: "USD", PerHour: 2, MonthForecast: 1000}
	stale := overviewRollup("sfo", testNow.Add(-time.Minute), nil)
	stale.Totals = globalview.Totals{Nodes: 10, Ready: 10, CPUCores: 100, CPUUsedCores: 50}
	regions := []globalview.Region{
		{Cell: "gru", Rollup: &fresh},
		{Cell: "sfo", Rollup: &stale, Stale: true},
		{Cell: "fra"},
	}
	totals := totalsOf(regions)
	if totals.Regions != 3 || totals.Fresh != 1 || totals.Stale != 1 || totals.NoData != 1 {
		t.Fatalf("region counts = %+v", totals)
	}
	if totals.Nodes != 2 || totals.Ready != 1 || totals.CPUCores != 4 || totals.CPUUsed != 1.5 {
		t.Fatalf("stale region leaked into node or CPU totals: %+v", totals)
	}
	if totals.Costed != 1 || totals.PerHour != 2 || totals.MonthForecast != 1000 || totals.Currency != "USD" {
		t.Fatalf("cost totals = %+v", totals)
	}
	tiles := overviewTiles(regions)
	if tiles[0].Value != "3" || tiles[0].Sub != "1 stale · 1 no data" || tiles[0].Status != "warn" {
		t.Fatalf("regions tile = %+v", tiles[0])
	}
	if tiles[6].Value != "2.00 USD" || tiles[6].Sub != "1 of 1 fresh regions report cost" {
		t.Fatalf("cost tile = %+v", tiles[6])
	}
}

func TestOverviewCostIsNotReportedWithoutCost(t *testing.T) {
	t.Parallel()
	rollup := overviewRollup("gru", testNow, nil)
	rollup.Cost = nil
	tiles := overviewTiles([]globalview.Region{{Cell: "gru", Rollup: &rollup}})
	if tiles[6].Value != "not reported" || tiles[7].Value != "not reported" {
		t.Fatalf("cost tiles without cost = %q and %q", tiles[6].Value, tiles[7].Value)
	}
}

func TestRegionCellsMarkStaleAndMissingRegions(t *testing.T) {
	t.Parallel()
	rollup := overviewRollup("gru", testNow, nil)
	rollup.Health = globalview.Health{Status: globalview.Degraded, Reasons: []string{"disk 90%", "lag"}}
	fresh := regionCellsOf(globalview.Region{Cell: "gru", Rollup: &rollup}, testNow)
	if fresh.Health != "warn" || fresh.HealthLabel != globalview.Degraded || fresh.Reasons != "disk 90%; lag" {
		t.Fatalf("fresh health = %+v", fresh)
	}
	if fresh.Nodes != "12 / 12" || fresh.Autoscale != "3 / 4 at goal" || fresh.Stale != "" {
		t.Fatalf("fresh row = %+v", fresh)
	}
	stale := regionCellsOf(globalview.Region{Cell: "gru", Rollup: &rollup, Stale: true}, testNow.Add(time.Minute))
	if stale.Health != "idle" || stale.HealthLabel != "unknown" || stale.Stale != "stale · last seen 1m ago" {
		t.Fatalf("stale row = %+v", stale)
	}
	missing := regionCellsOf(globalview.Region{Cell: "fra"}, testNow)
	if missing.Health != "idle" || missing.HealthLabel != "no data" || missing.Nodes != "—" || missing.CPU != "—" {
		t.Fatalf("missing row = %+v", missing)
	}
}

func TestLinkMatrixLooksUpEachDirection(t *testing.T) {
	t.Parallel()
	gru := overviewRollup("gru", testNow, []string{"sfo"})
	gru.Links = append(gru.Links, globalview.Link{Region: "fra", Reach: "error", Error: "timeout"})
	regions := []globalview.Region{{Cell: "gru", Rollup: &gru}, {Cell: "sfo"}, {Cell: "fra"}}
	matrix := linkMatrix(regions)
	if strings.Join(matrix.Headers, ",") != `From \ To,GRU,SFO,FRA` || len(matrix.Rows) != 3 {
		t.Fatalf("headers = %v, rows = %d", matrix.Headers, len(matrix.Rows))
	}
	to := matrix.Rows[0]
	if to[0].Text != "GRU" || to[1].Text != "—" || to[2].Text != "40 ms, lag 2 s" || to[2].Status != "ok" {
		t.Fatalf("gru to sfo = %+v", to[2])
	}
	if to[3].Status != "bad" || to[3].Title != "timeout" {
		t.Fatalf("gru to fra = %+v", to[3])
	}
	if matrix.Rows[1][1].Text != "·" || matrix.Rows[2][1].Text != "·" {
		t.Fatalf("regions without a rollup should show missing cells: %+v", matrix.Rows)
	}
}

func TestDataTableRendersEmptyNoteOrRows(t *testing.T) {
	t.Parallel()
	var out strings.Builder
	if err := dataTable(table{Empty: "nothing yet"}).Render(t.Context(), &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != `<p class="empty">nothing yet</p>` {
		t.Fatalf("empty table = %q", out.String())
	}
	out.Reset()
	rows := table{Caption: "Sizes", Headers: []string{"Name", "Value"},
		Rows: [][]cell{{{Text: "gru", Href: "/regions/gru"}, textCell("12")}}}
	if err := dataTable(rows).Render(t.Context(), &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`<th scope="row"`, `<a href="/regions/gru">gru</a>`, `<th scope="col">Value</th>`, `<td title="">12`} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("table lacks %q in %s", want, out.String())
		}
	}
}

func TestTopDatabasesAndErrorsMergeFreshRegions(t *testing.T) {
	t.Parallel()
	gru := overviewRollup("gru", testNow, nil)
	sfo := overviewRollup("sfo", testNow, nil)
	sfo.Databases = append(sfo.Databases, globalview.Database{Name: "big", ReplicationBytesPerSecond: 1 << 40})
	sfo.Errors = append(sfo.Errors, globalview.Error{At: testNow.Add(time.Second), Message: "newest"})
	stale := overviewRollup("fra", testNow.Add(-time.Minute), nil)
	stale.Databases = append(stale.Databases, globalview.Database{Name: "stale-big", ReplicationBytesPerSecond: 1 << 50})
	regions := []globalview.Region{{Cell: "gru", Rollup: &gru}, {Cell: "sfo", Rollup: &sfo}, {Cell: "fra", Rollup: &stale, Stale: true}}

	databases := topDatabases(regions)
	if len(databases) != overviewTop || databases[0].Name != "big" || databases[0].Region != "sfo" {
		t.Fatalf("databases = %d, first %+v", len(databases), databases[0])
	}
	for index := 1; index < len(databases); index++ {
		if databases[index].ReplicationBytesPerSecond > databases[index-1].ReplicationBytesPerSecond {
			t.Fatalf("databases not sorted by bandwidth at %d", index)
		}
	}
	errs := recentErrors(regions)
	if len(errs) != overviewTop || errs[0].Message != "newest" || errs[0].Region != "sfo" {
		t.Fatalf("errors = %d, first %+v", len(errs), errs[0])
	}
	if len(topDatabases(nil)) != 0 || len(recentErrors(nil)) != 0 {
		t.Fatal("no regions should merge to empty lists")
	}
}

func TestGlobalMapPlacesKnownRegionsOnly(t *testing.T) {
	t.Parallel()
	gru := overviewRollup("gru", testNow, []string{"sfo", "lab"})
	gru.Links[0].RTTMillis = floatPtr(45)
	gru.Links[0].LagSeconds = floatPtr(2)
	sfo := overviewRollup("sfo", testNow, nil)
	sfo.Links = nil
	lab := overviewRollup("lab", testNow, nil)
	current := view{Now: testNow, Local: &observability.MemberSnapshot{Cell: "gru"}, Global: []globalview.Region{
		{Cell: "gru", Rollup: &gru}, {Cell: "sfo", Rollup: &sfo}, {Cell: "lab", Rollup: &lab}}}
	var spec mapSpec
	if err := json.Unmarshal([]byte(globalMapJSON(current)), &spec); err != nil {
		t.Fatal(err)
	}
	if len(spec.Regions) != 2 || spec.Regions[0].ID != "gru" || !spec.Regions[0].Current || spec.Regions[0].Href != "/regions/gru" {
		t.Fatalf("placed regions = %+v", spec.Regions)
	}
	if len(spec.Links) != 1 || spec.Links[0].Label != "GRU → SFO 45 ms, lag 2 s" || spec.Links[0].State != "ok" {
		t.Fatalf("links = %+v", spec.Links)
	}
}

func TestGlobalMapWorseDirectionWins(t *testing.T) {
	t.Parallel()
	gru := overviewRollup("gru", testNow, []string{"sfo"})
	sfo := overviewRollup("sfo", testNow, nil)
	sfo.Links = []globalview.Link{{Region: "gru", Reach: "error", Error: "tls handshake failed"}}
	current := view{Now: testNow, Global: []globalview.Region{{Cell: "gru", Rollup: &gru}, {Cell: "sfo", Rollup: &sfo}}}
	var spec mapSpec
	if err := json.Unmarshal([]byte(globalMapJSON(current)), &spec); err != nil {
		t.Fatal(err)
	}
	if len(spec.Links) != 1 || spec.Links[0].Label != "SFO → GRU tls handshake failed" || spec.Links[0].State != "bad" {
		t.Fatalf("links = %+v", spec.Links)
	}
}

// noFanout fails the test when the overview asks a region for anything.
type noFanout struct{ t *testing.T }

func (fake noFanout) Regions(context.Context) []regionview.Summary {
	fake.t.Error("the overview asked every region for a summary")
	return nil
}

func (fake noFanout) Region(context.Context, string) (regionview.Summary, error) {
	fake.t.Error("the overview asked one region for a summary")
	return regionview.Summary{}, errors.New("not called")
}

func TestOverviewNeverAsksRegions(t *testing.T) {
	t.Parallel()
	rollup := overviewRollup("gru", testNow, nil)
	global := globalview.NewView("gru", func() []string { return []string{"sfo"} }, func() time.Time { return testNow })
	global.Accept(rollup)
	dashboard := newTestDashboard(Options{Snapshots: fixedSnapshots{snapshot: memberSnapshot()},
		Journal: &Journal{Regions: noFanout{t}, Global: global}})
	if body := get(t, dashboard.Handler(), "/").Body.String(); !strings.Contains(body, "GRU") {
		t.Fatal("the overview did not render the global view")
	}
	current := dashboard.load(t.Context(), pages[0], nil, nil)
	if len(current.Global) != 2 || current.Regions != nil {
		t.Fatalf("overview loaded regions: global=%d regions=%d", len(current.Global), len(current.Regions))
	}
}

// budgetCells are the twenty regions of the budget fixture, local gru first.
var budgetCells = strings.Fields("gru sfo fra lhr nrt iad phx ams cdg mad mil zrh arn sin bom syd mel icn yyz jnb")

// twentyRegionView is the TS-805 budget fixture: local gru and nineteen peers,
// each with a full rollup. mel is stale.
func twentyRegionView(now time.Time) *globalview.View {
	cells := budgetCells
	global := globalview.NewView("gru", func() []string { return cells }, func() time.Time { return now })
	for _, cell := range cells {
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
		global.Accept(rollup)
	}
	return global
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
	for _, name := range []string{"pico.min.css", "dashboard.css"} {
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
