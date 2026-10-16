package dashboard

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/globalview"
)

func TestNodeEntriesSortKeys(t *testing.T) {
	t.Parallel()
	fraction := func(value float64) *float64 { return &value }
	// a has the lowest CPU and most disk; b the highest CPU and most memory;
	// c has no CPU reading, so it sorts last by CPU.
	regions := []globalview.Region{{Cell: "gru", Rollup: &globalview.Rollup{Nodes: []globalview.Node{
		{Name: "a", CPU: fraction(0.2), MemoryUsedBytes: 1, MemoryBytes: 10, DiskUsedBytes: 9, DiskBytes: 10,
			NetworkRxBps: fraction(1)},
		{Name: "b", CPU: fraction(0.9), MemoryUsedBytes: 9, MemoryBytes: 10, DiskUsedBytes: 1, DiskBytes: 10,
			NetworkRxBps: fraction(1), NetworkTxBps: fraction(1)},
		{Name: "c", DiskUsedBytes: 5, DiskBytes: 10},
	}}}}
	for _, tc := range []struct{ key, want string }{
		{"name", "abc"}, {"cpu", "bac"}, {"memory", "bac"}, {"disk", "acb"}, {"network", "bac"},
	} {
		var got strings.Builder
		for _, entry := range nodeEntries(regions, "", tc.key) {
			got.WriteString(entry.Node.Name)
		}
		if got.String() != tc.want {
			t.Errorf("sort %s = %s, want %s", tc.key, got.String(), tc.want)
		}
	}
}

func TestNewPagerClamps(t *testing.T) {
	t.Parallel()
	if got := newPager(240, 2); got.From != 50 || got.To != 100 || got.Pages != 5 {
		t.Fatalf("page 2 of 240 = %+v", got)
	}
	if got := newPager(240, 99); got.Page != 5 || got.From != 200 || got.To != 240 {
		t.Fatalf("page 99 of 240 = %+v", got)
	}
	if got := newPager(0, 3); got.Page != 1 || got.From != 0 || got.To != 0 || got.Pages != 1 {
		t.Fatalf("empty list = %+v", got)
	}
}

func TestNodesListFilterAndSort(t *testing.T) {
	t.Parallel()
	handler := drillDashboard(t, drillView(testNow))
	if body := get(t, handler, "/nodes?region=sfo").Body.String(); !strings.Contains(body, "/regions/sfo/nodes/sfo-n00") ||
		strings.Contains(body, "/regions/gru/nodes/") || !strings.Contains(body, "Rows 1 – 4 of 4") ||
		!strings.Contains(body, ">stale<") {
		t.Error("GET /nodes?region=sfo does not list only the stale sfo nodes")
	}
	body := get(t, handler, "/nodes?sort=bogus&region=gru!").Body.String()
	if !strings.Contains(body, "Rows 1 – 8 of 8") || !strings.Contains(body, "/regions/gru/nodes/gru-n00") {
		t.Error("invalid sort and region did not fall back to all nodes by name")
	}
}

func TestNodesListPagesTwentyRegions(t *testing.T) {
	t.Parallel()
	handler := newTestDashboard(Options{Snapshots: fixedSnapshots{snapshot: memberSnapshot()},
		Journal: &Journal{Global: twentyRegionView(testNow)}}).Handler()
	first := get(t, handler, "/nodes").Body.String()
	if !strings.Contains(first, "Rows 1 – 50 of 240") || !strings.Contains(first, "Page 1 of 5") ||
		strings.Contains(first, "Previous") || !strings.Contains(first, "Next →") {
		t.Fatal("GET /nodes does not show page 1 of 5")
	}
	second := get(t, handler, "/nodes?page=2").Body.String()
	if !strings.Contains(second, "Rows 51 – 100 of 240") || !strings.Contains(second, ">fra-n02<") ||
		strings.Contains(second, ">fra-n01<") {
		t.Fatal("GET /nodes?page=2 does not show rows 51 to 100")
	}
	kept := get(t, handler, "/nodes?page=2&sort=cpu").Body.String()
	if !strings.Contains(kept, `/nodes?page=1&amp;sort=cpu`) || !strings.Contains(kept, `/nodes?page=3&amp;sort=cpu`) {
		t.Error("previous and next links do not keep the sort")
	}
	last := get(t, handler, "/nodes?page=99").Body.String()
	if !strings.Contains(last, "Page 5 of 5") || !strings.Contains(last, "Rows 201 – 240 of 240") {
		t.Error("page 99 is not clamped to the last page")
	}
	if !strings.Contains(get(t, handler, "/nodes?page=abc").Body.String(), "Page 1 of 5") {
		t.Error("an invalid page is not page 1")
	}
}

func TestVolumesListFilterAndRoutes(t *testing.T) {
	t.Parallel()
	dashboard := newTestDashboard(Options{Snapshots: fixedSnapshots{snapshot: memberSnapshot()},
		Journal: &Journal{Global: drillView(testNow)}})
	handler := dashboard.Handler()
	list := get(t, handler, "/volumes").Body.String()
	if !strings.Contains(list, "<h1>Volumes</h1>") || !strings.Contains(list, "/regions/gru/volumes/gru-vol-0") ||
		!strings.Contains(list, "Rows 1 – 8 of 8") {
		t.Fatal("GET /volumes does not list every region's volumes")
	}
	if sfo := get(t, handler, "/volumes?region=sfo").Body.String(); strings.Contains(sfo, "/regions/gru/volumes/") ||
		!strings.Contains(sfo, "/regions/sfo/volumes/sfo-vol-0") {
		t.Fatal("GET /volumes?region=sfo does not filter to sfo")
	}

	server := newStreamServer(t, dashboard)
	reader, response := openStream(t, server, "/volumes/stream")
	if response.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("/volumes/stream Content-Type = %q", response.Header.Get("Content-Type"))
	}
	if _, data := reader.next(); !strings.Contains(data, "<h1>Volumes</h1>") {
		t.Fatalf("/volumes/stream first patch is not the volumes list: %q", data)
	}

	// /volumes/{id} is the journal's volume detail page, not the list.
	detail := get(t, handler, "/volumes/gru-vol-0").Body.String()
	if !strings.Contains(detail, `href="/storage"`) || strings.Contains(detail, "All volumes") {
		t.Fatal("GET /volumes/{id} did not reach the volume detail page")
	}
}

func TestDrilldownBudgetTwentyRegions(t *testing.T) {
	t.Parallel()
	snapshot := memberSnapshot()
	snapshot.Cell = "gru"
	handler := newTestDashboard(Options{Snapshots: fixedSnapshots{snapshot: snapshot},
		Journal: &Journal{Global: twentyRegionView(testNow)}}).Handler()

	started := time.Now()
	response := getGzipped(t, handler, "/nodes")
	elapsed := time.Since(started)
	if response.Code != http.StatusOK || response.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("GET /nodes = %d, Content-Encoding %q", response.Code, response.Header().Get("Content-Encoding"))
	}
	htmlGzip := len(response.Body.Bytes())
	html := string(gunzip(t, response.Body.Bytes()))

	var cssGzip int
	for _, name := range []string{"dashboard.css"} {
		asset := getGzipped(t, handler, assetURL(name))
		if asset.Code != http.StatusOK {
			t.Fatalf("GET %s = %d", name, asset.Code)
		}
		cssGzip += len(asset.Body.Bytes())
	}

	t.Logf("GET /nodes (20 regions, 50 of 240 rows): HTML raw %d bytes, gzip %d bytes; CSS gzip %d bytes; total gzip %d bytes; elapsed %s",
		len(html), htmlGzip, cssGzip, htmlGzip+cssGzip, elapsed)
	if !strings.Contains(html, "Rows 1 – 50 of 240") {
		t.Error("budget page does not list 50 of 240 rows")
	}
	if elapsed >= 500*time.Millisecond {
		t.Errorf("GET /nodes took %s, budget is 500ms", elapsed)
	}
	if htmlGzip+cssGzip >= 100*1024 {
		t.Errorf("GET /nodes wire size %d bytes, budget is 100 KiB", htmlGzip+cssGzip)
	}
}
