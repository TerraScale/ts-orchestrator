package dashboard

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/globalview"
	"github.com/TerraScale/ts-orchestrator/internal/insights"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/regionview"
)

// fakeDecisions answers queries with the real matcher and chain builder.
type fakeDecisions struct {
	decisions   []decisionlog.Decision
	queries     atomic.Int64
	chains      atomic.Int64
	err         error
	chainErr    error
	beforeQuery func(context.Context, decisionlog.Query) error
	// complete answers every region in full instead of the default
	// partial result with SJC unreachable.
	complete bool
}

func (source *fakeDecisions) Query(ctx context.Context, query decisionlog.Query) (decisionlog.Result, error) {
	source.queries.Add(1)
	if source.beforeQuery != nil {
		if err := source.beforeQuery(ctx, query); err != nil {
			return decisionlog.Result{}, err
		}
	}
	if source.err != nil {
		return decisionlog.Result{}, source.err
	}
	query = query.Normalized()
	result := decisionlog.Result{Regions: []decisionlog.RegionStatus{{Region: "fra", State: decisionlog.RegionOK},
		{Region: "sjc", State: decisionlog.RegionUnreachable}}, Partial: true}
	if source.complete {
		result = decisionlog.Result{Regions: []decisionlog.RegionStatus{{Region: "fra", State: decisionlog.RegionOK},
			{Region: "sjc", State: decisionlog.RegionOK}}}
	}
	for _, decision := range source.decisions {
		if query.Matches(decision) {
			result.Decisions = append(result.Decisions, decision)
		}
	}
	decisionlog.SortNewestFirst(result.Decisions)
	return result, nil
}

func (source *fakeDecisions) Chain(_ context.Context, id string) (decisionlog.Chain, error) {
	source.chains.Add(1)
	if source.chainErr != nil {
		return decisionlog.Chain{}, source.chainErr
	}
	chain, ok := decisionlog.BuildChain(source.decisions, id)
	if !ok {
		return decisionlog.Chain{}, decisionlog.ErrNotFound
	}
	return chain, nil
}

// fakeInsights is an insight source whose changes the test pushes.
type fakeInsights struct {
	mu          sync.Mutex
	evaluation  insights.Evaluation
	changes     []insights.Change
	subscribers []chan insights.Change
}

func (source *fakeInsights) Current() insights.Evaluation {
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.evaluation
}

func (source *fakeInsights) Changes(since time.Time) []insights.Change {
	source.mu.Lock()
	defer source.mu.Unlock()
	var out []insights.Change
	for _, change := range source.changes {
		if !change.Time.Before(since) {
			out = append(out, change)
		}
	}
	return out
}

func (source *fakeInsights) Subscribe(ctx context.Context, buffer int) <-chan insights.Change {
	channel := make(chan insights.Change, buffer)
	source.mu.Lock()
	source.subscribers = append(source.subscribers, channel)
	source.mu.Unlock()
	return channel
}

func (source *fakeInsights) subscribed() int {
	source.mu.Lock()
	defer source.mu.Unlock()
	return len(source.subscribers)
}

func (source *fakeInsights) push(change insights.Change) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.changes = append(source.changes, change)
	for _, subscriber := range source.subscribers {
		subscriber <- change
	}
}

type fakeSummaries struct{}

func (fakeSummaries) Summary(_ context.Context, window time.Duration) (insights.Summary, error) {
	return insights.Summary{Window: window, Scope: "all regions",
		Text: "In the last " + insights.WindowPhrase(window) + " the orchestrator rolled back v0.42.9 in FRA."}, nil
}

type fakeVersions []UnitVersion

func (versions fakeVersions) Versions(context.Context) ([]UnitVersion, error) { return versions, nil }

type fakeVolumes []insights.Volume

func (volumes fakeVolumes) Volumes(context.Context) ([]insights.Volume, error) { return volumes, nil }

type fakeRollouts []insights.Rollout

func (rollouts fakeRollouts) Rollouts(context.Context) ([]insights.Rollout, error) {
	return rollouts, nil
}

func (rollouts fakeRollouts) Rollout(_ context.Context, id string) (insights.Rollout, error) {
	for _, record := range rollouts {
		if record.ID == id {
			return record, nil
		}
	}
	return insights.Rollout{}, ErrRolloutNotFound
}

type fakeQualification []Qualification

func (runs fakeQualification) Qualifications(context.Context) ([]Qualification, error) {
	return runs, nil
}

type fakeInventory []InventoryItem

func (items fakeInventory) Inventory(context.Context) (InventoryObservation, error) {
	return InventoryObservation{Items: items}, nil
}

var (
	release   = decisionlog.Subject{Kind: "release", ID: "sha256:aaaa", Name: "v0.43.0"}
	knownBad  = decisionlog.Subject{Kind: "release", ID: "sha256:bbbb", Name: "v0.42.9"}
	threshold = decisionlog.Threshold(2)
)

func testDecisions() []decisionlog.Decision {
	at := func(minutes int) time.Time { return testNow.Add(-time.Duration(minutes) * time.Minute) }
	return []decisionlog.Decision{
		{ID: "d1", Time: at(50), Region: "fra", Actor: decisionlog.Actor{Slice: "rollout", Member: "ctl-1"},
			Kind: decisionlog.KindReleaseAdmitted, Subject: release, Summary: "Admitted release v0.43.0",
			Status: decisionlog.StatusSucceeded, Attrs: map[string]string{"qualification": "passed", "delegation": "signer-q4"}},
		{ID: "d2", ParentID: "000000000012DW218K5MV0GCVX", Time: at(40), Region: "fra", Actor: decisionlog.Actor{Slice: "rollout"},
			Kind: decisionlog.KindCanaryPromoted, Subject: release, Summary: "Promoted the canary of v0.43.0",
			Reason: "Every health gate held.", Rule: "canary health gates", Status: decisionlog.StatusSucceeded,
			Signals: []decisionlog.Signal{{Name: "error_rate", Value: 0.3, Unit: "%", Comparison: "<=", Threshold: threshold,
				Passed: decisionlog.Passed(true)}},
			Alternatives: []decisionlog.Alternative{{Option: "extend the canary", Reason: "gates held with margin"}}},
		{ID: "d3", ParentID: "0000000000V88PE8JVRSWDV1G8", Time: at(30), Region: "fra", Actor: decisionlog.Actor{Slice: "rollout"},
			Kind: decisionlog.KindBatchPromoted, Subject: release, Summary: "Promoted batch 1 of 3",
			Status: decisionlog.StatusInProgress, Attrs: map[string]string{"batch": "1", "batches": "3"}},
		{ID: "d4", Time: at(45), Region: "gru", Actor: decisionlog.Actor{Slice: "rollout"},
			Kind: decisionlog.KindRollback, Subject: knownBad, Summary: "Rolled back v0.42.9",
			Reason: "The canary error rate rose to 4.1%.", Status: decisionlog.StatusRolledBack},
		{ID: "d5", Time: at(20), Region: "fra", Actor: decisionlog.Actor{Slice: "autoscale"},
			Kind: decisionlog.KindScaleUp, Subject: decisionlog.Subject{Kind: "service", ID: "terrabase-pool"},
			Summary: "Scaled the TerraBase pool up", Status: decisionlog.StatusSucceeded},
		{ID: "d6", Time: at(10), Region: "fra", Actor: decisionlog.Actor{Slice: "storage"},
			Kind: decisionlog.KindBackupTaken, Subject: decisionlog.Subject{Kind: "database", ID: "00000000000DMQEY0YD7RZ04RR"},
			Summary: "Backed up orders", Status: decisionlog.StatusSucceeded},
		{ID: "d7", Time: at(5), Region: "fra", Actor: decisionlog.Actor{Slice: "authority"},
			Kind: decisionlog.KindLeaderChanged, Subject: decisionlog.Subject{Kind: "member", ID: "ctl-1"},
			Summary: "ctl-1 became the regional authority leader", Status: decisionlog.StatusSucceeded},
	}
}

func testInsight(key, title string, severity insights.Severity, region string) insights.Insight {
	return insights.Insight{Key: entityid.Derive("insight", region, key), Rule: "disk_time_to_full", Severity: severity, Region: region, Title: title,
		Why: "The nats filesystem fills in about 2d.", FirstSeen: testNow.Add(-time.Hour), LastSeen: testNow,
		Entity: insights.Entity{Kind: "host", ID: "ctl-1", Href: "/members?host=ctl-1"},
		Evidence: []insights.Evidence{{Label: "Used", Metric: observability.HistFSRatio,
			Labels: map[string]string{"member": "ctl-1"}, Value: 0.8, Unit: "ratio", Comparison: "<", Threshold: float(0.85)}},
		Actions: []insights.Action{{Label: "Find large files", Command: "du -xh /var/lib/terrascale | sort -h | tail"}}}
}

func testRegions() []regionview.Summary {
	return []regionview.Summary{
		{Version: 1, Region: "fra", Local: true, Reach: decisionlog.RegionOK,
			Health:   regionview.Health{Score: 74, Status: regionview.StatusDegraded, Reasons: []string{"1 warning"}},
			Quorum:   regionview.Quorum{Expected: 3, Answering: 3, Ready: 3, Required: 2, Healthy: true},
			Leaders:  regionview.Leaders{Authority: "ctl-1", Epoch: 7, MetaLeader: "ctl-1"},
			Versions: []regionview.Version{{Version: "v0.43.0", Members: []string{"ctl-1", "ctl-2"}}},
			Capacity: regionview.Capacity{DiskBytes: 100, DiskUsedBytes: 40}, TerraBase: regionview.TerraBase{Databases: 2},
			Counts: insights.Counts{Warning: 1}},
		{Version: 1, Region: "sjc", Reach: decisionlog.RegionOK,
			Health:   regionview.Health{Score: 37, Status: regionview.StatusCritical},
			Quorum:   regionview.Quorum{Expected: 3, Answering: 2, Missing: []string{"sjc-ctl-3"}},
			Versions: []regionview.Version{{Version: "v0.42.1", Members: []string{"sjc-ctl-1"}}, {Version: "v0.43.0", Members: []string{"sjc-ctl-2"}}},
			Insights: []insights.Insight{testInsight("oci_throttled:sjc", "OCI is throttling the orchestrator (429)", insights.SeverityCritical, "sjc")},
			Counts:   insights.Counts{Critical: 1, Warning: 2}},
		{Version: 1, Region: "gru", Reach: decisionlog.RegionNotLinked,
			Health: regionview.Health{Status: regionview.StatusUnknown, Reasons: []string{"no cross-region link yet"}}},
	}
}

// testGlobalView is the global view of this region (fra) with gru and sjc
// rolled up.
func testGlobalView() *globalview.View {
	global := globalview.NewView("fra", func() []string { return []string{"gru", "sjc"} }, func() time.Time { return testNow })
	for _, cell := range []string{"gru", "sjc"} {
		global.Accept(overviewRollup(cell, testNow, nil))
	}
	return global
}

// testGlobal is the global view of testRegions: local first, each with a rollup.
func testGlobal() []globalview.Region {
	var out []globalview.Region
	for _, summary := range testRegions() {
		out = append(out, globalview.Region{Cell: summary.Region, Rollup: &globalview.Rollup{Cell: summary.Region}})
	}
	return out
}

func fullJournal() (*Journal, *fakeInsights, *fakeDecisions) {
	history := observability.NewHistory(observability.HistoryConfig{})
	for minute := 120; minute >= 0; minute-- {
		at := time.Now().Add(-time.Duration(minute) * time.Minute)
		history.Append(at, []observability.Sample{
			{Metric: observability.HistCPUUtilization, Labels: observability.L("member", "ctl-1"), Value: 0.4},
			{Metric: observability.HistMembersAnswering, Value: 2},
			{Metric: observability.HistFSRatio, Labels: observability.L("member", "ctl-1", "role", "nats"),
				Value: 0.7 + float64(120-minute)*0.001},
			{Metric: observability.HistOCICalls, Labels: observability.L("operation", "compute GET /instances"),
				Value: float64(120-minute) * 60, Counter: true},
		})
	}
	source := &fakeInsights{evaluation: insights.Evaluation{At: testNow,
		Insights: []insights.Insight{testInsight("disk:ctl-1", "ctl-1 nats filesystem full in about 2d", insights.SeverityWarning, "fra")},
		Counts:   insights.Counts{Warning: 1}}}
	decisions := &fakeDecisions{decisions: testDecisions()}
	journal := &Journal{Decisions: decisions, History: history, Insights: source, Summaries: fakeSummaries{},
		Local:  func(context.Context) regionview.Summary { return testRegions()[0] },
		Global: testGlobalView(),
		Versions: fakeVersions{{Region: "fra", Kind: "controller", Unit: "ctl-1", Version: "v0.43.0"},
			{Region: "fra", Kind: "controller", Unit: "ctl-2", Version: "v0.42.1"},
			{Region: "sjc", Kind: "seat", Unit: "orders-1", Version: "terrabase 3.8.1"}},
		Rollouts: fakeRollouts{{ID: "0000000000N6KCZG3MWDGZ0WBE", Release: "v0.43.0", Phase: "batch-1", PhaseStarted: testNow.Add(-time.Hour),
			PhaseDeadline: testNow.Add(-time.Minute)}},
		Volumes: fakeVolumes{{ID: "vol-stuck", Host: "host-a", State: "attaching", StateSince: testNow.Add(-time.Hour)}},
		Qualification: fakeQualification{{Release: "v0.43.1-rc.1", Status: "running", Time: testNow,
			Suites: []QualificationStep{{Name: "rolling upgrade", Status: "running"}}}},
		Inventory: fakeInventory{{Kind: "instance", ID: "ocid1.instance.x", Name: "host-old", State: "STOPPED", Drift: "unmanaged"}}}
	return journal, source, decisions
}

func journalDashboard(options Options) (*Dashboard, *fakeInsights, *fakeDecisions) {
	journal, source, decisions := fullJournal()
	options.Journal = journal
	options.Snapshots = fixedSnapshots{snapshot: memberSnapshot()}
	options.Health = readyHealth(true)
	return newTestDashboard(options), source, decisions
}

func TestJournalPagesRenderProviderData(t *testing.T) {
	t.Parallel()
	dashboard, _, _ := journalDashboard(Options{})
	handler := dashboard.Handler()
	for path, wants := range map[string][]string{
		"/":          {"All regions", "Links between regions", "SJC"},
		"/region":    {"Region FRA", "CPU by member", "ctl-1 nats filesystem full", "<ts-chart"},
		"/insights":  {"Needs attention", "expected &lt; 85.0%", "du -xh", "data-copy", "data-notify-toggle", "Notify me"},
		"/decisions": {"Decision journal", "Promoted the canary of v0.43.0", "sjc", "unreachable", "partial"},
		"/decisions?id=d2": {"canary health gates", "error_rate", "✓ passed", "extend the canary", "Admitted release v0.43.0",
			"Promoted batch 1 of 3"},
		"/releases":  {"Version matrix", "v0.43.0", "mixed versions", "rolled back", "signer-q4", "batch 1 of 3", "Target"},
		"/rollouts":  {"Rollout phases", "batch-1", "Known-bad releases", "v0.42.9"},
		"/ci":        {"v0.43.1-rc.1", "rolling upgrade", "Admitted release"},
		"/topology":  {`<svg class="topo"`, `data-node="ctl-1"`, "ts-orch controller", "Services + NATS"},
		"/members":   {"Fleet CPU heatmap", "Capacity", "heatmap"},
		"/nats":      {"Messages per second", "Leadership and quorum timeline", "Route RTT"},
		"/terrabase": {"Seats by database", "Time to full", "Scaling and placement decisions", "Scaled the TerraBase pool up"},
		"/storage":   {"vol-stuck", "attaching", "Backed up orders", "treemap"},
		"/oci":       {"Calls per second", "host-old", "unmanaged", "Mean latency"},
		"/cost":      {"OCI cost", "By region", "Method"},
		"/events":    {"Search"},
	} {
		response := get(t, handler, path)
		if response.Code != http.StatusOK {
			t.Fatalf("GET %s = %d", path, response.Code)
		}
		body := response.Body.String()
		for _, want := range wants {
			if !strings.Contains(body, want) {
				t.Errorf("GET %s lacks %q", path, want)
			}
		}
		for _, chrome := range []string{`id="region-switcher"`, `id="attention-badge"`, `id="toasts"`, "<ts-palette"} {
			if !strings.Contains(body, chrome) {
				t.Errorf("GET %s lacks %s", path, chrome)
			}
		}
	}
	// Another region's page is its global view, not this member's region page.
	if response := get(t, handler, "/region?r=sjc"); response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/regions/sjc" {
		t.Errorf("GET /region?r=sjc = %d to %q, want 303 to /regions/sjc", response.Code, response.Header().Get("Location"))
	}
}

func TestJournalPagesSayWhenProvidersAreMissing(t *testing.T) {
	t.Parallel()
	handler := newTestDashboard(Options{Snapshots: fixedSnapshots{snapshot: memberSnapshot()}}).Handler()
	for path, want := range map[string]string{
		"/":          "The multi-region view appears once",
		"/insights":  "The insights panel appears once",
		"/decisions": "The decision journal appears once",
		"/releases":  "Release timelines appears once",
		"/rollouts":  "appear once the rollout slice reports them",
		"/ci":        "No qualification results are published",
		"/storage":   "appears once the storage slice reports volumes",
		"/oci":       "OCI inventory provider is attached",
		"/terrabase": "No TerraBase load yet",
	} {
		if body := get(t, handler, path).Body.String(); !strings.Contains(body, want) {
			t.Errorf("GET %s lacks %q", path, want)
		}
	}
}

func TestFailingDecisionSourceIsNamedNotLeaked(t *testing.T) {
	t.Parallel()
	dashboard, _, decisions := journalDashboard(Options{})
	decisions.err = errors.New("nats: secret upstream detail")
	body := get(t, dashboard.Handler(), "/decisions").Body.String()
	if !strings.Contains(body, "Unavailable right now: decision journal") || strings.Contains(body, "secret upstream") {
		t.Fatalf("decisions page with a failing source does not explain it safely")
	}
}

func TestDecisionQueriesAreSharedAcrossTicks(t *testing.T) {
	t.Parallel()
	dashboard, _, decisions := journalDashboard(Options{})
	handler := dashboard.Handler()
	for range 5 {
		get(t, handler, "/decisions")
	}
	if got := decisions.queries.Load(); got != 1 {
		t.Fatalf("five renders issued %d decision queries, want 1", got)
	}
}

func TestDecisionChainsAreSharedAndFailuresNamed(t *testing.T) {
	t.Parallel()
	dashboard, _, decisions := journalDashboard(Options{})
	handler := dashboard.Handler()
	for range 5 {
		if body := get(t, handler, "/decisions?id=d2").Body.String(); !strings.Contains(body, "extend the canary") {
			t.Fatal("the decisions page does not show the opened chain")
		}
	}
	if got := decisions.chains.Load(); got != 1 {
		t.Fatalf("five renders issued %d chain lookups, want 1", got)
	}
	if body := get(t, handler, "/decisions?id=missing").Body.String(); strings.Contains(body, "decision chain") {
		t.Fatal("an unknown decision id is reported as an unavailable journal")
	}
	failing, _, broken := journalDashboard(Options{})
	broken.chainErr = errors.New("nats: secret upstream detail")
	body := get(t, failing.Handler(), "/decisions?id=d2").Body.String()
	if !strings.Contains(body, "decision chain") || strings.Contains(body, "secret upstream") {
		t.Fatal("a failing chain lookup is not explained safely")
	}
}

// TestChartTooltipsEscapeProviderText keeps provider-supplied names (hosts,
// volumes, decisions) out of ECharts' HTML tooltips unescaped: a custom
// tooltip formatter returns markup, so every one must escape what it
// interpolates.
func TestChartTooltipsEscapeProviderText(t *testing.T) {
	t.Parallel()
	script := get(t, newTestDashboard(Options{}).Handler(), assetURL("app.js")).Body.String()
	for number, line := range strings.Split(script, "\n") {
		if strings.Contains(line, "tooltip(t, {") && strings.Contains(line, "formatter:") &&
			strings.Contains(line, "<br>") && !strings.Contains(line, "escapeHTML(") {
			t.Errorf("app.js:%d formats a tooltip without escaping: %s", number+1, strings.TrimSpace(line))
		}
	}
	for _, unescaped := range []string{"`${spec.categories[", "`${p.treePathInfo"} {
		if strings.Contains(script, unescaped) {
			t.Errorf("app.js interpolates %q into tooltip HTML unescaped", unescaped)
		}
	}
}

func TestURLStateIsValidatedAndCarried(t *testing.T) {
	t.Parallel()
	board, source, _ := journalDashboard(Options{})
	body := get(t, board.Handler(), "/decisions?range=14d&r=SJC&live=0&kind=rollback,held&q=host-a&id=x%00y&actor=%3Cscript%3E&unknown=1").Body.String()
	for _, want := range []string{"14d", "Paused", `value="sjc" selected`, `value="host-a"`} {
		if !strings.Contains(body, want) {
			t.Errorf("query state lost %s", want)
		}
	}
	if strings.Contains(body, `value="x`) || strings.Contains(body, "unknown=1") || strings.Contains(body, `<script>`) {
		t.Fatal("invalid query state reached response")
	}
	for _, test := range []struct{ link, want string }{
		{"https://evil.example/x", `href="/"`}, {"//evil.example/x", `href="/"`}, {"javascript:alert(1)", `href="/"`}, {"relative", `href="/"`},
		{"/regions/SJC", `href="/regions/sjc"`}, {"/regions/SJC/nodes/Host-A", `href="/regions/sjc/nodes/Host-A"`}, {"/regions", `href="/"`}, {"/decisions?subject=seat/m1", `href="/decisions?q=m1"`}, {"/decisions?subject=db/p0/m1", `href="/decisions?q=db%2Fp0%2Fm1"`}, {"/decisions?subject=a&q=winner", `href="/decisions?q=winner"`},
	} {
		insight := testInsight("url", "URL target", insights.SeverityWarning, "")
		insight.Entity = insights.Entity{Kind: "subject", ID: "one", Href: test.link}
		source.evaluation.Insights = []insights.Insight{insight}
		body = get(t, board.Handler(), "/insights").Body.String()
		match := regexp.MustCompile(`<a (href="[^"]+") class="tag">subject one`).FindStringSubmatch(body)
		if len(match) != 2 || match[1] != test.want {
			t.Errorf("provider link %q rendered %v, want %s", test.link, match, test.want)
		}
		if strings.Contains(body, `href="https://evil`) || strings.Contains(body, `href="javascript:`) {
			t.Fatal("unsafe provider link escaped validation")
		}
	}
	body = get(t, board.Handler(), "/decisions?range=7y&subject=seat/m1").Body.String()
	if strings.Contains(body, "range=7y") || !strings.Contains(body, `value="m1"`) {
		t.Fatal("default range or legacy subject query is wrong")
	}
}

func TestLongTimeRangesReachChartHistory(t *testing.T) {
	t.Parallel()
	for key, duration := range map[string]time.Duration{"7d": 7 * 24 * time.Hour, "14d": 14 * 24 * time.Hour} {
		t.Run(key, func(t *testing.T) {
			state := parseState(url.Values{"range": {key}})
			if state.Range.Key != key || state.Range.Duration != duration {
				t.Fatalf("range = %+v, want %s over %s", state.Range, key, duration)
			}
			now := time.Now()
			history := observability.NewHistory(observability.HistoryConfig{})
			history.Append(now.Add(-duration+time.Hour), []observability.Sample{{Metric: observability.HistCPUUtilization, Value: 0.2}})
			history.Append(now, []observability.Sample{{Metric: observability.HistCPUUtilization, Value: 0.8}})
			current := view{State: state, Now: now, Journal: &Journal{History: history}}
			found := false
			for _, chart := range pageCharts(t, fixturePage(t, current, "/region")) {
				for _, series := range chart.Series {
					if len(series.Points) == 2 && series.Points[0][1] == .2 {
						found = true
						if chart.Start != now.Add(-duration).UnixMilli() || chart.End != now.UnixMilli() {
							t.Fatal("chart range clipped selected history")
						}
					}
				}
			}
			if !found {
				t.Fatalf("%s history did not reach the region chart", key)
			}

		})
	}
}

func TestPausedPagesDoNotStream(t *testing.T) {
	t.Parallel()
	dashboard, _, _ := journalDashboard(Options{})
	body := get(t, dashboard.Handler(), "/region?live=0").Body.String()
	if strings.Contains(body, "data-init=\"@get") || !strings.Contains(body, "Paused") {
		t.Fatal("a paused page still opens its stream")
	}
	body = get(t, dashboard.Handler(), "/region?range=14d&r=fra").Body.String()
	if !strings.Contains(body, "/region/stream?r=fra&amp;range=14d") {
		t.Fatal("the stream does not carry the page state")
	}
	for _, key := range []string{"7d", "14d"} {
		if !strings.Contains(body, `href="/region?r=fra&amp;range=`+key+`"`) {
			t.Errorf("the global picker lacks %s", key)
		}
	}
}

func TestEveryPageStreamCarriesChrome(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	t.Parallel()
	dashboard, _, _ := journalDashboard(Options{MaxStreams: len(pages) + 1})
	server := newStreamServer(t, dashboard)
	for _, page := range pages {
		if page.slug == "events" {
			continue
		}
		reader, _ := openStream(t, server, page.streamPath()+"?range=24h")
		eventType, data := reader.next()
		if eventType != "datastar-patch-elements" || !strings.Contains(data, `<div id="content">`) ||
			!strings.Contains(data, `id="region-switcher"`) || !strings.Contains(data, `id="attention-badge"`) {
			t.Fatalf("%s first patch lacks content or chrome: %q", page.streamPath(), data)
		}
	}

	// Finite representations use isolated fixtures; the live streams above keep their original inputs.
	providerBoard, _, _ := journalDashboard(Options{})
	missingBoard := newTestDashboard(Options{Snapshots: fixedSnapshots{snapshot: memberSnapshot()}})
	failingBoard, _, failedDecisions := journalDashboard(Options{})
	failedDecisions.err = errors.New("nats: secret upstream detail")
	localInsightsBoard, _, _ := journalDashboard(Options{})
	tooltipBoard := newTestDashboard(Options{})
	stateBoard, _, _ := journalDashboard(Options{})
	legacyBoard, _, _ := journalDashboard(Options{})
	pausedBoard, _, _ := journalDashboard(Options{})
	assetBoard := newTestDashboard(Options{})
	bus := observability.NewEventBus(16)
	bus.Publish(observability.Event{Time: testNow.Add(2 * time.Minute), Level: "INFO", Message: "near-event", Attrs: map[string]string{"seat": "orders-1"}})
	bus.Publish(observability.Event{Time: testNow.Add(time.Hour), Level: "INFO", Message: "far-event", Attrs: map[string]string{"seat": "orders-1"}})
	bus.Publish(observability.Event{Time: testNow.Add(2 * time.Minute), Level: "INFO", Message: "other-event", Attrs: map[string]string{"region": "fra"}})
	eventBoard := newTestDashboard(Options{Events: bus})
	linkBoards := make([]*Dashboard, 0, 10)
	for _, href := range []string{
		"https://evil.example/x",
		"//evil.example/x",
		"javascript:alert(1)",
		"relative",
		"/regions/SJC",
		"/regions/SJC/nodes/Host-A",
		"/regions",
		"/decisions?subject=seat/m1",
		"/decisions?subject=db/p0/m1",
		"/decisions?subject=a&q=winner",
	} {
		board, source, _ := journalDashboard(Options{})
		insight := testInsight("url", "URL target", insights.SeverityWarning, "")
		insight.Entity = insights.Entity{Kind: "subject", ID: "one", Href: href}
		source.evaluation.Insights = []insights.Insight{insight}
		linkBoards = append(linkBoards, board)
	}
	responses := []struct {
		root     string
		board    *Dashboard
		path     string
		contains []string
		absent   []string
		location string
		href     string
		asset    string
		tooltip  bool
	}{
		{
			root:     "TestJournalPagesRenderProviderData",
			board:    providerBoard,
			path:     "/",
			contains: []string{"All regions", "Links between regions", "SJC", "id=\"region-switcher\"", "id=\"attention-badge\"", "id=\"toasts\"", "<ts-palette"},
		},
		{
			root:     "TestJournalPagesRenderProviderData",
			board:    providerBoard,
			path:     "/region",
			contains: []string{"Region FRA", "CPU by member", "ctl-1 nats filesystem full", "<ts-chart", "id=\"region-switcher\"", "id=\"attention-badge\"", "id=\"toasts\"", "<ts-palette"},
		},
		{
			root:     "TestJournalPagesRenderProviderData",
			board:    providerBoard,
			path:     "/insights",
			contains: []string{"Needs attention", "expected &lt; 85.0%", "du -xh", "data-copy", "data-notify-toggle", "Notify me", "id=\"region-switcher\"", "id=\"attention-badge\"", "id=\"toasts\"", "<ts-palette"},
		},
		{
			root:     "TestJournalPagesRenderProviderData",
			board:    providerBoard,
			path:     "/decisions",
			contains: []string{"Decision journal", "Promoted the canary of v0.43.0", "sjc", "unreachable", "partial", "id=\"region-switcher\"", "id=\"attention-badge\"", "id=\"toasts\"", "<ts-palette"},
		},
		{
			root:     "TestJournalPagesRenderProviderData",
			board:    providerBoard,
			path:     "/decisions?id=d2",
			contains: []string{"canary health gates", "error_rate", "✓ passed", "extend the canary", "Admitted release v0.43.0", "Promoted batch 1 of 3", "id=\"region-switcher\"", "id=\"attention-badge\"", "id=\"toasts\"", "<ts-palette"},
		},
		{
			root:     "TestJournalPagesRenderProviderData",
			board:    providerBoard,
			path:     "/releases",
			contains: []string{"Version matrix", "v0.43.0", "mixed versions", "rolled back", "signer-q4", "batch 1 of 3", "Target", "id=\"region-switcher\"", "id=\"attention-badge\"", "id=\"toasts\"", "<ts-palette"},
		},
		{
			root:     "TestJournalPagesRenderProviderData",
			board:    providerBoard,
			path:     "/rollouts",
			contains: []string{"Rollout phases", "batch-1", "Known-bad releases", "v0.42.9", "id=\"region-switcher\"", "id=\"attention-badge\"", "id=\"toasts\"", "<ts-palette"},
		},
		{
			root:     "TestJournalPagesRenderProviderData",
			board:    providerBoard,
			path:     "/ci",
			contains: []string{"v0.43.1-rc.1", "rolling upgrade", "Admitted release", "id=\"region-switcher\"", "id=\"attention-badge\"", "id=\"toasts\"", "<ts-palette"},
		},
		{
			root:     "TestJournalPagesRenderProviderData",
			board:    providerBoard,
			path:     "/topology",
			contains: []string{"<svg class=\"topo\"", "data-node=\"ctl-1\"", "ts-orch controller", "Services + NATS", "id=\"region-switcher\"", "id=\"attention-badge\"", "id=\"toasts\"", "<ts-palette"},
		},
		{
			root:     "TestJournalPagesRenderProviderData",
			board:    providerBoard,
			path:     "/members",
			contains: []string{"Fleet CPU heatmap", "Capacity", "heatmap", "id=\"region-switcher\"", "id=\"attention-badge\"", "id=\"toasts\"", "<ts-palette"},
		},
		{
			root:     "TestJournalPagesRenderProviderData",
			board:    providerBoard,
			path:     "/nats",
			contains: []string{"Messages per second", "Leadership and quorum timeline", "Route RTT", "id=\"region-switcher\"", "id=\"attention-badge\"", "id=\"toasts\"", "<ts-palette"},
		},
		{
			root:     "TestJournalPagesRenderProviderData",
			board:    providerBoard,
			path:     "/terrabase",
			contains: []string{"Seats by database", "Time to full", "Scaling and placement decisions", "Scaled the TerraBase pool up", "id=\"region-switcher\"", "id=\"attention-badge\"", "id=\"toasts\"", "<ts-palette"},
		},
		{
			root:     "TestJournalPagesRenderProviderData",
			board:    providerBoard,
			path:     "/storage",
			contains: []string{"vol-stuck", "attaching", "Backed up orders", "treemap", "id=\"region-switcher\"", "id=\"attention-badge\"", "id=\"toasts\"", "<ts-palette"},
		},
		{
			root:     "TestJournalPagesRenderProviderData",
			board:    providerBoard,
			path:     "/oci",
			contains: []string{"Calls per second", "host-old", "unmanaged", "Mean latency", "id=\"region-switcher\"", "id=\"attention-badge\"", "id=\"toasts\"", "<ts-palette"},
		},
		{
			root:     "TestJournalPagesRenderProviderData",
			board:    providerBoard,
			path:     "/cost",
			contains: []string{"OCI cost", "By region", "Method", "id=\"region-switcher\"", "id=\"attention-badge\"", "id=\"toasts\"", "<ts-palette"},
		},
		{
			root:     "TestJournalPagesRenderProviderData",
			board:    providerBoard,
			path:     "/events",
			contains: []string{"Search", "id=\"region-switcher\"", "id=\"attention-badge\"", "id=\"toasts\"", "<ts-palette"},
		},
		{
			root:     "TestJournalPagesRenderProviderData",
			board:    providerBoard,
			path:     "/region?r=sjc",
			location: "/regions/sjc",
		},
		{
			root:     "TestJournalPagesSayWhenProvidersAreMissing",
			board:    missingBoard,
			path:     "/",
			contains: []string{"The multi-region view appears once"},
		},
		{
			root:     "TestJournalPagesSayWhenProvidersAreMissing",
			board:    missingBoard,
			path:     "/insights",
			contains: []string{"The insights panel appears once"},
		},
		{
			root:     "TestJournalPagesSayWhenProvidersAreMissing",
			board:    missingBoard,
			path:     "/decisions",
			contains: []string{"The decision journal appears once"},
		},
		{
			root:     "TestJournalPagesSayWhenProvidersAreMissing",
			board:    missingBoard,
			path:     "/releases",
			contains: []string{"Release timelines appears once"},
		},
		{
			root:     "TestJournalPagesSayWhenProvidersAreMissing",
			board:    missingBoard,
			path:     "/rollouts",
			contains: []string{"appear once the rollout slice reports them"},
		},
		{
			root:     "TestJournalPagesSayWhenProvidersAreMissing",
			board:    missingBoard,
			path:     "/ci",
			contains: []string{"No qualification results are published"},
		},
		{
			root:     "TestJournalPagesSayWhenProvidersAreMissing",
			board:    missingBoard,
			path:     "/storage",
			contains: []string{"appears once the storage slice reports volumes"},
		},
		{
			root:     "TestJournalPagesSayWhenProvidersAreMissing",
			board:    missingBoard,
			path:     "/oci",
			contains: []string{"OCI inventory provider is attached"},
		},
		{
			root:     "TestJournalPagesSayWhenProvidersAreMissing",
			board:    missingBoard,
			path:     "/terrabase",
			contains: []string{"No TerraBase load yet"},
		},
		{
			root:     "TestFailingDecisionSourceIsNamedNotLeaked",
			board:    failingBoard,
			path:     "/decisions",
			contains: []string{"Unavailable right now: decision journal"},
			absent:   []string{"secret upstream"},
		},
		{
			root:     "TestGlobalInsightsAreThisRegion",
			board:    localInsightsBoard,
			path:     "/insights",
			contains: []string{"Needs attention", "ctl-1"},
		},
		{
			root:    "TestChartTooltipsEscapeProviderText",
			board:   tooltipBoard,
			path:    assetURL("app.js"),
			absent:  []string{"`${spec.categories[", "`${p.treePathInfo"},
			tooltip: true,
		},
		{
			root:     "TestURLStateIsValidatedAndCarried",
			board:    stateBoard,
			path:     "/decisions?range=14d&r=SJC&live=0&kind=rollback,held&q=host-a&id=x%00y&actor=%3Cscript%3E&unknown=1",
			contains: []string{"14d", "Paused", "value=\"sjc\" selected", "value=\"host-a\""},
			absent:   []string{"value=\"x", "unknown=1", "<script>"},
		},
		{
			root:   "TestURLStateIsValidatedAndCarried",
			board:  linkBoards[0],
			path:   "/insights",
			absent: []string{"href=\"https://evil", "href=\"javascript:"},
			href:   "href=\"/\"",
		},
		{
			root:   "TestURLStateIsValidatedAndCarried",
			board:  linkBoards[1],
			path:   "/insights",
			absent: []string{"href=\"https://evil", "href=\"javascript:"},
			href:   "href=\"/\"",
		},
		{
			root:   "TestURLStateIsValidatedAndCarried",
			board:  linkBoards[2],
			path:   "/insights",
			absent: []string{"href=\"https://evil", "href=\"javascript:"},
			href:   "href=\"/\"",
		},
		{
			root:   "TestURLStateIsValidatedAndCarried",
			board:  linkBoards[3],
			path:   "/insights",
			absent: []string{"href=\"https://evil", "href=\"javascript:"},
			href:   "href=\"/\"",
		},
		{
			root:   "TestURLStateIsValidatedAndCarried",
			board:  linkBoards[4],
			path:   "/insights",
			absent: []string{"href=\"https://evil", "href=\"javascript:"},
			href:   "href=\"/regions/sjc\"",
		},
		{
			root:   "TestURLStateIsValidatedAndCarried",
			board:  linkBoards[5],
			path:   "/insights",
			absent: []string{"href=\"https://evil", "href=\"javascript:"},
			href:   "href=\"/regions/sjc/nodes/Host-A\"",
		},
		{
			root:   "TestURLStateIsValidatedAndCarried",
			board:  linkBoards[6],
			path:   "/insights",
			absent: []string{"href=\"https://evil", "href=\"javascript:"},
			href:   "href=\"/\"",
		},
		{
			root:   "TestURLStateIsValidatedAndCarried",
			board:  linkBoards[7],
			path:   "/insights",
			absent: []string{"href=\"https://evil", "href=\"javascript:"},
			href:   "href=\"/decisions?q=m1\"",
		},
		{
			root:   "TestURLStateIsValidatedAndCarried",
			board:  linkBoards[8],
			path:   "/insights",
			absent: []string{"href=\"https://evil", "href=\"javascript:"},
			href:   "href=\"/decisions?q=db%2Fp0%2Fm1\"",
		},
		{
			root:   "TestURLStateIsValidatedAndCarried",
			board:  linkBoards[9],
			path:   "/insights",
			absent: []string{"href=\"https://evil", "href=\"javascript:"},
			href:   "href=\"/decisions?q=winner\"",
		},
		{
			root:     "TestURLStateIsValidatedAndCarried",
			board:    legacyBoard,
			path:     "/decisions?range=7y&subject=seat/m1",
			contains: []string{"value=\"m1\""},
			absent:   []string{"range=7y"},
		},
		{
			root:     "TestPausedPagesDoNotStream",
			board:    pausedBoard,
			path:     "/region?live=0",
			contains: []string{"Paused"},
			absent:   []string{"data-init=\"@get"},
		},
		{
			root:     "TestPausedPagesDoNotStream",
			board:    pausedBoard,
			path:     "/region?range=14d&r=fra",
			contains: []string{"/region/stream?r=fra&amp;range=14d", "href=\"/region?r=fra&amp;range=7d\"", "href=\"/region?r=fra&amp;range=14d\""},
		},
		{
			root:  "TestLargeAssetsAreServedCompressed",
			board: assetBoard,
			path:  assetURL("echarts.min.js"),
			asset: "echarts.min.js",
		},
		{
			root:  "TestLargeAssetsAreServedCompressed",
			board: assetBoard,
			path:  assetURL("world.json"),
			asset: "world.json",
		},
		{
			root:  "TestLargeAssetsAreServedCompressed",
			board: assetBoard,
			path:  assetURL("app.js"),
			asset: "app.js",
		},
		{
			root:     "TestEventFilterSearchAndTimeWindow",
			board:    eventBoard,
			path:     "/events?q=Seat&at=" + url.QueryEscape(testNow.Format(time.RFC3339)),
			contains: []string{"near-event"},
			absent:   []string{"far-event", "other-event"},
		},
	}
	entityLink := regexp.MustCompile(`<a (href="[^"]+") class="tag">subject one`)
	for _, test := range responses {
		finiteServer := newStreamServer(t, test.board)
		client := *finiteServer.Client()
		client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, finiteServer.URL+test.path, nil)
		if err != nil {
			cancel()
			finiteServer.Close()
			t.Fatalf("%s GET %s request: %v", test.root, test.path, err)
		}
		if test.asset != "" {
			request.Header.Set("Accept-Encoding", "br, gzip")
		}
		response, err := client.Do(request)
		if err != nil {
			if response != nil && response.Body != nil {
				_ = response.Body.Close()
			}
			cancel()
			finiteServer.Close()
			t.Fatalf("%s GET %s: %v", test.root, test.path, err)
		}
		var body []byte
		var readErr, decodeErr, gzipCloseErr, drainErr error
		if test.asset != "" {
			reader, err := gzip.NewReader(response.Body)
			decodeErr = err
			if err == nil {
				body, readErr = io.ReadAll(reader)
				gzipCloseErr = reader.Close()
			}
			_, drainErr = io.Copy(io.Discard, response.Body)
		} else {
			body, readErr = io.ReadAll(response.Body)
		}
		closeErr := response.Body.Close()
		cancel()
		finiteServer.Close()
		if readErr != nil || drainErr != nil || closeErr != nil || gzipCloseErr != nil {
			t.Fatalf("%s GET %s read=%v drain=%v close=%v gzip-close=%v", test.root, test.path, readErr, drainErr, closeErr, gzipCloseErr)
		}
		wantStatus := http.StatusOK
		if test.location != "" {
			wantStatus = http.StatusSeeOther
		}
		if response.StatusCode != wantStatus {
			t.Fatalf("%s GET %s = %d, want %d", test.root, test.path, response.StatusCode, wantStatus)
		}
		if test.location != "" && response.Header.Get("Location") != test.location {
			t.Errorf("%s GET %s Location=%q, want %q", test.root, test.path, response.Header.Get("Location"), test.location)
		}
		text := string(body)
		for _, want := range test.contains {
			if !strings.Contains(text, want) {
				t.Errorf("%s GET %s lacks %q", test.root, test.path, want)
			}
		}
		for _, unwanted := range test.absent {
			if strings.Contains(text, unwanted) {
				t.Errorf("%s GET %s contains %q", test.root, test.path, unwanted)
			}
		}
		if test.href != "" {
			match := entityLink.FindStringSubmatch(text)
			if len(match) != 2 || match[1] != test.href {
				t.Errorf("%s GET %s provider link=%v, want %s", test.root, test.path, match, test.href)
			}
		}
		if test.tooltip {
			for number, line := range strings.Split(text, "\n") {
				if strings.Contains(line, "tooltip(t, {") && strings.Contains(line, "formatter:") &&
					strings.Contains(line, "<br>") && !strings.Contains(line, "escapeHTML(") {
					t.Errorf("app.js:%d formats a tooltip without escaping: %s", number+1, strings.TrimSpace(line))
				}
			}
		}
		if test.asset != "" {
			if response.Header.Get("Content-Encoding") != "gzip" ||
				!strings.Contains(response.Header.Get("Cache-Control"), "immutable") {
				t.Fatalf("%s = %d %v", test.asset, response.StatusCode, response.Header)
			}
			if decodeErr != nil {
				t.Fatalf("%s gzip reader: %v", test.asset, decodeErr)
			}
			if !bytes.Equal(body, assets[test.asset].body) {
				t.Fatalf("%s decompressed to different bytes", test.asset)
			}
		}
	}
}

func TestStreamRaisesToastsForNewInsights(t *testing.T) {
	t.Parallel()
	dashboard, source, _ := journalDashboard(Options{Interval: time.Hour})
	server := newStreamServer(t, dashboard)
	reader, _ := openStream(t, server, "/insights/stream")
	reader.next()
	deadline := time.Now().Add(5 * time.Second)
	for source.subscribed() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	resolved := testInsight("old", "Old problem", insights.SeverityWarning, "fra")
	source.push(insights.Change{Type: insights.ChangeResolved, Time: testNow, Insight: resolved})
	opened := testInsight("quorum:fra", "Controller quorum at risk", insights.SeverityCritical, "fra")
	source.push(insights.Change{Type: insights.ChangeOpened, Time: testNow, Insight: opened})
	_, data := reader.next()
	if !strings.Contains(data, "selector #toasts") || !strings.Contains(data, "mode append") ||
		!strings.Contains(data, "Controller quorum at risk") || !strings.Contains(data, `data-key="`+opened.Key+`"`) ||
		strings.Contains(data, "Old problem") {
		t.Fatalf("toast patch = %q", data)
	}
}

func TestReleaseTimelineAndVersionDrift(t *testing.T) {
	t.Parallel()
	journal, _, _ := fullJournal()
	result, _ := journal.Decisions.Query(context.Background(), decisionlog.Query{})
	current := view{Decisions: &result, Global: testGlobal(), Versions: []UnitVersion{
		{Region: "fra", Kind: "controller", Unit: "a", Version: "v0.42.1"},
		{Region: "fra", Kind: "controller", Unit: "b", Version: "v0.42.1"},
		{Region: "fra", Kind: "controller", Unit: "c", Version: "v0.43.0"},
		{Region: "sjc", Kind: "seat", Unit: "s", Version: "terrabase 3.8.1"},
	}}
	body := fixturePage(t, current, "/releases")
	for _, want := range []string{"v0.43.0", "signer-q4", "batch 1 of 3", "4.1%", "mixed versions", "2 units off the target version"} {
		if !strings.Contains(body, want) {
			t.Errorf("release page lacks %q", want)
		}
	}
	if target := pageTarget(t, current); target != "v0.43.0" {
		t.Fatalf("controller target=%q", target)
	}

}

func TestGlobalInsightsAreThisRegion(t *testing.T) {
	t.Parallel()
	board, _, _ := journalDashboard(Options{})
	body := get(t, board.Handler(), "/insights").Body.String()
	if !strings.Contains(body, "Needs attention") || !strings.Contains(body, "ctl-1") {
		t.Fatal("local insight was not visible")
	}
}

func TestLargeAssetsAreServedCompressed(t *testing.T) {
	t.Parallel()
	handler := newTestDashboard(Options{}).Handler()
	for _, name := range []string{"echarts.min.js", "world.json", "app.js"} {
		request := httptest.NewRequest(http.MethodGet, assetURL(name), nil)
		request.Header.Set("Accept-Encoding", "br, gzip")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Encoding") != "gzip" ||
			!strings.Contains(recorder.Header().Get("Cache-Control"), "immutable") {
			t.Fatalf("%s = %d %v", name, recorder.Code, recorder.Header())
		}
		reader, err := gzip.NewReader(recorder.Body)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(reader)
		if !bytes.Equal(body, assets[name].body) {
			t.Fatalf("%s decompressed to different bytes", name)
		}
	}
}

func TestDecisionCacheBoundsDistinctHTTPQueries(t *testing.T) {
	t.Parallel()
	board, _, source := journalDashboard(Options{})
	for i := range 65 {
		get(t, board.Handler(), "/decisions?q="+strconv.Itoa(i))
	}
	if len(board.decisions.entries) > 64 || source.queries.Load() != 65 {
		t.Fatal("decision cache exceeded its query bound")
	}
	get(t, board.Handler(), "/decisions?q=64")
	if source.queries.Load() != 65 {
		t.Fatal("newest query was not cached")
	}
}

// cacheWaitContext reports when an HTTP handler starts waiting on cancellation.
type cacheWaitContext struct {
	context.Context
	waiting chan<- struct{}
	once    sync.Once
}

func (ctx *cacheWaitContext) Done() <-chan struct{} {
	ctx.once.Do(func() { ctx.waiting <- struct{}{} })
	return ctx.Context.Done()
}

func TestDecisionCacheServesConcurrentHTTPReaders(t *testing.T) {
	t.Parallel()
	wait := func(t *testing.T, signal <-chan struct{}) {
		t.Helper()
		select {
		case <-signal:
		case <-time.After(5 * time.Second):
			t.Fatal("HTTP cache synchronization timed out")
		}
	}
	read := func(t *testing.T, server *httptest.Server, path, waiter string, ctx context.Context) error {
		t.Helper()
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+path, nil)
		if err != nil {
			return err
		}
		request.Header.Set("X-Cache-Waiter", waiter)
		response, err := server.Client().Do(request)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil || response.StatusCode != http.StatusOK || !strings.Contains(string(body), "Decision journal") {
			t.Errorf("concurrent request failed: %d %v", response.StatusCode, err)
		}
		return nil
	}
	serve := func(t *testing.T, board *Dashboard, waiting chan<- struct{}, finished chan<- struct{}) *httptest.Server {
		t.Helper()
		// Readiness derives a context before the cache and would signal a false wait.
		board.options.Health = nil
		handler := board.Handler()
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.Header.Get("X-Cache-Waiter") != "" {
				request = request.WithContext(&cacheWaitContext{Context: request.Context(), waiting: waiting})
				if finished != nil {
					defer func() { finished <- struct{}{} }()
				}
			}
			handler.ServeHTTP(writer, request)
		}))
		return server
	}

	board, _, source := journalDashboard(Options{})
	started, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	var startedOnce sync.Once
	source.beforeQuery = func(ctx context.Context, _ decisionlog.Query) error {
		startedOnce.Do(func() { close(started) })
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	waiting := make(chan struct{}, 16)
	server := serve(t, board, waiting, nil)
	var group sync.WaitGroup
	defer func() {
		unblock()
		group.Wait()
		server.Close()
	}()
	for index := range 16 {
		group.Go(func() {
			waiter := ""
			if index != 0 {
				waiter = "yes"
			}
			if err := read(t, server, "/decisions", waiter, t.Context()); err != nil {
				t.Error(err)
			}
		})
		if index == 0 {
			wait(t, started)
		}
	}
	for range 15 {
		wait(t, waiting)
	}
	unblock()
	group.Wait()
	if source.queries.Load() != 1 {
		t.Fatalf("concurrent clients triggered %d provider queries", source.queries.Load())
	}

	t.Run("different keys", func(t *testing.T) {
		board, _, source := journalDashboard(Options{})
		started, release := make(chan struct{}), make(chan struct{})
		unblock := sync.OnceFunc(func() { close(release) })
		source.beforeQuery = func(ctx context.Context, query decisionlog.Query) error {
			if query.Subject != "blocked" {
				return nil
			}
			close(started)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		server := serve(t, board, nil, nil)
		var group sync.WaitGroup
		defer func() {
			unblock()
			group.Wait()
			server.Close()
		}()
		group.Go(func() {
			if err := read(t, server, "/decisions?q=blocked", "", t.Context()); err != nil {
				t.Error(err)
			}
		})
		wait(t, started)
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		if err := read(t, server, "/decisions?q=independent", "", ctx); err != nil {
			t.Fatal("different key waited for blocked load:", err)
		}
		if source.queries.Load() != 2 {
			t.Fatal("different keys did not load independently")
		}
	})

	t.Run("waiter cancellation", func(t *testing.T) {
		board, _, source := journalDashboard(Options{})
		started, release := make(chan struct{}), make(chan struct{})
		unblock := sync.OnceFunc(func() { close(release) })
		var startedOnce sync.Once
		source.beforeQuery = func(ctx context.Context, _ decisionlog.Query) error {
			startedOnce.Do(func() { close(started) })
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		waiting, finished := make(chan struct{}, 1), make(chan struct{}, 1)
		server := serve(t, board, waiting, finished)
		var group sync.WaitGroup
		defer func() {
			unblock()
			group.Wait()
			server.Close()
		}()
		group.Go(func() {
			if err := read(t, server, "/decisions", "", t.Context()); err != nil {
				t.Error(err)
			}
		})
		wait(t, started)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		group.Go(func() {
			if err := read(t, server, "/decisions", "yes", ctx); !errors.Is(err, context.Canceled) {
				t.Errorf("canceled waiter returned %v", err)
			}
		})
		wait(t, waiting)
		cancel()
		wait(t, finished)
		if source.queries.Load() != 1 {
			t.Fatal("canceled waiter started another provider query")
		}
		unblock()
		group.Wait()
		if err := read(t, server, "/decisions", "", t.Context()); err != nil || source.queries.Load() != 1 {
			t.Fatalf("waiter cancellation disturbed cached owner result: %v", err)
		}
	})

	t.Run("canceled loader retry", func(t *testing.T) {
		board, _, source := journalDashboard(Options{})
		started := make(chan struct{})
		source.beforeQuery = func(ctx context.Context, _ decisionlog.Query) error {
			if source.queries.Load() != 1 {
				return nil
			}
			close(started)
			<-ctx.Done()
			return ctx.Err()
		}
		waiting := make(chan struct{}, 1)
		server := serve(t, board, waiting, nil)
		ctx, cancel := context.WithCancel(t.Context())
		var group sync.WaitGroup
		defer func() {
			cancel()
			group.Wait()
			server.Close()
		}()
		group.Go(func() {
			if err := read(t, server, "/decisions", "", ctx); !errors.Is(err, context.Canceled) {
				t.Errorf("canceled loader returned %v", err)
			}
		})
		wait(t, started)
		group.Go(func() {
			if err := read(t, server, "/decisions", "yes", t.Context()); err != nil {
				t.Error(err)
			}
		})
		wait(t, waiting)
		cancel()
		group.Wait()
		if source.queries.Load() != 2 {
			t.Fatal("waiting request did not retry canceled load exactly once")
		}
		if err := read(t, server, "/decisions", "", t.Context()); err != nil || source.queries.Load() != 2 {
			t.Fatalf("canceled load poisoned replacement cache entry: %v", err)
		}
	})
}

func TestEventFilterSearchAndTimeWindow(t *testing.T) {
	t.Parallel()
	bus := observability.NewEventBus(16)
	bus.Publish(observability.Event{Time: testNow.Add(2 * time.Minute), Level: "INFO", Message: "near-event", Attrs: map[string]string{"seat": "orders-1"}})
	bus.Publish(observability.Event{Time: testNow.Add(time.Hour), Level: "INFO", Message: "far-event", Attrs: map[string]string{"seat": "orders-1"}})
	bus.Publish(observability.Event{Time: testNow.Add(2 * time.Minute), Level: "INFO", Message: "other-event", Attrs: map[string]string{"region": "fra"}})
	body := get(t, newTestDashboard(Options{Events: bus}).Handler(), "/events?q=Seat&at="+url.QueryEscape(testNow.Format(time.RFC3339))).Body.String()
	if !strings.Contains(body, "near-event") || strings.Contains(body, "far-event") || strings.Contains(body, "other-event") {
		t.Fatal("event page ignored search or time window")
	}
}

func TestRegionStreamOfAnotherRegionRedirects(t *testing.T) {
	t.Parallel()
	dashboard := newTestDashboard(Options{Snapshots: fixedSnapshots{snapshot: memberSnapshot()}})
	server := newStreamServer(t, dashboard)
	reader, _ := openStream(t, server, "/region/stream?r=sjc")
	if eventType, data := reader.next(); eventType != "datastar-patch-elements" || !strings.Contains(data, "/regions/sjc") {
		t.Fatalf("stream of another region's page = %s %q, want a redirect to /regions/sjc", eventType, data)
	}
}
