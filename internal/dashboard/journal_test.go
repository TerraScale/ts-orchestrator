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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/insights"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionview"
)

// fakeDecisions answers queries with the real matcher and chain builder.
type fakeDecisions struct {
	decisions []decisionlog.Decision
	queries   atomic.Int64
	err       error
}

func (source *fakeDecisions) Query(_ context.Context, query decisionlog.Query) (decisionlog.Result, error) {
	source.queries.Add(1)
	if source.err != nil {
		return decisionlog.Result{}, source.err
	}
	query = query.Normalized()
	result := decisionlog.Result{Regions: []decisionlog.RegionStatus{{Region: "fra", State: decisionlog.RegionOK},
		{Region: "sfo", State: decisionlog.RegionUnreachable}}, Partial: true}
	for _, decision := range source.decisions {
		if query.Matches(decision) {
			result.Decisions = append(result.Decisions, decision)
		}
	}
	decisionlog.SortNewestFirst(result.Decisions)
	return result, nil
}

func (source *fakeDecisions) Chain(_ context.Context, id string) (decisionlog.Chain, error) {
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

type fakeRegions []regionview.Summary

func (regions fakeRegions) Regions(context.Context) []regionview.Summary { return regions }
func (regions fakeRegions) Region(_ context.Context, name string) (regionview.Summary, error) {
	for _, summary := range regions {
		if summary.Region == name {
			return summary, nil
		}
	}
	return regionview.Summary{}, errors.New("unknown")
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

type fakeQualification []Qualification

func (runs fakeQualification) Qualifications(context.Context) ([]Qualification, error) {
	return runs, nil
}

type fakeInventory []InventoryItem

func (items fakeInventory) Inventory(context.Context) ([]InventoryItem, error) { return items, nil }

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
		{ID: "d2", ParentID: "d1", Time: at(40), Region: "fra", Actor: decisionlog.Actor{Slice: "rollout"},
			Kind: decisionlog.KindCanaryPromoted, Subject: release, Summary: "Promoted the canary of v0.43.0",
			Reason: "Every health gate held.", Rule: "canary health gates", Status: decisionlog.StatusSucceeded,
			Signals: []decisionlog.Signal{{Name: "error_rate", Value: 0.3, Unit: "%", Comparison: "<=", Threshold: threshold,
				Passed: decisionlog.Passed(true)}},
			Alternatives: []decisionlog.Alternative{{Option: "extend the canary", Reason: "gates held with margin"}}},
		{ID: "d3", ParentID: "d2", Time: at(30), Region: "fra", Actor: decisionlog.Actor{Slice: "rollout"},
			Kind: decisionlog.KindBatchPromoted, Subject: release, Summary: "Promoted batch 1 of 3",
			Status: decisionlog.StatusInProgress, Attrs: map[string]string{"batch": "1", "batches": "3"}},
		{ID: "d4", Time: at(45), Region: "gru", Actor: decisionlog.Actor{Slice: "rollout"},
			Kind: decisionlog.KindRollback, Subject: knownBad, Summary: "Rolled back v0.42.9",
			Reason: "The canary error rate rose to 4.1%.", Status: decisionlog.StatusRolledBack},
		{ID: "d5", Time: at(20), Region: "fra", Actor: decisionlog.Actor{Slice: "autoscale"},
			Kind: decisionlog.KindScaleUp, Subject: decisionlog.Subject{Kind: "service", ID: "terrabase-pool"},
			Summary: "Scaled the TerraBase pool up", Status: decisionlog.StatusSucceeded},
		{ID: "d6", Time: at(10), Region: "fra", Actor: decisionlog.Actor{Slice: "storage"},
			Kind: decisionlog.KindBackupTaken, Subject: decisionlog.Subject{Kind: "database", ID: "orders"},
			Summary: "Backed up orders", Status: decisionlog.StatusSucceeded},
		{ID: "d7", Time: at(5), Region: "fra", Actor: decisionlog.Actor{Slice: "authority"},
			Kind: decisionlog.KindLeaderChanged, Subject: decisionlog.Subject{Kind: "member", ID: "ctl-1"},
			Summary: "ctl-1 became the regional authority leader", Status: decisionlog.StatusSucceeded},
	}
}

func testInsight(key, title string, severity insights.Severity, region string) insights.Insight {
	return insights.Insight{Key: key, Rule: "disk_time_to_full", Severity: severity, Region: region, Title: title,
		Why: "The nats filesystem fills in about 2d.", FirstSeen: testNow.Add(-time.Hour), LastSeen: testNow,
		Entity: insights.Entity{Kind: "host", ID: "ctl-1", Href: "/members?host=ctl-1"},
		Evidence: []insights.Evidence{{Label: "Used", Metric: observability.HistFSRatio,
			Labels: map[string]string{"member": "ctl-1"}, Value: 0.8, Unit: "ratio", Comparison: "<", Threshold: float(0.85)}},
		Actions: []insights.Action{{Label: "Find large files", Command: "du -xh /var/lib/terrascale | sort -h | tail"}}}
}

func testRegions() fakeRegions {
	return fakeRegions{
		{Version: 1, Region: "fra", Local: true, Reach: decisionlog.RegionOK,
			Health:   regionview.Health{Score: 74, Status: regionview.StatusDegraded, Reasons: []string{"1 warning"}},
			Quorum:   regionview.Quorum{Expected: 3, Answering: 3, Ready: 3, Required: 2, Healthy: true},
			Leaders:  regionview.Leaders{Authority: "ctl-1", Epoch: 7, MetaLeader: "ctl-1"},
			Versions: []regionview.Version{{Version: "v0.43.0", Members: []string{"ctl-1", "ctl-2"}}},
			Capacity: regionview.Capacity{DiskBytes: 100, DiskUsedBytes: 40}, TerraBase: regionview.TerraBase{Databases: 2},
			Counts: insights.Counts{Warning: 1}},
		{Version: 1, Region: "sfo", Reach: decisionlog.RegionOK,
			Health:   regionview.Health{Score: 37, Status: regionview.StatusCritical},
			Quorum:   regionview.Quorum{Expected: 3, Answering: 2, Missing: []string{"sfo-ctl-3"}},
			Versions: []regionview.Version{{Version: "v0.42.1", Members: []string{"sfo-ctl-1"}}, {Version: "v0.43.0", Members: []string{"sfo-ctl-2"}}},
			Insights: []insights.Insight{testInsight("oci_throttled:sfo", "OCI is throttling the orchestrator (429)", insights.SeverityCritical, "sfo")},
			Counts:   insights.Counts{Critical: 1, Warning: 2}},
		{Version: 1, Region: "gru", Reach: decisionlog.RegionNotLinked,
			Health: regionview.Health{Status: regionview.StatusUnknown, Reasons: []string{"no cross-region link yet"}}},
	}
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
		Regions: testRegions(),
		Versions: fakeVersions{{Region: "fra", Kind: "controller", Unit: "ctl-1", Version: "v0.43.0"},
			{Region: "fra", Kind: "controller", Unit: "ctl-2", Version: "v0.42.1"},
			{Region: "sfo", Kind: "seat", Unit: "orders-1", Version: "terrabase 3.8.1"}},
		Rollouts: fakeRollouts{{ID: "ro-1", Release: "v0.43.0", Phase: "batch-1", PhaseStarted: testNow.Add(-time.Hour),
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
		"/": {"All regions", "FRA", "SFO", "GRU", "not linked yet", "OCI is throttling the orchestrator", "<ts-map",
			"world.json", "<ts-timeline", "rolled back v0.42.9", "Regions side by side", "mixed versions", "missing sfo-ctl-3"},
		"/region":       {"Region FRA", "CPU by member", "ctl-1 nats filesystem full", "<ts-chart"},
		"/region?r=sfo": {"Region SFO", "served by that region", "OCI is throttling"},
		"/insights":     {"Needs attention", "expected &lt; 85.0%", "du -xh", "data-copy", "data-notify-toggle", "Notify me"},
		"/decisions":    {"Decision journal", "Promoted the canary of v0.43.0", "sfo", "unreachable", "partial"},
		"/decisions?id=d2": {"canary health gates", "error_rate", "✓ passed", "extend the canary", "Admitted release v0.43.0",
			"Promoted batch 1 of 3"},
		"/releases":  {"Version matrix", "v0.43.0", "mixed versions", "rolled back", "signer-q4", "batch 1 of 3", "Target"},
		"/rollouts":  {"Rollout phases", "batch-1", "Known-bad releases", "v0.42.9"},
		"/ci":        {"v0.43.1-rc.1", "rolling upgrade", "Admitted release"},
		"/topology":  {"<ts-topology", "region:fra", "member:fra:ctl-1", "seat:fra:s1", "NATS route"},
		"/members":   {"Fleet CPU heatmap", "Capacity", "heatmap"},
		"/nats":      {"Messages per second", "Leadership and quorum timeline", "Route RTT"},
		"/terrabase": {"Seats by database", "Time to full", "Scaling and placement decisions", "Scaled the TerraBase pool up"},
		"/storage":   {"vol-stuck", "attaching", "Backed up orders", "treemap"},
		"/oci":       {"Calls per second", "host-old", "unmanaged", "Mean latency"},
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
		"/terrabase": "does not export per-seat replication lag",
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
		get(t, handler, "/")
	}
	if got := decisions.queries.Load(); got != 1 {
		t.Fatalf("five renders issued %d decision queries, want 1", got)
	}
}

func TestURLStateIsValidatedAndCarried(t *testing.T) {
	t.Parallel()
	state := parseState(url.Values{"range": {"24h"}, "r": {"SFO"}, "live": {"0"}, "kind": {"rollback,held"},
		"q": {"host-a"}, "id": {"x\x00y"}, "actor": {"<script>"}, "unknown": {"1"}})
	if state.Range.Key != "24h" || state.Region != "sfo" || state.Live {
		t.Fatalf("shared state = %+v", state)
	}
	if state.param("kind") != "rollback,held" || state.param("q") != "host-a" || state.param("id") != "" ||
		state.param("actor") != "" || state.param("unknown") != "" {
		t.Fatalf("page params = %v", state.Params)
	}
	if link := state.link("/decisions", "id", "d1"); link != "/decisions?id=d1&live=0&r=sfo&range=24h" {
		t.Fatalf("link = %s", link)
	}
	if link := state.keep("/decisions", "kind", ""); !strings.Contains(link, "q=host-a") || strings.Contains(link, "kind=") {
		t.Fatalf("keep = %s", link)
	}
	if parseState(url.Values{"range": {"7y"}}).Range.Key != defaultRange {
		t.Fatal("an unknown range was accepted")
	}
	for _, unsafe := range []string{"https://evil.example/x", "//evil.example/x", "javascript:alert(1)", "relative"} {
		if got := state.adopt(unsafe, ""); got != "/" {
			t.Errorf("adopt(%q) = %q", unsafe, got)
		}
	}
	if got := state.adopt("/members?host=a", "gru"); got != "/members?host=a&live=0&r=sfo&range=24h" {
		t.Errorf("adopt kept the selected region over the entity's: %s", got)
	}
	plain := parseState(url.Values{})
	if got := plain.adopt("/members?host=a", "gru"); got != "/members?host=a&r=gru" {
		t.Errorf("adopt = %s", got)
	}
}

func TestPausedPagesDoNotStream(t *testing.T) {
	t.Parallel()
	dashboard, _, _ := journalDashboard(Options{})
	body := get(t, dashboard.Handler(), "/region?live=0").Body.String()
	if strings.Contains(body, "data-init=\"@get") || !strings.Contains(body, "Paused") {
		t.Fatal("a paused page still opens its stream")
	}
	body = get(t, dashboard.Handler(), "/region?range=6h&r=fra").Body.String()
	if !strings.Contains(body, "/region/stream?r=fra&amp;range=6h") {
		t.Fatal("the stream does not carry the page state")
	}
}

func TestEveryPageStreamCarriesChrome(t *testing.T) {
	t.Parallel()
	dashboard, _, _ := journalDashboard(Options{})
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
		!strings.Contains(data, "Controller quorum at risk") || !strings.Contains(data, `data-key="quorum:fra"`) ||
		strings.Contains(data, "Old problem") {
		t.Fatalf("toast patch = %q", data)
	}
}

func TestReleaseTimelineAndVersionDrift(t *testing.T) {
	t.Parallel()
	journal, _, _ := fullJournal()
	result, _ := journal.Decisions.Query(context.Background(), decisionlog.Query{})
	current := view{Decisions: &result, Regions: testRegions(), Versions: []UnitVersion{
		{Region: "fra", Kind: "controller", Unit: "a", Version: "v0.42.1"},
		{Region: "fra", Kind: "controller", Unit: "b", Version: "v0.42.1"},
		{Region: "fra", Kind: "controller", Unit: "c", Version: "v0.43.0"},
		{Region: "sfo", Kind: "seat", Unit: "s", Version: "terrabase 3.8.1"},
	}}
	releases := current.releases()
	if len(releases) != 2 {
		t.Fatalf("releases = %d", len(releases))
	}
	byName := map[string]releaseView{}
	for _, release := range releases {
		byName[release.Name] = release
	}
	running := byName["v0.43.0"]
	if running.Status != "run" || len(running.Lanes) != 1 || running.Lanes[0].Region != "fra" {
		t.Fatalf("v0.43.0 = %+v", running)
	}
	steps := map[string]releaseStep{}
	for _, step := range running.Lanes[0].Steps {
		steps[step.Stage] = step
	}
	if steps["qualified"].Label != "passed" || steps["signed"].Label != "signer-q4" || steps["canary"].Status != "ok" ||
		steps["batches"].Label != "batch 1 of 3" || steps["batches"].Status != "run" || steps["outcome"].Decision != nil {
		t.Fatalf("v0.43.0 steps = %+v", steps)
	}
	if bad := current.knownBad(); len(bad) != 1 || bad[0].Name != "v0.42.9" || !strings.Contains(bad[0].Reason, "4.1%") {
		t.Fatalf("known bad = %+v", bad)
	}
	// The newest healthy release is the target even though fewer units run it.
	if target := current.targetVersion("controller"); target != "v0.43.0" {
		t.Fatalf("controller target = %q", target)
	}
	if cell := current.versionCell("fra", "controller"); !cell.Drift || len(cell.Versions) != 2 || cell.Total != 3 {
		t.Fatalf("fra controllers = %+v", cell)
	}
	if cell := current.versionCell("sfo", "seat"); cell.Drift {
		t.Fatalf("a single on-target seat drifted: %+v", cell)
	}
	if drifted := current.driftedUnits(); len(drifted) != 2 {
		t.Fatalf("drifted = %+v", drifted)
	}
}

func TestGlobalInsightsMergeRegionsAndCounts(t *testing.T) {
	t.Parallel()
	journal, source, _ := fullJournal()
	evaluation := source.Current()
	current := view{Journal: journal, Regions: testRegions(), Evaluation: &evaluation}
	merged := current.globalInsights()
	if len(merged) != 2 || merged[0].Severity != insights.SeverityCritical || merged[0].Region != "sfo" {
		t.Fatalf("merged = %+v", merged)
	}
	// SFO lists one insight but counts three; the badge counts all.
	if counts := current.attention(); counts.Critical != 1 || counts.Warning != 3 {
		t.Fatalf("counts = %+v", counts)
	}
}

func TestForecastsAndHeatmaps(t *testing.T) {
	t.Parallel()
	start := float64(testNow.Add(-10 * time.Hour).UnixMilli())
	var points [][2]float64
	for hour := range 10 {
		points = append(points, [2]float64{start + float64(hour)*3600_000, 0.5 + 0.01*float64(hour)})
	}
	full, ok := timeToFull(points)
	if !ok || full < 40*time.Hour || full > 42*time.Hour {
		t.Fatalf("time to full = %v %v", full, ok)
	}
	if _, ok := timeToFull(points[:2]); ok {
		t.Fatal("two points made a forecast")
	}
	flat := [][2]float64{{0, 0.5}, {1000, 0.5}, {2000, 0.5}}
	if _, ok := timeToFull(flat); ok {
		t.Fatal("a flat series has a time to full")
	}
	current := view{Now: testNow, State: parseState(url.Values{"range": {"1h"}})}
	series := []chartSeries{{Name: "a", Points: [][2]float64{{float64(testNow.Add(-30 * time.Minute).UnixMilli()), 0.5},
		{float64(testNow.Add(-30*time.Minute).UnixMilli()) + 1, 0.7}, {float64(testNow.Add(-2 * time.Hour).UnixMilli()), 9}}}}
	spec := current.heatmap("percent", series, "none")
	if len(spec.Heat) != 1 || spec.Heat[0][2] != 0.6 || spec.Step != time.Hour.Milliseconds()/heatColumns {
		t.Fatalf("heatmap = %+v", spec)
	}
	if empty := current.heatmap("percent", nil, "no data"); empty.Empty != "no data" {
		t.Fatal("an empty heatmap has no empty state")
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
	if acceptsGzip("gzip;q=0") || !acceptsGzip("deflate, gzip") {
		t.Fatal("acceptsGzip")
	}
}

func TestKeyedCacheBoundsEntries(t *testing.T) {
	t.Parallel()
	cache := newKeyedCache[int](time.Hour, 2)
	loads := 0
	load := func(context.Context) (int, error) { loads++; return loads, nil }
	for _, key := range []string{"a", "a", "b", "c", "a"} {
		_, _ = cache.get(context.Background(), key, load)
	}
	if len(cache.entries) > 2 || loads < 3 {
		t.Fatalf("entries = %d loads = %d", len(cache.entries), loads)
	}
}

func TestKeyedCacheIsSafeForConcurrentStreams(t *testing.T) {
	t.Parallel()
	cache := newKeyedCache[int](time.Millisecond, 4)
	var group sync.WaitGroup
	for worker := range 8 {
		group.Go(func() {
			for index := range 200 {
				key := string(rune('a' + (worker+index)%6))
				_, _ = cache.get(context.Background(), key, func(context.Context) (int, error) { return index, nil })
			}
		})
	}
	group.Wait()
}

func TestEventFilterSearchAndTimeWindow(t *testing.T) {
	t.Parallel()
	filter := parseEventFilter(url.Values{"q": {"Seat"}, "at": {testNow.Format(time.RFC3339)}})
	near := observability.Event{Time: testNow.Add(2 * time.Minute), Level: "INFO", Message: "x", Attrs: map[string]string{"seat": "orders-1"}}
	far := near
	far.Time = testNow.Add(time.Hour)
	other := near
	other.Attrs = map[string]string{"region": "fra"}
	if !filter.matches(near) || filter.matches(far) || filter.matches(other) {
		t.Fatal("search or time window filter is wrong")
	}
}
