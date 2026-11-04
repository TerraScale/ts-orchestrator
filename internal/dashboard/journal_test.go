package dashboard

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
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
