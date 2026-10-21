package dashboard

import (
	"context"
	"errors"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/globalview"
	"github.com/TerraScale/ts-orchestrator/internal/insights"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/regionview"
)

// The tests in this file pin the fixes for the ts-reviewer findings on the
// dashboard (PR #125).

type failingRollouts struct{}

func (failingRollouts) Rollouts(context.Context) ([]insights.Rollout, error) {
	return nil, errors.New("rollout provider: secret upstream detail")
}

func (failingRollouts) Rollout(context.Context, string) (insights.Rollout, error) {
	return insights.Rollout{}, errors.New("rollout provider: secret upstream detail")
}

func withoutRollbacks(decisions []decisionlog.Decision) []decisionlog.Decision {
	return slices.DeleteFunc(slices.Clone(decisions), func(decision decisionlog.Decision) bool {
		return decision.Kind == decisionlog.KindRollback
	})
}

func TestEmptyHistoryIsNotClaimedWhenTheQueryFailedOrIsPartial(t *testing.T) {
	t.Parallel()
	failing, _, broken := journalDashboard(Options{})
	broken.err = errors.New("nats: timeout")
	handler := failing.Handler()
	if body := get(t, handler, "/releases").Body.String(); !strings.Contains(body, "Release history is unavailable right now") ||
		strings.Contains(body, "No release decisions in the last 7 days") {
		t.Fatalf("a failed release query reads as an empty history")
	}
	if body := get(t, handler, "/rollouts").Body.String(); !strings.Contains(body, "Rollback history is unavailable right now") ||
		strings.Contains(body, "No release was rolled back") || strings.Contains(body, "secret") {
		t.Fatalf("a failed rollback query reads as no rollback")
	}

	partial, _, decisions := journalDashboard(Options{})
	decisions.decisions = withoutRollbacks(decisions.decisions)
	if body := get(t, partial.Handler(), "/rollouts").Body.String(); !strings.Contains(body, "Rollback history is partial") ||
		strings.Contains(body, "No release was rolled back") {
		t.Fatalf("a partial rollback query reads as no rollback")
	}

	complete, _, decisions := journalDashboard(Options{})
	decisions.decisions, decisions.complete = withoutRollbacks(decisions.decisions), true
	if body := get(t, complete.Handler(), "/rollouts").Body.String(); !strings.Contains(body, "No release was rolled back in the last 7 days") {
		t.Fatalf("a complete history without rollbacks does not say so")
	}

	outage, _, _ := journalDashboard(Options{})
	journal := *outage.journal.Load()
	journal.Rollouts = failingRollouts{}
	outage.journal.Store(&journal)
	if body := get(t, outage.Handler(), "/rollouts").Body.String(); !strings.Contains(body, "rollout provider did not answer") ||
		strings.Contains(body, "No release rollout is known") || strings.Contains(body, "secret") {
		t.Fatalf("a rollout provider outage reads as no rollout")
	}
}

func completedRelease(regions ...string) []decisionlog.Decision {
	var out []decisionlog.Decision
	for index, region := range regions {
		out = append(out, decisionlog.Decision{ID: "c-" + region, Time: testNow.Add(-time.Duration(index+1) * time.Minute),
			Region: region, Kind: decisionlog.KindRolloutCompleted, Subject: release, Status: decisionlog.StatusSucceeded})
	}
	return out
}

func TestPartialReleaseHistoryIsNotCompleteEverywhere(t *testing.T) {
	t.Parallel()
	global := []globalview.Region{{Cell: "fra"}, {Cell: "sjc"}}
	journal := &Journal{Decisions: &fakeDecisions{}}
	label := func(result decisionlog.Result) string {
		return fixturePage(t, view{Journal: journal, Decisions: &result, Global: global}, "/releases")
	}

	// FRA completed and SJC did not answer: completion covers FRA only.
	partial := decisionlog.Result{Decisions: completedRelease("fra"), Partial: true,
		Regions: []decisionlog.RegionStatus{{Region: "fra", State: decisionlog.RegionOK},
			{Region: "sjc", State: decisionlog.RegionUnreachable}}}
	if got := label(partial); strings.Contains(got, "everywhere") || !strings.Contains(got, "observed") ||
		!strings.Contains(got, `pill s-warn`) {
		t.Fatalf("partial history = %q", got)
	}
	// Every region answered, but SJC never started the release.
	answered := decisionlog.Result{Decisions: completedRelease("fra"),
		Regions: []decisionlog.RegionStatus{{Region: "fra", State: decisionlog.RegionOK}, {Region: "sjc", State: decisionlog.RegionOK}}}
	if got := label(answered); strings.Contains(got, "everywhere") || !strings.Contains(got, "1 with no activity in the queried window") {
		t.Fatalf("release missing a region = %q", got)
	}
	everywhere := decisionlog.Result{Decisions: completedRelease("fra", "sjc"), Regions: answered.Regions}
	if got := label(everywhere); !strings.Contains(got, `pill s-ok">complete everywhere</span>`) {
		t.Fatalf("complete release = %q", got)
	}
}

func TestTargetVersionSkipsRolledBackReleasesAndUsesReleaseAge(t *testing.T) {
	t.Parallel()
	v1 := decisionlog.Subject{Kind: "release", ID: "r1", Name: "v1"}
	v2 := decisionlog.Subject{Kind: "release", ID: "r2", Name: "v2"}
	units := func(versions ...string) []UnitVersion {
		var out []UnitVersion
		for index, version := range versions {
			out = append(out, UnitVersion{Region: "fra", Kind: "controller", Unit: string(rune('a' + index)), Version: version})
		}
		return out
	}
	// The only release in the window is a rollback of v2, which most
	// units still run: v2 must not become the target.
	rollback := decisionlog.Result{Decisions: []decisionlog.Decision{{ID: "rb", Time: testNow, Region: "fra",
		Kind: decisionlog.KindRollback, Subject: v2, Status: decisionlog.StatusRolledBack}}}
	current := view{Decisions: &rollback, Versions: units("v2", "v2", "v2", "v1")}
	if target := pageTarget(t, current); target != "v1" {
		t.Fatalf("target with v2 rolled back = %q, want v1", target)
	}
	current.Versions = units("v2", "v2")
	if target := pageTarget(t, current); target != "" {
		t.Fatalf("target with only a rolled-back version = %q, want unknown", target)
	}
	if body := fixturePage(t, current, "/releases"); !strings.Contains(body, "2 units off the target version") {
		t.Fatal("rolled-back units were not flagged")
	}

	// v2 started after v1, but v1's last activity (its completion in
	// another region) is newer: the target stays v2.
	progress := decisionlog.Result{Decisions: []decisionlog.Decision{
		{ID: "v1-done", Time: testNow, Region: "sjc", Kind: decisionlog.KindRolloutCompleted, Subject: v1},
		{ID: "v2-start", Time: testNow.Add(-10 * time.Minute), Region: "fra", Kind: decisionlog.KindReleaseAdmitted, Subject: v2},
		{ID: "v1-start", Time: testNow.Add(-2 * time.Hour), Region: "sjc", Kind: decisionlog.KindReleaseAdmitted, Subject: v1},
	}}
	current = view{Decisions: &progress, Versions: units("v1", "v2")}

	if target := pageTarget(t, current); target != "v2" {
		t.Fatalf("target = %q, want the newest release v2", target)
	}
}

// historyJournal records 30 minutes of one-minute samples ending at now.
// The history picks its tier by the wall clock, so tests that read rates
// pass time.Now().
func historyJournal(now time.Time, samples func(at time.Time, minute int) []observability.Sample) *Journal {
	history := observability.NewHistory(observability.HistoryConfig{})
	for minute := 30; minute >= 0; minute-- {
		at := now.Add(-time.Duration(minute) * time.Minute)
		history.Append(at, samples(at, minute))
	}
	return &Journal{History: history}
}

func TestPartitionTileSparklinePlotsPartitionHistory(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	journal := historyJournal(now, func(time.Time, int) []observability.Sample {
		return []observability.Sample{{Metric: observability.HistDatabases, Value: 1}, {Metric: observability.HistSeatsServing, Value: 2}}
	})
	snapshot := memberSnapshot()
	body := fixturePage(t, view{Now: now, Journal: journal, Local: &snapshot, Ready: true}, "/region")
	at := strings.Index(body, "Managed TerraBase partitions")
	if at < 0 {
		t.Fatal("partition tile missing")
	}
	tail := body[at:]
	end := strings.Index(tail, "</article>")
	if end > 0 {
		tail = tail[:end]
	}
	match := regexp.MustCompile(`data-values="([^"]+)"`).FindStringSubmatch(tail)
	if len(match) != 2 {
		t.Fatal("partition tile sparkline missing")
	}
	for value := range strings.SplitSeq(match[1], ",") {
		if number, err := strconv.ParseFloat(value, 64); err != nil || number != 1 {
			t.Fatalf("partition sparkline %q includes seat count", match[1])
		}
	}
}

func TestConsumerSeriesKeepTheirStream(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	journal := historyJournal(now, func(time.Time, int) []observability.Sample {
		return []observability.Sample{
			{Metric: observability.HistConsumerPending, Labels: observability.L("stream", "A", "consumer", "worker"), Value: 1},
			{Metric: observability.HistConsumerPending, Labels: observability.L("stream", "B", "consumer", "worker"), Value: 2},
		}
	})
	body := fixturePage(t, view{Now: now, Journal: journal}, "/nats")
	for _, want := range []string{"A / worker", "B / worker"} {
		if !strings.Contains(body, want) {
			t.Errorf("NATS page lost %s series", want)
		}
	}
}

func TestHeatmapKeepsTheSampleAtTheRangeEnd(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(2 * time.Minute)
	history := observability.NewHistory(observability.HistoryConfig{})
	labels := observability.L("member", "physical")
	history.Append(now, []observability.Sample{{Metric: observability.HistHostCPUUtilization, Labels: labels, Value: .5}, {Metric: observability.HistHostReceivedAt, Labels: labels, Value: float64(now.UnixMilli())}})
	current := view{Now: now, Local: &observability.MemberSnapshot{Cell: "fra"}, Journal: &Journal{History: history}, LocalSummary: &regionview.Summary{Region: "fra", Local: true, Nodes: []regionview.Node{{Name: "physical"}}}}
	for _, chart := range pageCharts(t, fixturePage(t, current, "/members")) {
		if chart.Kind == "heatmap" {
			if len(chart.Heat) != 1 || chart.Heat[0][0] != float64(chart.Start+(heatColumns-1)*chart.Step) {
				t.Fatalf("range-end sample omitted: %+v", chart)
			}
			return
		}
	}
	t.Fatal("CPU heatmap missing")
}

// Only this region's engine raises insights, so a key is unique on the page;
// the card's id still names the region.
func TestInsightIdentityIsRegionScoped(t *testing.T) {
	t.Parallel()
	dashboard, source, _ := journalDashboard(Options{})
	source.evaluation.Insights = append(source.evaluation.Insights,
		testInsight("oci_throttled:sjc", "Same key in FRA", insights.SeverityWarning, "fra"))
	fraID := entityid.Derive("insight", "fra", "oci_throttled:sjc")
	body := get(t, dashboard.Handler(), "/insights?id="+fraID).Body.String()
	if !strings.Contains(body, `id="insight-`+fraID+`"`) {
		t.Fatal("the insight card id does not name its region")
	}
	start := strings.Index(body, `id="insight-`+fraID+`"`)
	if !strings.Contains(body[start:start+strings.Index(body[start:], ">")], "aria-current") {
		t.Fatal("the selection does not mark the card")
	}
	global := get(t, dashboard.Handler(), "/insights?region="+allRegions).Body.String()
	if !strings.Contains(global, `id="insight-`+fraID+`"`) {
		t.Fatal("the all-regions insight list lacks a region's card")
	}
}

func TestInsightsPageEmptyStatesAreHonest(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name      string
		current   view
		want      string
		forbidden string
	}{
		{"unavailable", view{Journal: &Journal{}}, "unavailable", "Every rule is quiet"},
		{"not run", view{Evaluation: &insights.Evaluation{}}, "unavailable", "Every rule is quiet"},
		{"quiet", view{Evaluation: &insights.Evaluation{At: testNow}}, "Every rule is quiet", ""},
		{"missing region", view{Evaluation: &insights.Evaluation{At: testNow}, Global: []globalview.Region{{Cell: "fra", Rollup: &globalview.Rollup{}}, {Cell: "sjc"}}}, "SJC", "Every rule is quiet"},
		{"missing inputs", view{Evaluation: &insights.Evaluation{At: testNow, Unavailable: []string{"volumes"}}}, "volumes", "Every rule is quiet"},
		{"filtered", view{State: parseState(url.Values{"severity": {"critical"}}), Evaluation: &insights.Evaluation{At: testNow, Insights: []insights.Insight{testInsight("k", "t", insights.SeverityInfo, "fra")}}}, "No insight matches these filters", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := fixturePage(t, test.current, "/insights")
			if !strings.Contains(body, test.want) || test.forbidden != "" && strings.Contains(body, test.forbidden) {
				t.Fatalf("insights state %s is misleading", test.name)
			}
		})
	}
}

func TestEntityLinksUseTheEntitysRegion(t *testing.T) {
	t.Parallel()
	dashboard, source, _ := journalDashboard(Options{})
	gru := testInsight("nats:gru", "GRU stream", insights.SeverityWarning, "gru")
	gru.Entity = insights.Entity{Kind: "stream", ID: "TS_X", Href: "/nats?stream=TS_X"}
	unreachable := testInsight("region_unreachable:sjc", "SJC unreachable", insights.SeverityWarning, "sjc")
	unreachable.Entity = insights.Entity{Kind: "region", ID: "sjc", Href: "/regions/sjc"}
	unreachable.Actions = []insights.Action{{Label: "Open the global view", Href: "/regions"}}
	held := testInsight("held:x", "Held", insights.SeverityWarning, "fra")
	held.Entity = insights.Entity{Kind: "subject", ID: "seat/s1", Href: "/decisions?subject=seat/s1"}
	source.evaluation.Insights = append(source.evaluation.Insights, gru, unreachable, held)
	body := get(t, dashboard.Handler(), "/insights?r=sjc&region=all").Body.String()
	for _, want := range []string{`href="/nats?r=gru&amp;stream=TS_X"`, `href="/region?r=sjc"`, `href="/?r=sjc"`,
		`href="/decisions?q=s1"`, `href="/members?host=ctl-1"`} {
		if !strings.Contains(body, want) {
			t.Errorf("insights page lacks %s", want)
		}
	}
}

func TestRegionFiltersFollowTheSelectedRegion(t *testing.T) {
	t.Parallel()
	dashboard, _, _ := journalDashboard(Options{})
	body := get(t, dashboard.Handler(), "/decisions?r=sjc").Body.String()
	if !strings.Contains(body, `<option value="sjc" selected>`) || strings.Contains(body, `<option value="all" selected>`) {
		t.Fatal("the region select does not show the effective region")
	}
	body = get(t, dashboard.Handler(), "/insights?r=sjc").Body.String()
	if strings.Contains(body, `id="insight-`+entityid.Derive("insight", "fra", "disk:ctl-1")) {
		t.Fatal("the insights page ignores the selected region")
	}
}

func TestFilterOptionsKeepTheActiveValues(t *testing.T) {
	t.Parallel()
	board, _, _ := journalDashboard(Options{})
	body := get(t, board.Handler(), "/decisions?kind=custom_kind&actor=custom-slice").Body.String()
	for _, want := range []string{`value="custom_kind" selected`, `value="custom-slice" selected`} {
		if !strings.Contains(body, want) {
			t.Errorf("filter form lacks %s", want)
		}
	}
}

func TestSwitcherOnlyOffersViewsThePageRenders(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"/topology", "/releases", "/members", "/nats", "/insights"} {
		board, _, _ := journalDashboard(Options{})
		body := get(t, board.Handler(), path+"?r=sjc").Body.String()
		if !strings.Contains(body, `href="/regions/fra"`) {
			t.Errorf("%s switcher lost regional drilldown", path)
		}
	}
}

func TestRemoteSelectionLabelsLocalSections(t *testing.T) {
	t.Parallel()
	dashboard, _, _ := journalDashboard(Options{})
	body := get(t, dashboard.Handler(), "/nats?r=sjc").Body.String()
	if !strings.Contains(body, "Live metrics and member detail on this page are from") ||
		strings.Contains(body, "Current JetStream meta leader") || !strings.Contains(body, "SJC · 24h at least") {
		t.Fatal("the NATS page mixes regions without saying so")
	}
	if body := get(t, dashboard.Handler(), "/nats").Body.String(); strings.Contains(body, "Live metrics and member detail") {
		t.Fatal("the local NATS page carries the remote scope note")
	}
}

func TestDerivedVersionsKeepTheLocalSnapshot(t *testing.T) {
	t.Parallel()
	snapshot := memberSnapshot()
	current := view{Local: &snapshot, Journal: &Journal{}, LocalSummary: &regionview.Summary{Region: "fra", Local: true},
		Global: []globalview.Region{{Cell: "fra"}, {Cell: "sjc", Rollup: &globalview.Rollup{Cell: "sjc",
			Versions: []globalview.BuildCount{{Version: "v1", Count: 1, Members: []string{"sjc-1"}}}}}}}
	body := fixturePage(t, current, "/releases")
	for _, want := range []string{"abc123def456", "SJC"} {
		if !strings.Contains(body, want) {
			t.Errorf("version matrix lacks %q", want)
		}
	}
}

func TestReleaseMatrixShowsRemoteControllers(t *testing.T) {
	t.Parallel()
	snapshot := memberSnapshot()
	current := view{Local: &snapshot, Journal: &Journal{}, LocalSummary: &regionview.Summary{Region: "fra", Local: true},
		Global: []globalview.Region{{Cell: "fra"}, {Cell: "sjc", Rollup: &globalview.Rollup{Cell: "sjc",
			Versions: []globalview.BuildCount{{Version: "v0.43.0", Count: 1, Members: []string{"sjc-ctl-1"}}}}}}}
	body := fixturePage(t, current, "/releases")
	for _, want := range []string{"abc123def456", "SJC"} {
		if !strings.Contains(body, want) {
			t.Errorf("version matrix lacks %q", want)
		}
	}
}

func TestChainPanelClosesOnItsOwnPage(t *testing.T) {
	t.Parallel()
	dashboard, _, _ := journalDashboard(Options{})
	body := get(t, dashboard.Handler(), "/releases?id=d2").Body.String()
	if !strings.Contains(body, `<a href="/releases">Close ✕</a>`) {
		t.Fatal("the release page's chain panel closes into the decision journal")
	}
}

func TestPartialHistoryIsNotBlamedOnRegions(t *testing.T) {
	t.Parallel()
	for _, state := range []string{decisionlog.RegionOK, decisionlog.RegionUnreachable} {
		result := decisionlog.Result{Partial: true, Regions: []decisionlog.RegionStatus{{Region: "sjc", State: state}}}
		body := fixturePage(t, view{Decisions: &result}, "/decisions")
		if state == decisionlog.RegionOK {
			if strings.Contains(body, "did not answer") || !strings.Contains(body, "could not be searched") {
				t.Fatal("partial history was blamed on a responding region")
			}
		} else if !strings.Contains(body, "did not answer") || !strings.Contains(body, "SJC") {
			t.Fatal("unreachable region evidence missing")
		}
	}
}

func TestStorageForecastNeedsHistory(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	history := observability.NewHistory(observability.HistoryConfig{})
	for minute := 2; minute >= 1; minute-- {
		history.Append(now.Add(-time.Duration(minute)*time.Minute), []observability.Sample{{Metric: observability.HistFSRatio, Labels: observability.L("member", "ctl-1", "role", "nats"), Value: .5}})
	}
	body := fixturePage(t, view{Now: now, Journal: &Journal{History: history}}, "/terrabase")
	if !strings.Contains(body, "not enough history") || !strings.Contains(body, "Not enough storage history") || strings.Contains(body, "headroom at its current growth") {
		t.Fatal("sparse history was presented as forecast headroom")
	}
	body = fixturePage(t, view{Now: now, Journal: &Journal{History: observability.NewHistory(observability.HistoryConfig{})}}, "/terrabase")
	if strings.Contains(body, "headroom at its current growth") || !strings.Contains(body, "No filesystem history yet") {
		t.Fatal("empty history was presented as known headroom")
	}
}

func TestDiskCapacityCountsSharedFilesystemsOnce(t *testing.T) {
	t.Parallel()
	snapshot := memberSnapshot()
	snapshot.System.Filesystems = []observability.FilesystemView{
		{Role: "state", Path: "/var/lib/x/state", SizeBytes: 100, AvailBytes: 40, Device: 7},
		{Role: "install", Path: "/var/lib/x/install", SizeBytes: 100, AvailBytes: 40, Device: 7},
	}
	now := time.Now().UTC()
	history := observability.NewHistory(observability.HistoryConfig{})
	history.Append(now, []observability.Sample{{Metric: observability.HistHostReceivedAt,
		Labels: observability.L("member", "physical-node"), Value: float64(now.UnixMilli())}})
	for _, filesystem := range snapshot.System.Filesystems {
		labels := observability.L("member", "physical-node", "role", filesystem.Role, "path", filesystem.Path, "device", "7")
		history.Append(now, []observability.Sample{
			{Metric: observability.HistHostFSSize, Labels: labels, Value: float64(filesystem.SizeBytes)},
			{Metric: observability.HistHostFSUsed, Labels: labels, Value: float64(filesystem.SizeBytes - filesystem.AvailBytes)},
			{Metric: observability.HistHostFSRatio, Labels: labels, Value: .6},
		})
	}
	current := view{State: parseState(url.Values{}), Local: &snapshot, Now: now, Journal: &Journal{History: history},
		LocalSummary: &regionview.Summary{Region: "fra", Local: true, Nodes: []regionview.Node{{Name: "physical-node", Member: "ctl-1"}}}}
	found := false
	for _, chart := range pageCharts(t, fixturePage(t, current, "/storage")) {
		if chart.Kind == "treemap" {
			found = true
			if len(chart.Tree) != 1 || len(chart.Tree[0].Children) != 1 || chart.Tree[0].Children[0].Name != "install, state" || chart.Tree[0].Value != 100 {
				t.Fatalf("shared filesystem counted twice: %+v", chart.Tree)
			}
		}
	}
	if !found {
		t.Fatal("filesystem chart missing")
	}

}

func TestOCIRateEvidenceChartsTheSummedPerMinuteRate(t *testing.T) {
	t.Parallel()
	now := time.Now()
	journal := historyJournal(now, func(_ time.Time, minute int) []observability.Sample {
		elapsed := float64(30-minute) * 60
		return []observability.Sample{
			{Metric: observability.HistOCIErrors, Labels: observability.L("operation", "a"), Value: elapsed * 0.1, Counter: true},
			{Metric: observability.HistOCIErrors, Labels: observability.L("operation", "b"), Value: elapsed * 0.05, Counter: true},
		}
	})
	current := view{State: parseState(url.Values{}), Now: now, Journal: journal, Local: &observability.MemberSnapshot{Cell: "fra"}}
	insight := insights.Insight{Region: "fra", Evidence: []insights.Evidence{{Label: "Rate", Metric: observability.HistOCIErrors,
		Value: 9, Unit: perMinute, Comparison: "<", Threshold: float(1)}}}
	insight.Key = entityid.Derive("rate-insight")
	insight.Title = "OCI error rate"
	insight.Severity = insights.SeverityWarning
	current.Evaluation = &insights.Evaluation{At: now, Insights: []insights.Insight{insight}}
	found := false
	for _, chart := range pageCharts(t, fixturePage(t, current, "/insights")) {
		if len(chart.Series) == 1 && chart.Series[0].Name == "Rate per minute" {
			found = true
			for _, point := range chart.Series[0].Points {
				if point[1] < 8.9 || point[1] > 9.1 {
					t.Fatalf("per-minute rate point = %v, want 9", point)
				}
			}
		}
	}
	if !found {
		t.Fatal("OCI rate evidence chart missing")
	}

}

func TestGzipQualityZeroIsRefused(t *testing.T) {
	t.Parallel()
	server := newStreamServer(t, newTestDashboard(Options{}))
	for header, want := range map[string]bool{"gzip": true, "gzip;q=0.5": true, "br, gzip; q=1": true, "gzip;q=0": false, "gzip;q=0.0": false, "gzip; q=0.000": false, "deflate": false, "gzip;Q=0.00": false} {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+assetURL("app.js"), nil)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		request.Header.Set("Accept-Encoding", header)
		response, err := server.Client().Do(request)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		_, readErr := io.Copy(io.Discard, response.Body)
		closeErr := response.Body.Close()
		cancel()
		if readErr != nil || closeErr != nil {
			t.Fatalf("GET asset with %q read=%v close=%v", header, readErr, closeErr)
		}
		if response.StatusCode != http.StatusOK || (response.Header.Get("Content-Encoding") == "gzip") != want {
			t.Errorf("GET asset with %q = %d, encoding %q", header, response.StatusCode, response.Header.Get("Content-Encoding"))
		}
	}
}

func TestRegionReadinessListsEveryMember(t *testing.T) {
	t.Parallel()
	local := memberSnapshot()
	peer := memberSnapshot()
	peer.Member, peer.Ready = "ctl-2", false
	peer.Checks = []observability.CheckResult{{Name: "cluster", Detail: "regional cluster is below its full replica count"}}
	current := view{Local: &local, Ready: true, Checks: []observability.CheckResult{{Name: "nats", OK: true,
		Detail: "regional broker connected"}},
		Cluster: &observability.ClusterSnapshot{Members: []observability.MemberSnapshot{local, peer}, Missing: []string{"ctl-3"}}}
	page := current
	page.State = parseState(url.Values{})
	body := fixturePage(t, page, "/region")
	for _, want := range []string{"Region readiness", "regional broker connected", "not answering", "ctl-3"} {
		if !strings.Contains(body, want) {
			t.Errorf("region page lacks %q", want)
		}
	}
}

func TestEmptyTimelinesSayWhy(t *testing.T) {
	t.Parallel()
	for _, source := range []*fakeDecisions{{complete: true}, {err: errors.New("private timeout")}} {
		body := fixturePage(t, view{Journal: &Journal{Decisions: source}}, "/decisions")
		if strings.Contains(body, "private timeout") {
			t.Fatal("timeline leaked provider error")
		}
		if source.err != nil && !strings.Contains(body, "unavailable") {
			t.Fatal("failed timeline appeared empty")
		}
		if source.err == nil && !strings.Contains(body, "No decisions") {
			t.Fatal("empty timeline lacks reason")
		}
	}
}

// TestDashboardScriptGuards pins the client fixes that have no Go-side
// behavior; each was also exercised in headless Chromium over CDP.
func TestDashboardScriptGuards(t *testing.T) {
	t.Parallel()
	script := get(t, newTestDashboard(Options{}).Handler(), assetURL("app.js")).Body.String()
	for name, want := range map[string]string{
		"notify label is only assigned when it changed (MutationObserver loop)": "if (button.textContent !== label) button.textContent = label;",
		"a render checks the chart and generation after awaiting":               "this.chart !== chart || this.generation !== generation",
		"only a backdrop click closes the palette":                              "e.composedPath()[0] === this",
		"a failed GeoJSON load is retried":                                      "if (geoLoading === attempt) geoLoading = null;",
		"the map keeps the operator's zoom":                                     "zoom: current && current.zoom ? current.zoom : 1.15",
		"copy works without the clipboard API":                                  "if (!navigator.clipboard || !navigator.clipboard.writeText) { manual(); return; }",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("app.js lost the guard: %s", name)
		}
	}
}

// These pin the fixes for the ts-reviewer findings on PRs #127 and #130.

func releasePage(t *testing.T, decisions ...decisionlog.Decision) string {
	t.Helper()
	return fixturePage(t, view{Decisions: &decisionlog.Result{Decisions: decisions}}, "/releases")
}

// Admission is not CI qualification: without explicit evidence there is no
// qualified step.
func TestAdmissionAloneIsNotQualified(t *testing.T) {
	t.Parallel()
	body := releasePage(t, decisionlog.Decision{ID: "a", Time: testNow, Region: "fra", Kind: decisionlog.KindReleaseAdmitted, Subject: release})
	if strings.Contains(body, `class="step s-ok"`) {
		t.Fatal("admission produced a successful qualification step")
	}
	if !strings.Contains(body, `id=a`) {
		t.Fatal("admission decision did not reach release page")
	}
}

// A rollback that has started is not reported as rolled back, and an
// aborted rollout is a failed outcome, not a running lane.
func TestRollbackInProgressAndAbortedOutcomes(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		kind        decisionlog.Kind
		status      decisionlog.Status
		phase, want string
	}{
		{decisionlog.KindRollback, decisionlog.StatusInProgress, "", "rolling back"},
		{decisionlog.KindRollback, decisionlog.StatusRolledBack, "", "rolled back"},
		{decisionlog.KindHeld, decisionlog.StatusFailed, "aborted", "aborted"},
	} {
		body := releasePage(t, decisionlog.Decision{ID: "rb", Time: testNow, Region: "fra", Kind: test.kind, Subject: release, Status: test.status, Attrs: map[string]string{"phase": test.phase}})
		if !strings.Contains(body, test.want) {
			t.Errorf("release page lacks outcome %q", test.want)
		}
	}
}

// The rollout producer names its subject "<kind>/<rollout>"; that label is
// not a version, and a release whose start was not observed does not
// outrank one whose admission was.
func TestTargetVersionUsesVersionIdentityAndObservedStarts(t *testing.T) {
	t.Parallel()
	rollout := decisionlog.Subject{Kind: "release", ID: "sha256:cccc", Name: "orchestrator/ro-7"}
	currentVersion := view{Decisions: &decisionlog.Result{Decisions: []decisionlog.Decision{{Subject: rollout, Time: testNow, Region: "fra", Kind: decisionlog.KindReleaseAdmitted}}}, Versions: []UnitVersion{{Region: "fra", Kind: "controller", Unit: "a", Version: rollout.ID}}}
	if target := pageTarget(t, currentVersion); target != rollout.ID {
		t.Fatalf("rollout target=%q, want digest", target)
	}

	v1 := decisionlog.Subject{Kind: "release", ID: "r1", Name: "v1"}
	v2 := decisionlog.Subject{Kind: "release", ID: "r2", Name: "v2"}
	result := decisionlog.Result{Decisions: []decisionlog.Decision{
		// v1's admission is outside the window; its first loaded decision
		// is a recent batch.
		{ID: "v1-batch", Time: testNow.Add(-time.Hour), Region: "fra", Kind: decisionlog.KindBatchPromoted, Subject: v1},
		{ID: "v2-start", Time: testNow.Add(-2 * time.Hour), Region: "fra", Kind: decisionlog.KindReleaseAdmitted, Subject: v2},
	}}
	current := view{Decisions: &result, Versions: []UnitVersion{
		{Region: "fra", Kind: "controller", Unit: "a", Version: "v1"},
		{Region: "fra", Kind: "controller", Unit: "b", Version: "v2"}}}
	if target := pageTarget(t, current); target != "v2" {
		t.Fatalf("target = %q, want v2 whose start was observed", target)
	}
}

// The rollout diagram reads the rollout state machine's phases.
func TestRolloutDiagramReadsStateMachinePhases(t *testing.T) {
	t.Parallel()
	for _, phase := range []string{"canary", "canary-soak", "batch", "batch-soak", "complete", "preflight", "rolled-back", "aborted"} {
		source := fakeRollouts{{ID: entityid.Derive("phase", phase), Release: "release", Phase: phase, Done: phase == "complete" || phase == "rolled-back" || phase == "aborted"}}
		body := fixturePage(t, view{Journal: &Journal{Rollouts: source}}, "/rollouts")
		if !strings.Contains(body, ">"+phase+"</span>") {
			t.Errorf("rollouts lost %s phase", phase)
		}
		if phase == "canary-soak" {
			for _, want := range []string{`phase s-ok">canary`, `phase s-run">soak`, `phase s-idle">batches`} {
				if !strings.Contains(body, want) {
					t.Errorf("canary soak lacks %s", want)
				}
			}
		}
	}
}

// Heatmap columns are never finer than the samples, so continuous 1m
// rollups in a 1h view fill every column.
func TestHeatmapColumnsFollowTheSampleResolution(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Minute)
	history := observability.NewHistory(observability.HistoryConfig{})
	for minute := 60; minute >= 0; minute-- {
		at := now.Add(-time.Duration(minute) * time.Minute)
		history.Append(at, []observability.Sample{{Metric: observability.HistHostCPUUtilization, Labels: observability.L("member", "physical"), Value: .5}, {Metric: observability.HistHostReceivedAt, Labels: observability.L("member", "physical"), Value: float64(at.UnixMilli())}})
	}
	current := view{Now: now, Local: &observability.MemberSnapshot{Cell: "fra"}, Journal: &Journal{History: history}, LocalSummary: &regionview.Summary{Region: "fra", Local: true, Nodes: []regionview.Node{{Name: "physical"}}}}
	for _, chart := range pageCharts(t, fixturePage(t, current, "/members")) {
		if chart.Kind == "heatmap" {
			columns := (chart.End - chart.Start + chart.Step - 1) / chart.Step
			if chart.Step < time.Minute.Milliseconds() || int64(len(chart.Heat)) != columns {
				t.Fatalf("heatmap resolution lost continuous samples: %+v", chart)
			}
			return
		}
	}
	t.Fatal("CPU heatmap missing")
}

// A slow fill near 100% that rounding would flatten is still forecast.
func TestStorageForecastFitsRawSamples(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	history := observability.NewHistory(observability.HistoryConfig{})
	for minute := 24 * 60; minute >= 0; minute -= 10 {
		history.Append(now.Add(-time.Duration(minute)*time.Minute), []observability.Sample{{Metric: observability.HistFSRatio, Labels: observability.L("member", "ctl-1", "role", "nats"), Value: .99994 - float64(minute)/(24*60)*.00003}})
	}
	body := fixturePage(t, view{Now: now, Journal: &Journal{History: history}}, "/terrabase")
	found := false
	for _, chart := range pageCharts(t, body) {
		for _, series := range chart.Series {
			if series.Dashed {
				found = true
			}
		}
	}
	if !found || strings.Contains(body, "not enough history") {
		t.Fatal("slow fill near full was flattened instead of forecast")
	}
}

// A failed volume read is not "no block volume is attached".
func TestStoragePageNamesAFailedVolumeRead(t *testing.T) {
	t.Parallel()
	body := fixturePage(t, view{Journal: &Journal{Volumes: failingVolumeProvider{}}}, "/storage")
	if strings.Contains(body, "No block volume is attached") || !strings.Contains(body, "could not be read") || strings.Contains(body, "placement store timeout") {
		t.Fatal("storage page misreported or leaked the failed volume read")
	}
}

type failingVolumeProvider struct{}

func (failingVolumeProvider) Volumes(context.Context) ([]insights.Volume, error) {
	return nil, errors.New("placement store timeout")
}

func pageTarget(t *testing.T, current view) string {
	t.Helper()
	body := fixturePage(t, current, "/releases")
	match := regexp.MustCompile(`(?s)<tbody>\s*<tr>\s*<th scope="row">Controllers</th>\s*<td><code>([^<]*)</code>`).FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatalf("controller target missing in release matrix")
	}
	return html.UnescapeString(match[1])
}
