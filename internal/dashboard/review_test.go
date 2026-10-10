package dashboard

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/a-h/templ"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/insights"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionview"
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
	summaries := []regionview.Summary{{Region: "fra", Local: true, Reach: decisionlog.RegionOK},
		{Region: "sfo", Reach: decisionlog.RegionUnreachable}}
	journal := &Journal{Decisions: &fakeDecisions{}}
	label := func(result decisionlog.Result) string {
		current := view{Journal: journal, Decisions: &result, Regions: summaries}
		releases := current.releases()
		if len(releases) != 1 {
			t.Fatalf("releases = %+v", releases)
		}
		return releases[0].Status + " " + releases[0].Label
	}
	// FRA completed and SFO did not answer: completion covers FRA only.
	partial := decisionlog.Result{Decisions: completedRelease("fra"), Partial: true,
		Regions: []decisionlog.RegionStatus{{Region: "fra", State: decisionlog.RegionOK},
			{Region: "sfo", State: decisionlog.RegionUnreachable}}}
	if got := label(partial); strings.Contains(got, "everywhere") || !strings.Contains(got, "observed") ||
		!strings.HasPrefix(got, "warn") {
		t.Fatalf("partial history = %q", got)
	}
	// Every region answered, but SFO never started the release.
	answered := decisionlog.Result{Decisions: completedRelease("fra"),
		Regions: []decisionlog.RegionStatus{{Region: "fra", State: decisionlog.RegionOK}, {Region: "sfo", State: decisionlog.RegionOK}}}
	if got := label(answered); strings.Contains(got, "everywhere") || !strings.Contains(got, "1 with no activity in the queried window") {
		t.Fatalf("release missing a region = %q", got)
	}
	everywhere := decisionlog.Result{Decisions: completedRelease("fra", "sfo"), Regions: answered.Regions}
	if got := label(everywhere); got != "ok complete everywhere" {
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
	if target := current.targetVersion("controller"); target != "v1" {
		t.Fatalf("target with v2 rolled back = %q, want v1", target)
	}
	current.Versions = units("v2", "v2")
	if target := current.targetVersion("controller"); target != "" {
		t.Fatalf("target with only a rolled-back version = %q, want unknown", target)
	}
	if drifted := current.driftedUnits(); len(drifted) != 2 {
		t.Fatalf("units on a rolled-back version are not flagged: %+v", drifted)
	}
	// v2 started after v1, but v1's last activity (its completion in
	// another region) is newer: the target stays v2.
	progress := decisionlog.Result{Decisions: []decisionlog.Decision{
		{ID: "v1-done", Time: testNow, Region: "sfo", Kind: decisionlog.KindRolloutCompleted, Subject: v1},
		{ID: "v2-start", Time: testNow.Add(-10 * time.Minute), Region: "fra", Kind: decisionlog.KindReleaseAdmitted, Subject: v2},
		{ID: "v1-start", Time: testNow.Add(-2 * time.Hour), Region: "sfo", Kind: decisionlog.KindReleaseAdmitted, Subject: v1},
	}}
	current = view{Decisions: &progress, Versions: units("v1", "v2")}
	if releases := current.releases(); releases[0].Name != "v1" {
		t.Fatalf("the timeline is no longer ordered by last activity: %+v", releases)
	}
	if target := current.targetVersion("controller"); target != "v2" {
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
	journal := historyJournal(testNow, func(_ time.Time, minute int) []observability.Sample {
		return []observability.Sample{{Metric: observability.HistDatabases, Value: 1},
			{Metric: observability.HistSeatsServing, Value: float64(minute % 3)}}
	})
	snapshot := memberSnapshot()
	current := view{State: parseState(url.Values{}), Now: testNow, Journal: journal, Local: &snapshot, Ready: true}
	for _, tile := range current.regionKPIs() {
		if tile.Label == "Managed TerraBase partitions" {
			for value := range strings.SplitSeq(tile.Spark, ",") {
				if number, err := strconv.ParseFloat(value, 64); err != nil || number != 1 {
					t.Fatalf("partition sparkline = %q, want the partition count's history", tile.Spark)
				}
			}
			return
		}
	}
	t.Fatal("no partition tile")
}

func TestConsumerSeriesKeepTheirStream(t *testing.T) {
	t.Parallel()
	journal := historyJournal(testNow, func(time.Time, int) []observability.Sample {
		return []observability.Sample{
			{Metric: observability.HistConsumerPending, Labels: observability.L("stream", "A", "consumer", "worker"), Value: 1},
			{Metric: observability.HistConsumerPending, Labels: observability.L("stream", "B", "consumer", "worker"), Value: 2},
		}
	})
	current := view{State: parseState(url.Values{}), Now: testNow, Journal: journal}
	series := current.historyRange(observability.HistConsumerPending, nil, "stream,consumer", false)
	if len(series) != 2 || series[0].Name != "A / worker" || series[1].Name != "B / worker" {
		t.Fatalf("consumer series = %+v", series)
	}
	natsView := current
	natsView.Page = pages[slices.IndexFunc(pages, func(entry page) bool { return entry.slug == "nats" })]
	if body := renderHTML(t, natsBody(natsView)); !strings.Contains(body, "A / worker") {
		t.Fatal("the NATS page names consumers without their stream")
	}
}

func TestHeatmapKeepsTheSampleAtTheRangeEnd(t *testing.T) {
	t.Parallel()
	current := view{State: parseState(url.Values{}), Now: testNow}
	spec := current.heatmap("percent", []chartSeries{{Name: "m", Points: [][2]float64{{float64(testNow.UnixMilli()), 0.5}}}}, "empty")
	if spec.Empty != "" || len(spec.Heat) != 1 || spec.Heat[0][0] != float64(spec.Start+(heatColumns-1)*spec.Step) {
		t.Fatalf("heatmap = %+v", spec)
	}
}

func TestInsightIdentityIsRegionScoped(t *testing.T) {
	t.Parallel()
	dashboard, source, _ := journalDashboard(Options{})
	source.evaluation.Insights = append(source.evaluation.Insights,
		testInsight("oci_throttled:sfo", "Same key in FRA", insights.SeverityWarning, "fra"))
	fraID := entityid.Derive("insight", "fra", "oci_throttled:sfo")
	sfoID := entityid.Derive("insight", "sfo", "oci_throttled:sfo")
	body := get(t, dashboard.Handler(), "/insights?id="+sfoID).Body.String()
	if !strings.Contains(body, `id="insight-`+fraID+`"`) || !strings.Contains(body, `id="insight-`+sfoID+`"`) {
		t.Fatal("cards with the same key in two regions share a DOM id")
	}
	card := func(id string) string {
		start := strings.Index(body, `id="insight-`+id+`"`)
		return body[start : start+strings.Index(body[start:], ">")]
	}
	if !strings.Contains(card(sfoID), "aria-current") || strings.Contains(card(fraID), "aria-current") {
		t.Fatal("the selection marks the wrong card")
	}
	global := get(t, dashboard.Handler(), "/insights?region="+allRegions).Body.String()
	if !strings.Contains(global, `id="insight-`+fraID+`"`) || !strings.Contains(global, `id="insight-`+sfoID+`"`) {
		t.Fatal("the all-regions insight list lacks a region's card")
	}
}

func TestInsightsPageEmptyStatesAreHonest(t *testing.T) {
	t.Parallel()
	if text := (view{Journal: &Journal{}}).quietText(); !strings.Contains(text, "unavailable") {
		t.Fatalf("no evaluation = %q", text)
	}
	// A new engine's empty evaluation (zero time) has not run yet.
	if text := (view{Evaluation: &insights.Evaluation{}}).quietText(); !strings.Contains(text, "unavailable") {
		t.Fatalf("not yet evaluated = %q", text)
	}
	quiet := view{Evaluation: &insights.Evaluation{At: testNow}}
	if text := quiet.quietText(); !strings.Contains(text, "Every rule is quiet") {
		t.Fatalf("quiet = %q", text)
	}
	// A region that could not be observed rules out the global all-clear.
	unlinked := view{Evaluation: &insights.Evaluation{At: testNow}, Regions: []regionview.Summary{
		{Region: "fra", Local: true, Reach: decisionlog.RegionOK}, {Region: "sfo", Reach: decisionlog.RegionNotLinked}}}
	if text := unlinked.quietText(); strings.Contains(text, "Every rule is quiet") || !strings.Contains(text, "SFO") {
		t.Fatalf("unobserved region = %q", text)
	}
	blind := view{Evaluation: &insights.Evaluation{At: testNow, Unavailable: []string{"volumes"}}}
	if text := blind.quietText(); strings.Contains(text, "Every rule is quiet") {
		t.Fatalf("rules without input = %q", text)
	}
	filtered := view{Evaluation: &insights.Evaluation{Insights: []insights.Insight{testInsight("k", "t", insights.SeverityInfo, "fra")}}}
	if text := filtered.quietText(); !strings.Contains(text, "No insight matches these filters") {
		t.Fatalf("filtered = %q", text)
	}
}

func TestEntityLinksUseTheEntitysRegion(t *testing.T) {
	t.Parallel()
	dashboard, source, _ := journalDashboard(Options{})
	gru := testInsight("nats:gru", "GRU stream", insights.SeverityWarning, "gru")
	gru.Entity = insights.Entity{Kind: "stream", ID: "TS_X", Href: "/nats?stream=TS_X"}
	unreachable := testInsight("region_unreachable:sfo", "SFO unreachable", insights.SeverityWarning, "sfo")
	unreachable.Entity = insights.Entity{Kind: "region", ID: "sfo", Href: "/regions/sfo"}
	unreachable.Actions = []insights.Action{{Label: "Open the global view", Href: "/regions"}}
	held := testInsight("held:x", "Held", insights.SeverityWarning, "fra")
	held.Entity = insights.Entity{Kind: "subject", ID: "seat/s1", Href: "/decisions?subject=seat/s1"}
	source.evaluation.Insights = append(source.evaluation.Insights, gru, unreachable, held)
	body := get(t, dashboard.Handler(), "/insights?r=sfo&region=all").Body.String()
	for _, want := range []string{`href="/nats?r=gru&amp;stream=TS_X"`, `href="/region?r=sfo"`, `href="/?r=sfo"`,
		`href="/decisions?q=s1"`, `href="/members?host=ctl-1"`} {
		if !strings.Contains(body, want) {
			t.Errorf("insights page lacks %s", want)
		}
	}
}

func TestRegionFiltersFollowTheSelectedRegion(t *testing.T) {
	t.Parallel()
	selected := parseState(url.Values{"r": {"fra"}})
	if got := journalDecisions(view{State: selected}).Regions; !slices.Equal(got, []string{"fra"}) {
		t.Fatalf("regions with r=fra = %v", got)
	}
	all := parseState(url.Values{"r": {"fra"}, "region": {allRegions}})
	if got := journalDecisions(view{State: all}).Regions; got != nil {
		t.Fatalf("regions with region=all = %v", got)
	}
	dashboard, _, _ := journalDashboard(Options{})
	body := get(t, dashboard.Handler(), "/decisions?r=sfo").Body.String()
	if !strings.Contains(body, `<option value="sfo" selected>`) || strings.Contains(body, `<option value="all" selected>`) {
		t.Fatal("the region select does not show the effective region")
	}
	body = get(t, dashboard.Handler(), "/insights?r=sfo").Body.String()
	if strings.Contains(body, `id="insight-`+entityid.Derive("insight", "fra", "disk:ctl-1")) || !strings.Contains(body, `id="insight-`+entityid.Derive("insight", "sfo", "oci_throttled:sfo")) {
		t.Fatal("the insights page ignores the selected region")
	}
}

func TestFilterOptionsKeepTheActiveValues(t *testing.T) {
	t.Parallel()
	current := view{State: parseState(url.Values{"kind": {"custom_kind"}, "actor": {"custom-slice"}})}
	if !slices.Contains(current.kindOptions(), "custom_kind") || !slices.Contains(current.actorOptions(), "custom-slice") {
		t.Fatal("an active custom kind or actor disappears from its select")
	}
}

func TestSwitcherOnlyOffersViewsThePageRenders(t *testing.T) {
	t.Parallel()
	pageOf := func(slug string) page {
		return pages[slices.IndexFunc(pages, func(entry page) bool { return entry.slug == slug })]
	}
	state := parseState(url.Values{"r": {"sfo"}})
	cases := []struct {
		slug, link string
		global     bool
		selected   string
	}{
		{"topology", "/region?r=fra", true, ""},
		{"releases", "/region?r=fra", true, ""},
		{"members", "/region?r=fra", false, "gru"},
		{"nats", "/nats?r=fra", false, "sfo"},
		{"insights", "/insights?r=fra", false, "sfo"},
	}
	for _, test := range cases {
		current := view{Page: pageOf(test.slug), State: state, Local: &observability.MemberSnapshot{Cell: "gru"}}
		if got := current.switchLink("fra"); got != test.link {
			t.Errorf("%s switch link = %s, want %s", test.slug, got, test.link)
		}
		if current.globalScope() != test.global {
			t.Errorf("%s global scope = %v", test.slug, current.globalScope())
		}
		for _, region := range []string{"gru", "sfo", "fra"} {
			if current.selectedRegion(region) != (region == test.selected) {
				t.Errorf("%s marks %s selected = %v", test.slug, region, current.selectedRegion(region))
			}
		}
	}
}

func TestRemoteSelectionLabelsLocalSections(t *testing.T) {
	t.Parallel()
	dashboard, _, _ := journalDashboard(Options{})
	body := get(t, dashboard.Handler(), "/nats?r=sfo").Body.String()
	if !strings.Contains(body, "Live metrics and member detail on this page are from") ||
		strings.Contains(body, "Current JetStream meta leader") || !strings.Contains(body, "SFO · 24h at least") {
		t.Fatal("the NATS page mixes regions without saying so")
	}
	if body := get(t, dashboard.Handler(), "/nats").Body.String(); strings.Contains(body, "Live metrics and member detail") {
		t.Fatal("the local NATS page carries the remote scope note")
	}
}

func TestDerivedVersionsKeepTheLocalSnapshot(t *testing.T) {
	t.Parallel()
	snapshot := memberSnapshot()
	current := view{Local: &snapshot, Journal: &Journal{},
		Regions: []regionview.Summary{{Region: "fra", Local: true}, {Region: "sfo",
			Versions: []regionview.Version{{Version: "v1", Members: []string{"sfo-1"}}}}}}
	current.loadVersions(context.Background())
	if len(current.Versions) != 2 || current.Versions[1].Unit != "ctl-1" || current.Versions[1].Version != "abc123def456" {
		t.Fatalf("versions = %+v", current.Versions)
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
	answered := &decisionlog.Result{Partial: true, Regions: []decisionlog.RegionStatus{{Region: "fra", State: decisionlog.RegionOK}}}
	body := renderHTML(t, regionStatuses(answered))
	if strings.Contains(body, "did not answer") || !strings.Contains(body, "could not be searched") {
		t.Fatalf("partial history = %q", body)
	}
	missing := &decisionlog.Result{Partial: true, Regions: []decisionlog.RegionStatus{{Region: "sfo", State: decisionlog.RegionUnreachable}}}
	if body := renderHTML(t, regionStatuses(missing)); !strings.Contains(body, "did not answer") || !strings.Contains(body, "SFO") {
		t.Fatalf("unanswered region = %q", body)
	}
}

func TestStorageForecastNeedsHistory(t *testing.T) {
	t.Parallel()
	history := observability.NewHistory(observability.HistoryConfig{})
	for minute := 2; minute >= 1; minute-- {
		history.Append(testNow.Add(-time.Duration(minute)*time.Minute), []observability.Sample{{Metric: observability.HistFSRatio,
			Labels: observability.L("member", "ctl-1", "role", "nats"), Value: 0.5}})
	}
	current := view{State: parseState(url.Values{}), Now: testNow, Journal: &Journal{History: history}}
	forecasts, spec := current.storageForecasts()
	if len(forecasts) != 1 || forecasts[0].Status != "idle" || forecastText(forecasts[0]) != "not enough history" {
		t.Fatalf("forecasts = %+v", forecasts)
	}
	if strings.Contains(spec.Empty, "headroom at its current growth") || !strings.Contains(spec.Empty, "Not enough storage history") {
		t.Fatalf("empty = %q", spec.Empty)
	}
	empty := view{State: parseState(url.Values{}), Now: testNow,
		Journal: &Journal{History: observability.NewHistory(observability.HistoryConfig{})}}
	if _, spec := empty.storageForecasts(); strings.Contains(spec.Empty, "headroom at its current growth") {
		t.Fatalf("an empty history claims headroom: %q", spec.Empty)
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
		Regions: []regionview.Summary{{Region: "fra", Local: true, Nodes: []regionview.Node{{Name: "physical-node", Member: "ctl-1"}}}}}
	spec := current.capacityChart(true)
	if spec.Bars[0].Values[0]+spec.Bars[1].Values[0] != 100 {
		t.Fatalf("disk capacity = %+v", spec.Bars)
	}
	tree := current.filesystemTree()
	if len(tree.Tree[0].Children) != 1 || tree.Tree[0].Children[0].Name != "install, state" || tree.Tree[0].Value != 100 {
		t.Fatalf("treemap = %+v", tree.Tree)
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
	spec, ok := current.insightChart(insight)
	if !ok || len(spec.Series) != 1 {
		t.Fatalf("chart = %+v", spec)
	}
	for _, point := range spec.Series[0].Points {
		if point[1] < 8.9 || point[1] > 9.1 {
			t.Fatalf("per-minute rate point = %v, want 9", point)
		}
	}
}

func TestGzipQualityZeroIsRefused(t *testing.T) {
	t.Parallel()
	for header, want := range map[string]bool{
		"gzip": true, "gzip;q=0.5": true, "br, gzip; q=1": true, "gzip;q=0": false, "gzip;q=0.0": false,
		"gzip; q=0.000": false, "deflate": false, "gzip;Q=0.00": false,
	} {
		if got := acceptsGzip(header); got != want {
			t.Errorf("acceptsGzip(%q) = %v, want %v", header, got, want)
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
	rows := current.readiness()
	if len(rows) != 3 || rows[0].Checks[0].Detail != "regional broker connected" || rows[1].Ready ||
		!rows[2].Missing || rows[2].Member != "ctl-3" {
		t.Fatalf("readiness = %+v", rows)
	}
	page := current
	page.State = parseState(url.Values{})
	body := renderHTML(t, regionBody(page))
	for _, want := range []string{"Region readiness", "regional broker connected", "not answering", "ctl-3"} {
		if !strings.Contains(body, want) {
			t.Errorf("region page lacks %q", want)
		}
	}
}

func TestEmptyTimelinesSayWhy(t *testing.T) {
	t.Parallel()
	body := renderHTML(t, timeline("", chartSpec{Empty: "No decisions were recorded since then."}))
	if !strings.Contains(body, "No decisions were recorded since then.") {
		t.Fatalf("an empty timeline renders nothing: %q", body)
	}
	failed := view{State: parseState(url.Values{}), Now: testNow, Journal: &Journal{Decisions: &fakeDecisions{}}}
	if spec := failed.decisionTimeline(nil, true); !strings.Contains(spec.Empty, "unavailable") {
		t.Fatalf("failed timeline = %q", spec.Empty)
	}
}

// TestDashboardScriptGuards pins the client fixes that have no Go-side
// behavior; each was also exercised in headless Chromium over CDP.
func TestDashboardScriptGuards(t *testing.T) {
	t.Parallel()
	script := string(assets["app.js"].body)
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

func renderHTML(t *testing.T, component templ.Component) string {
	t.Helper()
	var body strings.Builder
	if err := component.Render(context.Background(), &body); err != nil {
		t.Fatal(err)
	}
	return body.String()
}

// These pin the fixes for the ts-reviewer findings on PRs #127 and #130.

func releaseLabel(t *testing.T, decisions ...decisionlog.Decision) releaseView {
	t.Helper()
	result := decisionlog.Result{Decisions: decisions}
	releases := view{Journal: &Journal{Decisions: &fakeDecisions{}}, Decisions: &result}.releases()
	if len(releases) != 1 {
		t.Fatalf("releases = %+v", releases)
	}
	return releases[0]
}

// Admission is not CI qualification: without explicit evidence there is no
// qualified step.
func TestAdmissionAloneIsNotQualified(t *testing.T) {
	t.Parallel()
	release := releaseLabel(t, decisionlog.Decision{ID: "a", Time: testNow, Region: "fra",
		Kind: decisionlog.KindReleaseAdmitted, Subject: release})
	for _, step := range release.Lanes[0].Steps {
		if step.Stage == "qualified" && step.Decision != nil {
			t.Fatalf("admission produced a qualified step: %+v", step)
		}
	}
}

// A rollback that has started is not reported as rolled back, and an
// aborted rollout is a failed outcome, not a running lane.
func TestRollbackInProgressAndAbortedOutcomes(t *testing.T) {
	t.Parallel()
	rolling := releaseLabel(t, decisionlog.Decision{ID: "rb", Time: testNow, Region: "fra",
		Kind: decisionlog.KindRollback, Subject: release, Status: decisionlog.StatusInProgress})
	if rolling.Status != "serious" || !strings.HasPrefix(rolling.Label, "rolling back") {
		t.Fatalf("rollback in progress = %s %q", rolling.Status, rolling.Label)
	}
	done := releaseLabel(t, decisionlog.Decision{ID: "rb", Time: testNow, Region: "fra",
		Kind: decisionlog.KindRollback, Subject: release, Status: decisionlog.StatusRolledBack})
	if !strings.HasPrefix(done.Label, "rolled back") {
		t.Fatalf("finished rollback = %q", done.Label)
	}
	aborted := releaseLabel(t, decisionlog.Decision{ID: "ab", Time: testNow, Region: "fra",
		Kind: decisionlog.KindHeld, Subject: release, Status: decisionlog.StatusFailed,
		Attrs: map[string]string{"phase": "aborted"}})
	if aborted.Status != "bad" || !strings.HasPrefix(aborted.Label, "aborted") {
		t.Fatalf("aborted rollout = %s %q", aborted.Status, aborted.Label)
	}
}

// The rollout producer names its subject "<kind>/<rollout>"; that label is
// not a version, and a release whose start was not observed does not
// outrank one whose admission was.
func TestTargetVersionUsesVersionIdentityAndObservedStarts(t *testing.T) {
	t.Parallel()
	rollout := decisionlog.Subject{Kind: "release", ID: "sha256:cccc", Name: "orchestrator/ro-7"}
	if got := releaseVersion(decisionlog.Decision{Subject: rollout}, rollout.ID); got != "sha256:cccc" {
		t.Fatalf("rollout producer version = %q", got)
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
	if target := current.targetVersion("controller"); target != "v2" {
		t.Fatalf("target = %q, want v2 whose start was observed", target)
	}
}

// The rollout diagram reads the rollout state machine's phases.
func TestRolloutDiagramReadsStateMachinePhases(t *testing.T) {
	t.Parallel()
	for phase, want := range map[string]string{"canary": "canary", "canary-soak": "soak", "batch": "batches",
		"batch-soak": "batches", "complete": "complete", "preflight": ""} {
		if got := rolloutStep(phase); got != want {
			t.Errorf("rolloutStep(%q) = %q, want %q", phase, got, want)
		}
	}
	soaking := insights.Rollout{Phase: "canary-soak"}
	if phaseStatus(soaking, "canary", testNow) != "ok" || phaseStatus(soaking, "soak", testNow) != "run" ||
		phaseStatus(soaking, "batches", testNow) != "idle" {
		t.Fatal("a canary soak is not drawn on the soak step")
	}
	if rolloutStatus(insights.Rollout{Phase: "rolled-back", Done: true}, testNow) != "serious" ||
		rolloutStatus(insights.Rollout{Phase: "aborted", Done: true}, testNow) != "bad" {
		t.Fatal("terminal failures read as complete")
	}
}

// Heatmap columns are never finer than the samples, so continuous 1m
// rollups in a 1h view fill every column.
func TestHeatmapColumnsFollowTheSampleResolution(t *testing.T) {
	t.Parallel()
	current := view{State: parseState(url.Values{"range": {"1h"}}), Now: testNow}
	var points [][2]float64
	for minute := 60; minute >= 0; minute-- {
		points = append(points, [2]float64{float64(testNow.Add(-time.Duration(minute) * time.Minute).UnixMilli()), 0.5})
	}
	spec := current.heatmap("percent", []chartSeries{{Name: "m", Points: points}}, "empty")
	if spec.Step < time.Minute.Milliseconds() {
		t.Fatalf("step %dms is finer than the 1m samples", spec.Step)
	}
	columns := (spec.End - spec.Start + spec.Step - 1) / spec.Step
	if int64(len(spec.Heat)) != columns {
		t.Fatalf("heat cells = %d, want every one of %d columns filled", len(spec.Heat), columns)
	}
}

// A slow fill near 100% that rounding would flatten is still forecast.
func TestStorageForecastFitsRawSamples(t *testing.T) {
	t.Parallel()
	history := observability.NewHistory(observability.HistoryConfig{})
	for minute := 24 * 60; minute >= 0; minute -= 10 {
		history.Append(testNow.Add(-time.Duration(minute)*time.Minute), []observability.Sample{{Metric: observability.HistFSRatio,
			Labels: observability.L("member", "ctl-1", "role", "nats"), Value: 0.99994 - float64(minute)/(24*60)*0.00003}})
	}
	current := view{State: parseState(url.Values{}), Now: testNow, Journal: &Journal{History: history}}
	forecasts, _ := current.storageForecasts()
	if len(forecasts) != 1 || !forecasts[0].Known || !forecasts[0].Trend {
		t.Fatalf("forecasts = %+v, want a known fill from the raw trend", forecasts)
	}
}

// A failed volume read is not "no block volume is attached".
func TestStoragePageNamesAFailedVolumeRead(t *testing.T) {
	t.Parallel()
	current := view{Page: page{slug: "storage"}, State: parseState(url.Values{}), Now: testNow,
		Journal: &Journal{Volumes: failingVolumeProvider{}}, Unavailable: []string{"volumes"}}
	var body strings.Builder
	if err := storageBody(current).Render(context.Background(), &body); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body.String(), "No block volume is attached") || !strings.Contains(body.String(), "could not be read") {
		t.Fatalf("storage page with a failed volume read = %s", body.String())
	}
}

type failingVolumeProvider struct{}

func (failingVolumeProvider) Volumes(context.Context) ([]insights.Volume, error) {
	return nil, errors.New("placement store timeout")
}
