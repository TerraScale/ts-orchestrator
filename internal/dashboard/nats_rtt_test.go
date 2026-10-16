package dashboard

import (
	"encoding/json/v2"
	"fmt"
	"html"
	"math"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

func TestNATSRouteRTTReachesTheRenderedChartWithoutRoundingToZero(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	history := observability.NewHistory(observability.HistoryConfig{})
	for _, pair := range []struct{ server, peer string }{{"gru-a", "gru-b"}, {"gru-b", "gru-a"}} {
		history.Append(now, []observability.Sample{{Metric: observability.HistNATSRouteRTT,
			Labels: observability.L("member", pair.server, "server", pair.server, "peer", pair.peer), Value: .00001337}})
	}
	current := view{Now: now, State: parseState(url.Values{}), Journal: &Journal{History: history}}
	body := fixturePage(t, current, "/nats")
	for _, match := range regexp.MustCompile(`data-spec="([^"]*)"`).FindAllStringSubmatch(body, -1) {
		var chart chartSpec
		if err := json.Unmarshal([]byte(html.UnescapeString(match[1])), &chart); err != nil {
			t.Fatal(err)
		}
		if chart.Unit != "latency" {
			continue
		}
		if len(chart.Series) != 2 || chart.Series[0].Name != "gru-a / gru-b" || chart.Series[1].Name != "gru-b / gru-a" {
			t.Fatalf("directed route series = %+v", chart.Series)
		}
		for _, series := range chart.Series {
			if len(series.Points) != 1 || series.Points[0][1] != .00001337 {
				t.Fatalf("measured RTT lost precision: %+v", series)
			}
		}
		return
	}
	t.Fatal("NATS page did not render route RTT history")
}

func TestNATSRouteRTTShowsUnknownPartialStaleAndTruncatedEvidence(t *testing.T) {
	t.Parallel()
	member := memberSnapshot()
	member.ObservedAt = testNow
	member.NATS.RouteRTTs = []observability.RouteRTTView{
		{RemoteName: "measured-peer", Connections: 3, MeasuredConnections: 2, RTTSeconds: new(.00001337)},
		{RemoteName: "unmeasured-peer", Connections: 3},
	}
	member.NATS.RouteRTTsTruncated = true
	current := view{Local: &member, Now: testNow, State: parseState(url.Values{})}
	body := fixturePage(t, current, "/nats")
	for _, want := range []string{"measured-peer", "unmeasured-peer", "13.37µs", "2 / 3", "0 / 3", "unavailable", "omitted peers have unknown RTT"} {
		if !strings.Contains(body, want) {
			t.Errorf("NATS route evidence lacks %q", want)
		}
	}
	if strings.Contains(body, "not sampled yet") {
		t.Error("NATS route panel still claims RTT is never collected")
	}
	member.ObservedAt = testNow.Add(-10 * time.Minute)
	if body := fixturePage(t, current, "/nats"); !strings.Contains(body, "13.37µs (stale)") {
		t.Error("old snapshot RTT was shown as current")
	}
	member.Errors = map[string]string{"nats": "unavailable"}
	if body := fixturePage(t, current, "/nats"); strings.Contains(body, "13.37µs") {
		t.Error("failed NATS collection was presented as a valid route RTT")
	}
}

func TestNATSRouteRTTHistoryDisclosesOmittedObservations(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	for _, count := range []int{1, 65} {
		history := observability.NewHistory(observability.HistoryConfig{})
		for index := range count {
			history.Append(now, []observability.Sample{{Metric: observability.HistNATSRouteRTT,
				Labels: observability.L("server", "gru-a", "peer", fmt.Sprintf("peer-%03d", index)), Value: .00001337}})
		}
		var source observability.HistorySource = history
		if count == 1 {
			source = incompleteHostHistory{history}
		}
		current := view{Now: now, State: parseState(url.Values{}), Journal: &Journal{History: source}}
		chart := routeChartPage(t, current)
		if len(chart.Series) != min(count, 64) {
			t.Fatalf("%d observations returned %d series", count, len(chart.Series))
		}
		if body := fixturePage(t, current, "/nats"); !strings.Contains(body, "Route RTT history is partial;") {
			t.Fatalf("%d observations hid partial history", count)
		}
	}
}

func TestNATSRouteRTTEmptyInventoryRequiresCompleteCollection(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name      string
		routes    int
		truncated bool
		failed    bool
		empty     bool
	}{
		{name: "complete empty", empty: true},
		{name: "unidentified connections", routes: 2, truncated: true},
		{name: "reported connections", routes: 2},
		{name: "omitted inventory", truncated: true},
		{name: "failed collector", failed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			member := memberSnapshot()
			member.NATS.Routes = test.routes
			member.NATS.RouteRTTsTruncated = test.truncated
			if test.failed {
				member.Errors = map[string]string{"nats": "unavailable"}
			}
			current := view{Local: &member, Now: testNow, State: parseState(url.Values{})}
			body := fixturePage(t, current, "/nats")
			if strings.Contains(body, "No route connections reported.") != test.empty {
				t.Fatalf("unproven empty route inventory: routes=%d truncated=%v failed=%v", test.routes, test.truncated, test.failed)
			}
			if strings.Contains(body, "Route inventory unavailable.") == test.empty {
				t.Fatal("empty and unavailable inventory states were not distinguished")
			}
		})
	}
}

func TestNATSRouteRTTHistoryKeepsCollectionGapsAfterRecovery(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Minute)
	for _, test := range []struct {
		name    string
		gapAt   time.Time
		rangeID string
		partial bool
	}{
		{name: "recent omission", gapAt: now.Add(-2 * time.Minute), partial: true},
		{name: "rolled up omission", gapAt: now.Add(-2 * time.Minute), rangeID: "6h", partial: true},
		{name: "outside selected range", gapAt: now.Add(-2 * time.Hour)},
		{name: "always complete"},
	} {
		t.Run(test.name, func(t *testing.T) {
			history := observability.NewHistory(observability.HistoryConfig{})
			member := memberSnapshot()
			member.NATS.RouteRTTs = []observability.RouteRTTView{{RemoteName: "ctl-2", Connections: 2,
				MeasuredConnections: 2, RTTSeconds: new(.00001337)}}
			cluster := observability.ClusterSnapshot{Members: []observability.MemberSnapshot{member}}
			sampler := new(observability.SnapshotSampler)
			if !test.gapAt.IsZero() {
				member.NATS.RouteRTTsTruncated = true
				history.Append(test.gapAt, sampler.Samples(cluster))
			}
			member.NATS.RouteRTTsTruncated = false
			member.ObservedAt = now
			history.Append(now, sampler.Samples(cluster))
			current := view{Local: &member, Now: now, State: parseState(url.Values{"range": {test.rangeID}}), Journal: &Journal{History: history}}
			chart := routeChartPage(t, current)
			if len(chart.Series) != 1 || (chart.Warning != "") != test.partial {
				t.Fatalf("route history after recovery: series=%d warning=%q; partial=%v", len(chart.Series), chart.Warning, test.partial)
			}
			body := fixturePage(t, current, "/nats")
			if strings.Contains(body, "Route RTT history is partial;") != test.partial || strings.Contains(body, "Route inventory is partial;") {
				t.Fatal("historical collection gaps were hidden or current recovery was ignored")
			}
		})
	}
}

func TestNATSRouteRTTHistoryPreservesBucketPeaks(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Minute).Add(-30 * time.Second)
	history := observability.NewHistory(observability.HistoryConfig{})
	member := memberSnapshot()
	member.NATS.RouteRTTs = []observability.RouteRTTView{{RemoteName: "ctl-2", Connections: 2, MeasuredConnections: 2}}
	sampler := new(observability.SnapshotSampler)
	for index, rtt := range []float64{.00001337, .009, .00001337} {
		member.NATS.RouteRTTs[0].RTTSeconds = new(rtt)
		history.Append(now.Add(time.Duration(index-2)*10*time.Second), sampler.Samples(observability.ClusterSnapshot{Members: []observability.MemberSnapshot{member}}))
	}
	for _, rangeID := range []string{"15m", "1h", "6h", "24h", "7d"} {
		t.Run(rangeID, func(t *testing.T) {
			current := view{Now: now, State: parseState(url.Values{"range": {rangeID}}), Journal: &Journal{History: history}}
			chart := routeChartPage(t, current)
			if len(chart.Series) != 1 {
				t.Fatalf("route series = %+v", chart.Series)
			}
			points := chart.Series[0].Points
			if rangeID == "15m" {
				if len(points) != 3 || points[0][1] != .00001337 || points[1][1] != .009 || points[2][1] != .00001337 {
					t.Fatalf("raw RTT readings changed: %+v", points)
				}
			} else if len(points) != 1 || points[0][1] != .009 {
				t.Fatalf("RTT spike was averaged away: %+v", points)
			}
		})
	}
}

func TestNATSRouteRTTHistoryValidatesSelectedPeak(t *testing.T) {
	t.Parallel()
	result := observability.HistoryResult{Series: []observability.HistorySeries{{Points: []observability.Point{
		{Time: testNow, Value: 2, Max: 4},
		{Time: testNow.Add(time.Second), Value: 2, Max: math.NaN()},
		{Time: testNow.Add(2 * time.Second), Value: 2, Max: math.Inf(1)},
	}}}}

	current := view{Now: testNow, Journal: &Journal{History: peakHistory{result: result}}}
	chart := routeChartPage(t, current)
	if len(chart.Series) != 1 || len(chart.Series[0].Points) != 1 || chart.Series[0].Points[0][1] != 4 {
		t.Fatalf("invalid RTT peaks reached chart: %+v", chart)
	}
}

func TestNATSRouteRTTHistoryDisclosesUnmeasuredConnections(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Minute).Add(-30 * time.Second)
	for _, test := range []struct {
		name     string
		measured int
		gapAt    time.Time
		partial  bool
	}{
		{name: "partial", measured: 1, gapAt: now.Add(-20 * time.Second), partial: true},
		{name: "entirely unmeasured", gapAt: now.Add(-20 * time.Second), partial: true},
		{name: "complete changing count", measured: 2, gapAt: now.Add(-20 * time.Second)},
		{name: "outside selected range", measured: 1, gapAt: now.Add(-8 * 24 * time.Hour)},
	} {
		for _, rangeID := range []string{"15m", "1h", "6h", "24h", "7d"} {
			t.Run(test.name+"/"+rangeID, func(t *testing.T) {
				history := observability.NewHistory(observability.HistoryConfig{})
				member := memberSnapshot()
				member.NATS.RouteRTTs = []observability.RouteRTTView{{RemoteName: "ctl-2", Connections: 2, MeasuredConnections: test.measured}}
				if test.measured > 0 {
					member.NATS.RouteRTTs[0].RTTSeconds = new(.009)
				}
				cluster := observability.ClusterSnapshot{Members: []observability.MemberSnapshot{member}}
				sampler := new(observability.SnapshotSampler)
				history.Append(test.gapAt, sampler.Samples(cluster))
				member.NATS.RouteRTTs[0] = observability.RouteRTTView{RemoteName: "ctl-2", Connections: 3, MeasuredConnections: 3, RTTSeconds: new(.00001337)}
				history.Append(now, sampler.Samples(cluster))
				current := view{Local: &member, Now: now, State: parseState(url.Values{"range": {rangeID}}), Journal: &Journal{History: history}}
				if chart := routeChartPage(t, current); len(chart.Series) != 1 || (chart.Warning != "") != test.partial {
					t.Fatalf("measurement coverage after recovery: series=%d warning=%q; partial=%v", len(chart.Series), chart.Warning, test.partial)
				}
			})
		}
	}
}

func TestNATSRouteRTTHistoryRequiresCompleteCoverageEvidence(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Minute)
	for _, test := range []struct {
		name    string
		peers   int
		omit    []string
		partial bool
	}{
		{name: "complete", peers: 1},
		{name: "unmeasured peer without RTT", peers: 2, partial: true},
		{name: "coverage exceeds query bound", peers: 65, partial: true},
		{name: "missing totals", peers: 1, omit: []string{observability.HistNATSRouteConnections}, partial: true},
		{name: "missing measured counts", peers: 1, omit: []string{observability.HistNATSRouteMeasuredConnections}, partial: true},
		{name: "missing both counts", peers: 1, omit: []string{observability.HistNATSRouteConnections, observability.HistNATSRouteMeasuredConnections}, partial: true},
		{name: "missing RTT with equal counts", peers: 1, omit: []string{observability.HistNATSRouteRTT}, partial: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			history := observability.NewHistory(observability.HistoryConfig{})
			member := memberSnapshot()
			for index := range test.peers {
				member.NATS.RouteRTTs = append(member.NATS.RouteRTTs, observability.RouteRTTView{RemoteName: fmt.Sprintf("peer-%03d", index), Connections: 2})
			}
			member.NATS.RouteRTTs[0].MeasuredConnections = 2
			member.NATS.RouteRTTs[0].RTTSeconds = new(.00001337)
			sampler := new(observability.SnapshotSampler)
			samples := sampler.Samples(observability.ClusterSnapshot{Members: []observability.MemberSnapshot{member}})
			samples = slices.DeleteFunc(samples, func(sample observability.Sample) bool { return slices.Contains(test.omit, sample.Metric) })
			history.Append(now, samples)
			data, err := history.Export(0)
			if err != nil {
				t.Fatal(err)
			}
			restored := observability.NewHistory(observability.HistoryConfig{})
			if err := restored.Import(data); err != nil {
				t.Fatal(err)
			}
			for _, source := range []*observability.History{history, restored} {
				current := view{Now: now, State: parseState(url.Values{}), Journal: &Journal{History: source}}
				wantSeries := 1
				if slices.Contains(test.omit, observability.HistNATSRouteRTT) {
					wantSeries = 0
				}
				if chart := routeChartPage(t, current); len(chart.Series) != wantSeries || (chart.Warning != "") != test.partial {
					t.Fatalf("coverage evidence: series=%d warning=%q; partial=%v", len(chart.Series), chart.Warning, test.partial)
				}
			}
		})
	}
}

func TestNATSRouteRTTHistoryMatchesRestoredAndFreshCoverage(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Minute).Add(-30 * time.Second)
	for _, gapAge := range []time.Duration{20 * time.Second, 2 * time.Minute, 2 * time.Hour} {
		t.Run(gapAge.String(), func(t *testing.T) {
			history := observability.NewHistory(observability.HistoryConfig{})
			member := memberSnapshot()
			member.NATS.RouteRTTs = []observability.RouteRTTView{{RemoteName: "ctl-2", Connections: 2}}
			cluster := observability.ClusterSnapshot{Members: []observability.MemberSnapshot{member}}
			sampler := new(observability.SnapshotSampler)
			history.Append(now.Add(-gapAge), sampler.Samples(cluster))
			data, err := history.Export(0)
			if err != nil {
				t.Fatal(err)
			}
			restored := observability.NewHistory(observability.HistoryConfig{})
			if err := restored.Import(data); err != nil {
				t.Fatal(err)
			}
			member.NATS.RouteRTTs[0] = observability.RouteRTTView{RemoteName: "ctl-2", Connections: 3, MeasuredConnections: 3, RTTSeconds: new(.00001337)}
			restored.Append(now, sampler.Samples(cluster))
			current := view{Now: now, State: parseState(url.Values{"range": {"15m"}}), Journal: &Journal{History: restored}}
			if chart := routeChartPage(t, current); len(chart.Series) != 1 || (chart.Warning != "") != (gapAge < 15*time.Minute) {
				t.Fatalf("restored coverage: series=%d warning=%q gapAge=%v", len(chart.Series), chart.Warning, gapAge)
			}
		})
	}
}

func TestNATSRouteRTTHistoryKeepsBoundedExportLossAfterRecovery(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Minute).Add(-30 * time.Second)
	labels := observability.L("member", "ctl-1", "server", "ctl-1", "peer", "ctl-2")
	samples := []observability.Sample{
		{Metric: observability.HistNATSRouteConnections, Labels: labels, Value: 2},
		{Metric: observability.HistNATSRouteMeasuredConnections, Labels: labels, Value: 2},
		{Metric: observability.HistNATSRouteRTT, Labels: labels, Value: .009},
		{Metric: "z", Value: 1},
	}
	history := observability.NewHistory(observability.HistoryConfig{})
	history.Append(now.Add(-20*time.Second), samples)
	full, err := history.Export(0)
	if err != nil {
		t.Fatal(err)
	}
	var restored *observability.History
	for limit := len(full) - 1; limit > 0; limit -= 16 {
		data, err := history.Export(limit)
		if err != nil {
			t.Fatal(err)
		}
		candidate := observability.NewHistory(observability.HistoryConfig{})
		if err := candidate.Import(data); err != nil {
			t.Fatal(err)
		}
		if slices.Equal(candidate.Metrics(), []string{observability.HistNATSRouteConnections, observability.HistNATSRouteMeasuredConnections}) {
			restored = candidate
			break
		}
	}
	if restored == nil {
		t.Fatal("bounded export did not retain paired counts while omitting RTT")
	}
	samples[2].Value = .00001337
	restored.Append(now, samples[:3])
	for restart := range 3 {
		for _, rangeID := range []string{"15m", "1h", "6h", "7d"} {
			t.Run(fmt.Sprintf("restart-%d/%s", restart, rangeID), func(t *testing.T) {
				current := view{Now: now, State: parseState(url.Values{"range": {rangeID}}), Journal: &Journal{History: restored}}
				if chart := routeChartPage(t, current); len(chart.Series) != 1 || len(chart.Series[0].Points) != 1 || chart.Warning == "" {
					t.Fatalf("fresh RTT hid an earlier lost peak: %+v", chart)
				}
			})
		}
		data, err := restored.Export(0)
		if err != nil {
			t.Fatal(err)
		}
		restored = observability.NewHistory(observability.HistoryConfig{})
		if err := restored.Import(data); err != nil {
			t.Fatal(err)
		}
		restored.Append(now, samples[:3])
	}
}

func routeChartPage(t *testing.T, current view) chartSpec {
	t.Helper()
	body := fixturePage(t, current, "/nats")
	for _, chart := range pageCharts(t, body) {
		if chart.Unit == "latency" {
			if strings.Contains(body, "Route RTT history is partial;") {
				chart.Warning = "partial"
			}
			return chart
		}
	}
	t.Fatal("NATS route chart missing")
	return chartSpec{}
}

type peakHistory struct {
	observability.HistorySource
	result observability.HistoryResult
}

func (source peakHistory) Range(query observability.HistoryQuery) observability.HistoryResult {
	if query.Metric == observability.HistNATSRouteRTT {
		return source.result
	}
	return observability.HistoryResult{}
}
