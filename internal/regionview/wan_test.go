package regionview

import (
	"context"
	"fmt"
	"maps"
	"reflect"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
)

func wanHistorySamples(at time.Time) []observability.Sample {
	labels := observability.L("member", "node-a", "node", "Node-A", "role", "terrabase", "receiver_region", "sfo-1", "source_region", "gru-1")
	samples := []observability.Sample{{Metric: observability.HistHostReceivedAt,
		Labels: observability.L("member", "node-a"), Value: float64(at.UnixMilli())}}
	for metric, value := range map[string]float64{
		observability.HistTerraBaseWANObservedAt: float64(at.UnixMilli()),
		observability.HistTerraBaseWANLagGroups:  0, observability.HistTerraBaseWANMembers: 3,
		observability.HistTerraBaseWANStaleness: 1, observability.HistTerraBaseWANConflicts: 0,
		observability.HistTerraBaseWANUnregistered: 0, observability.HistTerraBaseWANAheadFailures: 5,
	} {
		samples = append(samples, observability.Sample{Metric: metric, Labels: labels, Value: value})
	}
	return samples
}

func wanNativeSourceSamples(at time.Time, source string, offset int) []observability.Sample {
	samples := wanHistorySamples(at)[1:]
	for index := range samples {
		sample := &samples[index]
		for labelIndex := range sample.Labels {
			if sample.Labels[labelIndex].Name == "source_region" {
				sample.Labels[labelIndex].Value = source
			}
		}
		if sample.Metric == observability.HistTerraBaseWANMembers {
			sample.Value = float64(3 + offset%3)
		} else if sample.Metric != observability.HistTerraBaseWANObservedAt {
			sample.Value += float64(offset)
		}
	}
	return samples
}

type countingWANHistory struct {
	observability.HistorySource
	queries []observability.HistoryQuery
}

func (history *countingWANHistory) Range(query observability.HistoryQuery) observability.HistoryResult {
	history.queries = append(history.queries, query)
	return history.HistorySource.Range(query)
}

func TestWANHistoryQueriesEachGaugeOncePerNode(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	scraped := now.Add(-30 * time.Second)
	nodes := []Node{{Name: "Node-A", Services: []Service{{Role: "terrabase"}}}}
	for _, sources := range []int{1, 3, terrabase.MaxWANRegions, terrabase.MaxWANRegions + 1} {
		t.Run(fmt.Sprint(sources), func(t *testing.T) {
			baseline := observability.NewHistory(observability.HistoryConfig{})
			samples := wanHistorySamples(now)[:1]
			want := make(map[string]WANPeer, sources)
			for index := range sources {
				source := fmt.Sprintf("native-%d", index)
				samples = append(samples, wanNativeSourceSamples(scraped, source, index)...)
				want[source] = WANPeer{SourceRegion: source, Node: "Node-A", ObservedAt: scraped,
					Lag: float64(index), Members: 3 + index%3, StalenessSeconds: float64(1 + index),
					Conflicts: float64(index), Unregistered: float64(index), AheadFailures: new(float64(5 + index))}
			}
			baseline.Append(now, samples)
			history := &countingWANHistory{HistorySource: baseline}
			rows := CollectWAN(nodes, "sfo-1", history, now)
			metrics := []string{observability.HistHostReceivedAt, observability.HistTerraBaseWANObservedAt,
				observability.HistTerraBaseWANLagGroups, observability.HistTerraBaseWANMembers, observability.HistTerraBaseWANStaleness,
				observability.HistTerraBaseWANConflicts, observability.HistTerraBaseWANUnregistered, observability.HistTerraBaseWANAheadFailures}
			if sources > terrabase.MaxWANRegions {
				clear(want)
				metrics = metrics[:2]
			}
			if len(history.queries) != len(metrics) {
				t.Fatalf("%d sources used %d Range calls, want %d", sources, len(history.queries), len(metrics))
			}
			counts := make(map[string]int)
			for _, query := range history.queries {
				counts[query.Metric]++
				labels := map[string]string{"member": "node-a"}
				if query.Metric != observability.HistHostReceivedAt {
					labels["node"], labels["role"], labels["receiver_region"] = "Node-A", "terrabase", "sfo-1"
				}
				if !maps.Equal(query.Labels, labels) || query.MaxSeries != terrabase.MaxWANRegions ||
					query.Tier != observability.TierRaw || query.Rate || !query.Start.Equal(now.Add(-terrabase.WANFreshFor)) || !query.End.Equal(now) {
					t.Fatalf("query changed identity, bound or raw freshness: %+v", query)
				}
			}
			for _, metric := range metrics {
				if counts[metric] != 1 {
					t.Fatalf("metric %s queried %d times, want once", metric, counts[metric])
				}
			}
			if len(rows) != len(want) {
				t.Fatalf("%d sources produced %d rows, want %d", sources, len(rows), len(want))
			}
			for _, row := range rows {
				if !reflect.DeepEqual(row, want[row.SourceRegion]) {
					t.Fatalf("source values or original scrape time changed: got %+v, want %+v", row, want[row.SourceRegion])
				}
				delete(want, row.SourceRegion)
			}
		})
	}
}

func TestWANHistorySeparatesSourcesAndLatestBatch(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	batchAt := now.Add(-10 * time.Second)
	scraped := now.Add(-30 * time.Second)
	nodes := []Node{{Name: "Node-A", Services: []Service{{Role: "terrabase"}}}}
	for _, test := range []struct {
		name, omit, newer string
		wantRows          int
		missingAhead      bool
	}{
		{name: "complete", wantRows: 3},
		{name: "missing gauge", omit: observability.HistTerraBaseWANLagGroups, wantRows: 2},
		{name: "missing marker", omit: observability.HistTerraBaseWANObservedAt, wantRows: 2},
		{name: "missing optional ahead", omit: observability.HistTerraBaseWANAheadFailures, wantRows: 3, missingAhead: true},
		{name: "newer gauge", newer: observability.HistTerraBaseWANLagGroups, wantRows: 2},
		{name: "newer marker", newer: observability.HistTerraBaseWANObservedAt, wantRows: 2},
		{name: "newer optional ahead", newer: observability.HistTerraBaseWANAheadFailures, wantRows: 3, missingAhead: true},
		{name: "newer report", newer: observability.HistHostReceivedAt, wantRows: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			baseline := observability.NewHistory(observability.HistoryConfig{})
			oldSamples := wanHistorySamples(now.Add(-time.Minute))[:1]
			samples := wanHistorySamples(batchAt)[:1]
			var newer []observability.Sample
			for index, source := range []string{"gru-1", "iad-1", "phx-1"} {
				oldSamples = append(oldSamples, wanNativeSourceSamples(now.Add(-time.Minute), source, index)...)
				for _, sample := range wanNativeSourceSamples(scraped, source, index) {
					if source == "iad-1" {
						if sample.Metric == test.omit {
							continue
						}
						if sample.Metric == test.newer {
							newer = append(newer, sample)
						}
					}
					samples = append(samples, sample)
				}
			}
			if test.newer == observability.HistHostReceivedAt {
				newer = wanHistorySamples(now)[:1]
			}
			baseline.Append(now.Add(-time.Minute), oldSamples)
			baseline.Append(batchAt, samples)
			baseline.Append(now, newer)
			history := &countingWANHistory{HistorySource: baseline}
			rows := CollectWAN(nodes, "sfo-1", history, now)
			if len(history.queries) != 8 || len(rows) != test.wantRows {
				t.Fatalf("got %d queries and %d rows, want 8 and %d: %+v", len(history.queries), len(rows), test.wantRows, rows)
			}
			for _, row := range rows {
				if !row.ObservedAt.Equal(scraped) {
					t.Fatalf("borrowed old scrape time: %+v", row)
				}
				if row.SourceRegion == "iad-1" && test.wantRows == 2 {
					t.Fatalf("borrowed another source or batch: %+v", row)
				}
				if row.SourceRegion == "iad-1" && test.missingAhead && row.AheadFailures != nil {
					t.Fatalf("borrowed optional counter from another source or batch: %+v", row)
				}
				if row.SourceRegion != "iad-1" && (row.AheadFailures == nil || *row.AheadFailures != row.Lag+5) {
					t.Fatalf("unaffected source lost its counter: %+v", row)
				}
			}
		})
	}
}

func TestWANHistoryPreservesScrapeTimeAndExactHostBinding(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	scraped := now.Add(-30 * time.Second)
	history := observability.NewHistory(observability.HistoryConfig{})
	history.Append(now, wanHistorySamples(scraped))
	nodes := []Node{{Name: "Node-A", Member: "controller-a", Services: []Service{{Role: "terrabase"}}},
		{Name: "unobserved", Member: "node-a", Services: []Service{{Role: "terrabase"}}}}
	rows := CollectWAN(nodes, "sfo-1", history, now)
	if len(rows) != 1 || rows[0].Node != "Node-A" || rows[0].SourceRegion != "gru-1" ||
		!rows[0].ObservedAt.Equal(scraped) || rows[0].Lag != 0 || rows[0].Members != 3 || rows[0].AheadFailures == nil || *rows[0].AheadFailures != 5 {
		t.Fatalf("WAN history changed origin, zero or scrape time: %+v", rows)
	}
	provider := &Provider{Cell: "sfo", History: history, NativeRegion: func() string { return "sfo-1" }, Now: func() time.Time { return now },
		Nodes: func(_ context.Context) []Node { return nodes }}
	if got := provider.Local(t.Context()).TerraBase.WAN; len(got) != 1 {
		t.Fatalf("region summary omitted WAN: %+v", got)
	}
	for _, receiver := range []string{"", "gru-1"} {
		if rows := CollectWAN(nodes, receiver, history, now); len(rows) != 0 {
			t.Fatalf("borrowed WAN from another receiver identity %q: %+v", receiver, rows)
		}
	}
}

func TestWANHistoryDoesNotBorrowOlderReportMetrics(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	nodes := []Node{{Name: "Node-A", Services: []Service{{Role: "terrabase"}}}}
	for _, missing := range []string{observability.HistTerraBaseWANObservedAt, observability.HistTerraBaseWANLagGroups,
		observability.HistTerraBaseWANMembers, observability.HistTerraBaseWANStaleness,
		observability.HistTerraBaseWANConflicts, observability.HistTerraBaseWANUnregistered} {
		t.Run(missing, func(t *testing.T) {
			history := observability.NewHistory(observability.HistoryConfig{})
			history.Append(now.Add(-time.Minute), wanHistorySamples(now.Add(-time.Minute)))
			var samples []observability.Sample
			for _, sample := range wanHistorySamples(now) {
				if sample.Metric != missing {
					samples = append(samples, sample)
				}
			}
			history.Append(now, samples)
			if rows := CollectWAN(nodes, "sfo-1", history, now); len(rows) != 0 {
				t.Fatalf("borrowed old %s: %+v", missing, rows)
			}
		})
	}
}

type partialWANHistory struct {
	observability.HistorySource
	metric string
	state  string
}

func (history partialWANHistory) Range(query observability.HistoryQuery) observability.HistoryResult {
	result := history.HistorySource.Range(query)
	if query.Metric == history.metric {
		result.Pending = history.state == "pending"
		result.Incomplete = history.state == "incomplete"
		result.Truncated = history.state == "truncated"
	}
	return result
}

func TestWANHistoryRejectsPartialReplayAndStaleScrapes(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	history := observability.NewHistory(observability.HistoryConfig{})
	history.Append(now, wanHistorySamples(now))
	nodes := []Node{{Name: "Node-A", Services: []Service{{Role: "terrabase"}}}}
	for _, state := range []string{"pending", "incomplete", "truncated"} {
		for _, metric := range []string{observability.HistHostReceivedAt, observability.HistTerraBaseWANObservedAt,
			observability.HistTerraBaseWANLagGroups, observability.HistTerraBaseWANMembers, observability.HistTerraBaseWANStaleness,
			observability.HistTerraBaseWANConflicts, observability.HistTerraBaseWANUnregistered} {
			if rows := CollectWAN(nodes, "sfo-1", partialWANHistory{history, metric, state}, now); len(rows) != 0 {
				t.Fatalf("partial replay %s %s produced health: %+v", metric, state, rows)
			}
		}
		rows := CollectWAN(nodes, "sfo-1", partialWANHistory{history, observability.HistTerraBaseWANAheadFailures, state}, now)
		if len(rows) != 1 || rows[0].AheadFailures != nil {
			t.Fatalf("partial optional counter %s changed required gauges: %+v", state, rows)
		}
	}
	history = observability.NewHistory(observability.HistoryConfig{})
	history.Append(now, wanHistorySamples(now.Add(-3*time.Minute)))
	if rows := CollectWAN(nodes, "sfo-1", history, now); len(rows) != 0 {
		t.Fatalf("publication refreshed an old scrape: %+v", rows)
	}
}
