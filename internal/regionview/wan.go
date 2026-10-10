package regionview

import (
	"math"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
)

// CollectWAN preserves scrape time and never combines different host reports.
func CollectWAN(nodes []Node, nativeRegion string, history observability.HistorySource, now time.Time) []WANPeer {
	if history == nil || nativeRegion == "" {
		return nil
	}
	var rows []WANPeer
	for _, node := range nodes {
		for _, service := range node.Services {
			if service.Role == "terrabase" {
				rows = append(rows, nodeWAN(node.Name, nativeRegion, history, now)...)
				break
			}
		}
	}
	return rows
}

func nodeWAN(node, nativeRegion string, history observability.HistorySource, now time.Time) []WANPeer {
	query := func(metric string, labels map[string]string) observability.HistoryResult {
		return history.Range(observability.HistoryQuery{Metric: metric, Labels: labels,
			Start: now.Add(-terrabase.WANFreshFor), End: now, Tier: observability.TierRaw, MaxSeries: terrabase.MaxWANRegions})
	}
	complete := func(result observability.HistoryResult) bool {
		return !result.Pending && !result.Incomplete && !result.Truncated
	}
	received := query(observability.HistHostReceivedAt, map[string]string{"member": strings.ToLower(node)})
	if !complete(received) || len(received.Series) != 1 {
		return nil
	}
	batch := latestReading(received.Series[0].Points, now)
	if batch == nil || batch.Value <= 0 || batch.Value > float64(now.UnixMilli()) ||
		now.Sub(time.UnixMilli(int64(batch.Value))) > terrabase.WANFreshFor {
		return nil
	}
	labels := map[string]string{"member": strings.ToLower(node), "node": node, "role": "terrabase", "receiver_region": nativeRegion}
	markers := query(observability.HistTerraBaseWANObservedAt, labels)
	if !complete(markers) {
		return nil
	}
	var gauges [5]observability.HistoryResult
	for index, metric := range []string{observability.HistTerraBaseWANLagGroups, observability.HistTerraBaseWANMembers,
		observability.HistTerraBaseWANStaleness, observability.HistTerraBaseWANConflicts, observability.HistTerraBaseWANUnregistered} {
		gauges[index] = query(metric, labels)
		if !complete(gauges[index]) {
			return nil
		}
	}
	counter := query(observability.HistTerraBaseWANAheadFailures, labels)
	sourceReading := func(result observability.HistoryResult, source string) *Reading {
		var match *observability.HistorySeries
		for index := range result.Series {
			series := &result.Series[index]
			if series.Labels["source_region"] == source {
				if match != nil {
					return nil
				}
				match = series
			}
		}
		if match == nil {
			return nil
		}
		return latestReading(match.Points, now)
	}
	var rows []WANPeer
	for _, marker := range markers.Series {
		observed := latestReading(marker.Points, now)
		if observed == nil || !observed.ObservedAt.Equal(batch.ObservedAt) || observed.Value <= 0 ||
			observed.Value > float64(now.UnixMilli()) || observed.Value != math.Trunc(observed.Value) ||
			marker.Labels["source_region"] == "" {
			continue
		}
		row := WANPeer{SourceRegion: marker.Labels["source_region"],
			Node: node, ObservedAt: time.UnixMilli(int64(observed.Value)).UTC()}
		if now.Sub(row.ObservedAt) > terrabase.WANFreshFor {
			continue
		}
		values := make([]float64, 5)
		valid := true
		for index, result := range gauges {
			reading := sourceReading(result, row.SourceRegion)
			if reading == nil || !reading.ObservedAt.Equal(batch.ObservedAt) || reading.Value > terrabase.WANMaxValue {
				valid = false
				break
			}
			values[index] = reading.Value
		}
		if !valid || values[1] != math.Trunc(values[1]) || values[1] > maxTopologyMembers {
			continue
		}
		row.Lag, row.Members, row.StalenessSeconds, row.Conflicts, row.Unregistered = values[0], int(values[1]), values[2], values[3], values[4]
		if complete(counter) {
			if reading := sourceReading(counter, row.SourceRegion); reading != nil && reading.ObservedAt.Equal(batch.ObservedAt) && reading.Value <= terrabase.WANMaxValue {
				row.AheadFailures = new(reading.Value)
			}
		}
		rows = append(rows, row)
	}
	return rows
}
