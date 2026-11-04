package observability

import (
	"slices"
	"testing"
	"time"
)

func hostMetricWANBatch(at time.Time) HostMetricBatch {
	labels := L("member", "node-a", "node", "Node-A", "role", "terrabase", "receiver_region", "gru-native", "source_region", "west-native")
	batch := HostMetricBatch{Version: HostMetricBatchVersion, At: at, Epoch: 1,
		Samples: []Sample{{Metric: HistHostReceivedAt, Labels: L("member", "node-a"), Value: float64(at.Add(30 * time.Second).UnixMilli())}}}
	for _, reading := range []struct {
		metric string
		value  float64
	}{
		{HistTerraBaseWANObservedAt, float64(at.Add(20 * time.Second).UnixMilli())},
		{HistTerraBaseWANLagGroups, 7}, {HistTerraBaseWANStaleness, 12.5}, {HistTerraBaseWANMembers, 3},
		{HistTerraBaseWANUnregistered, 2}, {HistTerraBaseWANConflicts, 1}, {HistTerraBaseWANAheadFailures, 4},
	} {
		batch.Samples = append(batch.Samples, Sample{Metric: reading.metric, Labels: slices.Clone(labels), Value: reading.value})
	}
	return batch
}

func TestHostMetricWANPublishesAndReplaysOriginalScrapeBatches(t *testing.T) {
	srv := hostMetricBroker(t, t.TempDir(), -1)
	writer := hostMetricTestStream(t, srv)
	now := time.Now().UTC().Truncate(HostMetricInterval)
	old := hostMetricWANBatch(now.Add(-10 * time.Minute))
	current := hostMetricWANBatch(now.Add(-HostMetricInterval))
	current.Samples[7].Value = 1 // A real native counter reset remains a lower cumulative reading.
	cleared := HostMetricBatch{Version: HostMetricBatchVersion, At: now, Epoch: 1,
		Samples: []Sample{{Metric: HistHostReceivedAt, Labels: L("member", "node-a"), Value: float64(now.UnixMilli())}}}
	for _, batch := range []HostMetricBatch{old, current, cleared} {
		if confirmed, err := writer.Publish(t.Context(), batch); err != nil || !confirmed {
			t.Fatalf("WAN publish = %v, %v", confirmed, err)
		}
	}
	// Independent controller readers replay the same regional delivery history.
	for range 2 {
		reader := hostMetricTestStream(t, srv)
		history := NewHistory(HistoryConfig{Interval: HostMetricInterval})
		hostMetricTail(t, reader, history)
		hostMetricWait(t, reader.CaughtUp)
		for _, reading := range current.Samples[1:] {
			result := history.Range(HistoryQuery{Metric: reading.Metric, Labels: map[string]string{"member": "node-a", "receiver_region": "gru-native", "source_region": "west-native"},
				Start: old.At.Add(-HostMetricInterval), End: now, Tier: TierRaw})
			if len(result.Series) != 1 || len(result.Series[0].Points) != 2 {
				t.Fatalf("WAN replay %s = %+v", reading.Metric, result)
			}
			last := result.Series[0].Points[1]
			if !last.Time.Equal(current.At) || last.Value != reading.Value {
				t.Fatalf("scrape values/time refreshed by replay: %+v", last)
			}
		}
		received := history.Range(HistoryQuery{Metric: HistHostReceivedAt, Labels: map[string]string{"member": "node-a"}, Start: old.At, End: now, Tier: TierRaw})
		if len(received.Series) != 1 || len(received.Series[0].Points) != 3 || !received.Series[0].Points[2].Time.Equal(now) {
			t.Fatalf("latest report did not create a separate WAN-absent batch: %+v", received)
		}
		if reader.ReplayFailures() != 0 || reader.ArchiveIncomplete() {
			t.Fatal("valid WAN replay was marked incomplete")
		}
	}
}
