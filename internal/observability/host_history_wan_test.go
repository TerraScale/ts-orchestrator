package observability

import (
	"fmt"
	"math"
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

func TestHostMetricWANValidatesLabelsCountsAndOriginalFreshness(t *testing.T) {
	at := time.Now().UTC().Truncate(HostMetricInterval)
	valid := hostMetricWANBatch(at)
	hostMetricAcceptArchive(t, valid)
	for name, change := range map[string]func(*HostMetricBatch){
		"NaN":                func(b *HostMetricBatch) { b.Samples[2].Value = math.NaN() },
		"infinity":           func(b *HostMetricBatch) { b.Samples[3].Value = math.Inf(1) },
		"negative":           func(b *HostMetricBatch) { b.Samples[2].Value = -1 },
		"fractional members": func(b *HostMetricBatch) { b.Samples[4].Value = 1.5 },
		"inexact count":      func(b *HostMetricBatch) { b.Samples[2].Value = 1 << 53 },
		"missing label":      func(b *HostMetricBatch) { b.Samples[2].Labels = b.Samples[2].Labels[:4] },
		"duplicate label":    func(b *HostMetricBatch) { b.Samples[2].Labels = append(b.Samples[2].Labels, b.Samples[2].Labels[0]) },
		"extra label": func(b *HostMetricBatch) {
			b.Samples[2].Labels = append(b.Samples[2].Labels, Label{Name: "source_cell", Value: "sfo"})
		},
		"different node":        func(b *HostMetricBatch) { b.Samples[2].Labels[1].Value = "node-b" },
		"different role":        func(b *HostMetricBatch) { b.Samples[2].Labels[2].Value = "api" },
		"display receiver":      func(b *HostMetricBatch) { b.Samples[2].Labels[3].Value = "GRU" },
		"inconsistent receiver": func(b *HostMetricBatch) { b.Samples[2].Labels[3].Value = "another-native" },
		"invalid source":        func(b *HostMetricBatch) { b.Samples[2].Labels[4].Value = "west_native" },
		"duplicate series":      func(b *HostMetricBatch) { b.Samples = append(b.Samples, b.Samples[2]) },
		"counter flag":          func(b *HostMetricBatch) { b.Samples[7].Counter = true },
		"zero time":             func(b *HostMetricBatch) { b.Samples[1].Value = 0 },
		"fractional time":       func(b *HostMetricBatch) { b.Samples[1].Value += 0.5 },
		"future batch time": func(b *HostMetricBatch) {
			b.Samples[1].Value = float64(at.Add(HostMetricInterval + time.Second).UnixMilli())
		},
		"after receipt": func(b *HostMetricBatch) { b.Samples[1].Value = b.Samples[0].Value + 1 },
		"stale original time": func(b *HostMetricBatch) {
			b.Samples[1].Value = float64(at.Add(-2*time.Minute - time.Millisecond).UnixMilli())
		},
		"inconsistent scrape times": func(b *HostMetricBatch) {
			sample := b.Samples[1]
			sample.Labels = slices.Clone(sample.Labels)
			sample.Labels[4].Value = "east-native"
			sample.Value--
			b.Samples = append(b.Samples, sample)
		},
		"source bound": func(b *HostMetricBatch) {
			for i := range 65 {
				sample := b.Samples[2]
				sample.Labels = slices.Clone(sample.Labels)
				sample.Labels[4].Value = fmt.Sprintf("native-%d", i)
				b.Samples = append(b.Samples, sample)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			batch := hostMetricWANBatch(at)
			change(&batch)
			hostMetricRejectArchive(t, batch)
		})
	}
	// Zero members and missing optional counter remain honest failure/unknown data.
	valid.Samples[4].Value = 0
	valid.Samples = valid.Samples[:7]
	hostMetricAcceptArchive(t, valid)
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
