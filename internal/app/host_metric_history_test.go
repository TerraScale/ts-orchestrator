package app

import (
	"context"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

func TestHostMetricHistoryReplaysWithoutMemberSnapshotOverlap(t *testing.T) {
	js := testRolloutJetStream(t)
	writer, err := observability.OpenHostMetricStream(t.Context(), js, "gru", 1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Minute)
	for _, at := range []time.Time{now.Add(-13 * 24 * time.Hour), now} {
		if _, err := writer.Publish(t.Context(), observability.HostMetricBatch{Version: observability.HostMetricBatchVersion, At: at, Epoch: 1,
			Samples: []observability.Sample{{Metric: observability.HistHostCPUUtilization,
				Labels: observability.L("member", "host-a"), Value: 0.25}}}); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	for range 2 {
		local := observability.NewHistory(observability.HistoryConfig{})
		local.Append(now, []observability.Sample{
			{Metric: observability.HistHostCPUUtilization, Labels: observability.L("member", "host-a"), Value: 0.99},
			{Metric: observability.HistCPUUtilization, Labels: observability.L("member", "ctl-a"), Value: 0.8}})
		h := &hostMetricHistory{local: local,
			shared: observability.NewHistory(observability.HistoryConfig{Interval: observability.HostMetricInterval})}
		query := observability.HistoryQuery{Metric: observability.HistHostCPUUtilization,
			Labels: map[string]string{"member": "host-a"}, Start: now.Add(-14 * 24 * time.Hour), End: now}
		if result := h.Range(query); !result.Pending || len(result.Series) != 0 {
			t.Fatalf("member snapshot masked regional replay: %+v", result)
		}
		done := make(chan struct{})
		go func() { h.run(ctx, js, "gru", 1, nil, nil); close(done) }()
		t.Cleanup(func() { cancel(); <-done })
		for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
			result := h.Range(query)
			if !result.Pending && len(result.Series) == 1 && len(result.Series[0].Points) == 2 {
				for _, point := range result.Series[0].Points {
					if point.Value != 0.25 {
						t.Fatalf("member-local value leaked: %+v", result)
					}
				}
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("shared history not replayed: %+v", result)
			}
		}
		query.Metric, query.Labels = observability.HistCPUUtilization, map[string]string{"member": "ctl-a"}
		if result := h.Range(query); result.Pending || len(result.Series) != 1 || result.Series[0].Points[0].Value != 0.8 {
			t.Fatalf("controller history not isolated: %+v", result)
		}
	}
}
