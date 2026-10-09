package app

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
)

func TestHostMetricHistoryDisclosesArchiveOmissionsAfterRestart(t *testing.T) {
	js := testRolloutJetStream(t)
	writer, err := observability.OpenHostMetricStream(t.Context(), js, "gru", 1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(observability.HostMetricInterval)
	load := overflowingHostMetricLoad(t, 1)
	dropped, confirmed, err := publishHostMetricBatch(t.Context(), writer, load, load.archiveBatch(now.Add(-time.Minute)))
	if err != nil || !confirmed || dropped != 58 {
		t.Fatalf("overflow publish: dropped=%d confirmed=%t err=%v", dropped, confirmed, err)
	}
	// A newer complete batch cannot erase loss in the retained archive.
	if confirmed, err := writer.Publish(t.Context(), observability.HostMetricBatch{At: now, Epoch: 2,
		Samples: []observability.Sample{{Metric: observability.HistHostCPUUtilization,
			Labels: observability.L("member", "host-000"), Value: 0.25}}}); err != nil || !confirmed {
		t.Fatalf("complete publish: confirmed=%t err=%v", confirmed, err)
	}
	// Each controller starts with no publisher counters or previous replay state.
	for range 2 {
		h := &hostMetricHistory{local: observability.NewHistory(observability.HistoryConfig{}),
			shared: observability.NewHistory(observability.HistoryConfig{Interval: observability.HostMetricInterval})}
		h.local.Append(now, []observability.Sample{{Metric: observability.HistCPUUtilization,
			Labels: observability.L("member", "ctl-a"), Value: 0.8}})
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() { h.run(ctx, js, "gru", 1, nil, nil); close(done) }()
		t.Cleanup(func() { cancel(); <-done })
		for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
			if stream := h.stream.Load(); stream != nil && stream.CaughtUp() {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("archive replay did not catch up")
			}
		}
		query := observability.HistoryQuery{Metric: observability.HistHostCPUUtilization,
			Labels: map[string]string{"member": "host-000"}, Start: now.Add(-time.Hour), End: now}
		result := h.Range(query)
		if result.Pending || !result.Incomplete || len(result.Series) != 1 || len(result.Series[0].Points) != 2 {
			t.Fatalf("retained data hid archive omissions: %+v", result)
		}
		query.Metric = observability.HistServiceMemoryUsed
		query.Labels = map[string]string{"member": "host-061", "service": "role-31"}
		if result := h.Range(query); result.Pending || !result.Incomplete || len(result.Series) != 0 {
			t.Fatalf("omitted service appeared complete: %+v", result)
		}
		if h.shared.Stats().Dropped != 0 || h.droppedSamples.Load() != 0 || h.stream.Load().ReplayFailures() != 0 {
			t.Fatal("archive omissions confused with local counters, cache loss, or invalid records")
		}
		query.Metric, query.Labels = observability.HistCPUUtilization, map[string]string{"member": "ctl-a"}
		if result := h.Range(query); result.Pending || result.Incomplete || len(result.Series) != 1 {
			t.Fatalf("resource archive loss contaminated controller history: %+v", result)
		}
		var metrics bytes.Buffer
		h.writeMetrics(&metrics)
		if !strings.Contains(metrics.String(), "ts_orch_host_history_replay_ready 0\n") ||
			!strings.Contains(metrics.String(), "ts_orch_host_history_archive_incomplete 1\n") {
			t.Fatalf("replicated archive omissions absent from readiness/coverage metrics: %s", metrics.String())
		}
		cancel()
		<-done
	}
}
