package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostload"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionview"
)

type metricTestFence struct{ switchingFencer }

func (f *metricTestFence) Guard(_ context.Context, epoch uint64) error {
	snapshot := f.Current()
	if !snapshot.CanMutate() || snapshot.Epoch != epoch {
		return authority.ErrFenced
	}
	return nil
}

type metricPublishFunc func(context.Context, observability.HostMetricBatch) (bool, error)

func (f metricPublishFunc) Publish(ctx context.Context, batch observability.HostMetricBatch) (bool, error) {
	return f(ctx, batch)
}

func TestHostMetricPublicationFencesAuthorityChanges(t *testing.T) {
	fence := &metricTestFence{}
	leader := authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Ready: true, Leader: true, Epoch: 1, Revision: 1, ExpiresAt: time.Now().Add(time.Hour)}
	fence.set(leader)
	load := &hostTelemetry{fencer: fence, load: hostload.NewAggregator(hostload.AggregatorConfig{})}
	cpu, cores := 0.4, 0.125
	origin := hostload.Origin{Cell: "gru", Environment: "production", Node: "Host-A"}
	report := hostload.Report{SchemaVersion: hostload.SchemaVersion, Host: hostload.HostUsage{CPU: &cpu},
		Roles: []hostload.RoleUsage{{Role: "api", CPUCores: &cores}}}
	if err := load.record(origin, report); err != nil {
		t.Fatal(err)
	}
	batch := load.archiveBatch(time.Now())
	if batch.Epoch != 1 || len(batch.Samples) != 4 || batch.At.Second() != 0 {
		t.Fatalf("batch = %+v", batch)
	}
	calls := 0
	writer := metricPublishFunc(func(context.Context, observability.HostMetricBatch) (bool, error) { calls++; return true, nil })
	if _, _, err := publishHostMetricBatch(t.Context(), writer, load, batch); err != nil || calls != 1 {
		t.Fatalf("current batch publish: calls=%d err=%v", calls, err)
	}
	leader.Epoch = 2
	fence.set(leader)
	if _, _, err := publishHostMetricBatch(t.Context(), writer, load, batch); !errors.Is(err, authority.ErrFenced) || calls != 1 {
		t.Fatalf("previous term published: calls=%d err=%v", calls, err)
	}
	if got := load.archiveBatch(time.Now()); len(got.Samples) != 0 {
		t.Fatal("new term reused old reports")
	}
	if err := load.record(origin, report); err != nil {
		t.Fatal(err)
	}
	fresh := load.archiveBatch(time.Now())
	if fresh.Epoch != 2 || len(fresh.Samples) != 4 {
		t.Fatalf("new term lost fresh reports: %+v", fresh)
	}
	fence.set(authority.Snapshot{})
	if _, _, err := publishHostMetricBatch(t.Context(), writer, load, fresh); !errors.Is(err, authority.ErrFenced) || calls != 1 {
		t.Fatalf("demoted controller published: calls=%d err=%v", calls, err)
	}
}

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

func TestJournalHistoryStartsWithoutPrivateListener(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	broker, err := natscell.Start(ctx, natscell.Config{Cell: "lab", Instance: "history-controller", Replicas: 1, Lab: true,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "nats")}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
	runtime := &runtimeObservability{cell: "lab", member: "history-controller",
		registry: observability.NewRegistry(false), events: observability.NewEventBus(16)}
	runtime.startDecisionJournal(ctx)
	t.Cleanup(runtime.close)
	collector, err := observability.NewCollector(observability.CollectorConfig{Cell: "lab", Member: "history-controller", Role: "controller", Registry: runtime.registry})
	if err != nil {
		t.Fatal(err)
	}
	runtime.attachJournal(ctx, controllerObservation{nats: broker, replicas: 1}, collector, nil)
	providers := runtime.providers.Load()
	if providers == nil || providers.History == nil || runtime.boardJournal == nil {
		t.Fatal("history providers depend on a private listener")
	}
}

func TestHostMetricHistoryPreservesLatestConsumers(t *testing.T) {
	h := &hostMetricHistory{local: observability.NewHistory(observability.HistoryConfig{}),
		shared: observability.NewHistory(observability.HistoryConfig{Interval: observability.HostMetricInterval})}
	now := time.Now()
	h.local.Append(now, []observability.Sample{
		{Metric: observability.HistCPUUtilization, Labels: observability.L("member", "ctl-a"), Value: 0.4},
		{Metric: observability.HistCPUUtilization, Labels: observability.L("member", "ctl-b"), Value: 0.6},
		{Metric: observability.HistTerraBaseLagSeq, Labels: observability.L("member", "host-a", "role", "terrabase"), Value: 12},
		{Metric: observability.HistTerraBaseLagSeq, Labels: observability.L("member", "host-b", "role", "terrabase"), Value: 99},
		{Metric: observability.HistHostCPUUtilization, Labels: observability.L("member", "host-a"), Value: 0.99},
	})
	h.shared.Append(now, []observability.Sample{{Metric: observability.HistHostCPUUtilization,
		Labels: observability.L("member", "host-a"), Value: 0.25}})
	provider := &regionview.Provider{Cell: "gru", History: h}
	if cpu := provider.Local(t.Context()).Capacity.CPUUtilization; cpu != 0.5 {
		t.Fatalf("region CPU summary = %g, want 0.5", cpu)
	}
	// The topology uses this optional method with a member filter.
	var source observability.HistorySource = h
	latest, ok := source.(interface {
		Latest(string, map[string]string) map[string]float64
	})
	if !ok {
		t.Fatal("regional history lost Latest")
	}
	lag := latest.Latest(observability.HistTerraBaseLagSeq, map[string]string{"member": "host-a"})
	if len(lag) != 1 || lag["member=host-a,role=terrabase"] != 12 {
		t.Fatalf("topology lag readings = %v", lag)
	}
	resource := latest.Latest(observability.HistHostCPUUtilization, map[string]string{"member": "host-a"})
	if len(resource) != 1 || resource["member=host-a"] != 0.25 {
		t.Fatalf("regional resource readings = %v", resource)
	}
}

func TestHostMetricHistoryDisclosesReplaySeriesChurn(t *testing.T) {
	js := testRolloutJetStream(t)
	writer, err := observability.OpenHostMetricStream(t.Context(), js, "gru", 1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Minute)
	older := observability.HostMetricBatch{Version: observability.HostMetricBatchVersion, At: now.Add(-13 * 24 * time.Hour), Epoch: 1}
	for index := range observability.DefaultHistorySeries {
		older.Samples = append(older.Samples, observability.Sample{Metric: observability.HistHostCPUUtilization,
			Labels: observability.L("member", fmt.Sprintf("retired-%04d", index)), Value: 0.25})
	}
	replacement := observability.HostMetricBatch{Version: observability.HostMetricBatchVersion, At: now, Epoch: 2, Samples: []observability.Sample{
		{Metric: observability.HistHostCPUUtilization, Labels: observability.L("member", "replacement"), Value: 0.5},
	}}
	for _, batch := range []observability.HostMetricBatch{older, replacement} {
		if confirmed, err := writer.Publish(t.Context(), batch); err != nil || !confirmed {
			t.Fatalf("publish: confirmed=%t err=%v", confirmed, err)
		}
	}
	h := &hostMetricHistory{local: observability.NewHistory(observability.HistoryConfig{}),
		shared: observability.NewHistory(observability.HistoryConfig{Interval: observability.HostMetricInterval})}
	h.local.Append(now, []observability.Sample{{Metric: observability.HistCPUUtilization, Value: 0.75}})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { h.run(ctx, js, "gru", 1, nil, nil); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if stream := h.stream.Load(); stream != nil && stream.CaughtUp() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("replay did not consume both retained batches")
		}
	}
	if stats := h.shared.Stats(); stats.Series != observability.DefaultHistorySeries || stats.Dropped != 1 {
		t.Fatalf("replay capacity = %+v", stats)
	}
	query := observability.HistoryQuery{Metric: observability.HistHostCPUUtilization,
		Labels: map[string]string{"member": "replacement"}, Start: now.Add(-time.Hour), End: now}
	result := h.Range(query)
	if result.Pending || !result.Incomplete || len(result.Series) != 0 {
		t.Fatalf("cache omission presented as complete or still loading: %+v", result)
	}
	encoded, err := json.Marshal(result)
	if err != nil || !bytes.Contains(encoded, []byte(`"incomplete":true`)) {
		t.Fatalf("query API hides cache omissions: %s err=%v", encoded, err)
	}
	query.Labels, query.Start = map[string]string{"member": "retired-0000"}, older.At.Add(-time.Minute)
	if result := h.Range(query); !result.Incomplete || len(result.Series) != 1 {
		t.Fatalf("partial history lost available data: %+v", result)
	}
	query.Metric, query.Labels = observability.HistCPUUtilization, nil
	if result := h.Range(query); result.Pending || result.Incomplete || len(result.Series) != 1 {
		t.Fatalf("regional capacity contaminated controller history: %+v", result)
	}
	var metrics bytes.Buffer
	h.writeMetrics(&metrics)
	if !strings.Contains(metrics.String(), "ts_orch_host_history_replay_ready 0\n") ||
		!strings.Contains(metrics.String(), "ts_orch_host_history_replay_dropped_samples_total 1\n") {
		t.Fatalf("metrics claim complete replay: %s", metrics.String())
	}
	stored, err := js.Stream(t.Context(), observability.HostMetricStreamName)
	if err != nil {
		t.Fatal(err)
	}
	info, err := stored.Info(t.Context())
	if err != nil || info.State.Msgs != 2 {
		t.Fatalf("cache overflow changed retained archive: %+v err=%v", info, err)
	}
}

func TestHostMetricHistoryDisclosesRejectedReplayBatch(t *testing.T) {
	js := testRolloutJetStream(t)
	writer, err := observability.OpenHostMetricStream(t.Context(), js, "gru", 1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Minute)
	if confirmed, err := writer.Publish(t.Context(), observability.HostMetricBatch{Version: observability.HostMetricBatchVersion, At: now, Epoch: 1,
		Samples: []observability.Sample{{Metric: observability.HistHostCPUUtilization,
			Labels: observability.L("member", "host-a"), Value: 0.25}}}); err != nil || !confirmed {
		t.Fatalf("valid publish: confirmed=%t err=%v", confirmed, err)
	}
	stored, err := js.Stream(t.Context(), observability.HostMetricStreamName)
	if err != nil {
		t.Fatal(err)
	}
	info, err := stored.Info(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.Publish(t.Context(), info.Config.Subjects[0], []byte("invalid retained batch")); err != nil {
		t.Fatal(err)
	}
	h := &hostMetricHistory{local: observability.NewHistory(observability.HistoryConfig{}),
		shared: observability.NewHistory(observability.HistoryConfig{Interval: observability.HostMetricInterval})}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { h.run(ctx, js, "gru", 1, nil, nil); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if stream := h.stream.Load(); stream != nil && stream.CaughtUp() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("replay did not advance past rejected batch")
		}
	}
	result := h.Range(observability.HistoryQuery{Metric: observability.HistHostCPUUtilization,
		Labels: map[string]string{"member": "host-a"}, Start: now.Add(-time.Hour), End: now})
	if result.Pending || !result.Incomplete || len(result.Series) != 1 || h.shared.Stats().Dropped != 0 {
		t.Fatalf("rejected batch hidden or confused with capacity loss: %+v", result)
	}
	var metrics bytes.Buffer
	h.writeMetrics(&metrics)
	if !strings.Contains(metrics.String(), "ts_orch_host_history_replay_ready 0\n") ||
		!strings.Contains(metrics.String(), "ts_orch_host_history_failures_total 1\n") {
		t.Fatalf("rejected replay batch absent from readiness/failure metrics: %s", metrics.String())
	}
}

func TestHostMetricArchiveOverflowRetainsSubsetAndAccountsDrops(t *testing.T) {
	load := overflowingHostMetricLoad(t, 1, time.Now())
	batch := load.archiveBatch(time.Now())
	if len(batch.Samples) != 4278 {
		t.Fatalf("producer samples = %d", len(batch.Samples))
	}
	h := &hostMetricHistory{}
	events := observability.NewEventBus(16)
	// Failed attempts do not count samples as omitted from a retained batch.
	failedCtx, cancelFailed := context.WithCancel(t.Context())
	h.publish(failedCtx, metricPublishFunc(func(context.Context, observability.HostMetricBatch) (bool, error) {
		cancelFailed()
		return false, errors.New("publication unavailable")
	}), load, events)
	if h.droppedSamples.Load() != 0 || h.failures.Load() != 1 {
		t.Fatalf("failed publication counters: dropped=%d failures=%d", h.droppedSamples.Load(), h.failures.Load())
	}
	stream, err := observability.OpenHostMetricStream(t.Context(), testRolloutJetStream(t), "gru", 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	var retained observability.HostMetricBatch
	h.publish(ctx, metricPublishFunc(func(publishCtx context.Context, bounded observability.HostMetricBatch) (bool, error) {
		defer cancel()
		retained = bounded
		return stream.Publish(publishCtx, bounded)
	}), load, events)
	if len(retained.Samples) != observability.DefaultHistorySeries || !retained.Incomplete || h.droppedSamples.Load() != 182 {
		t.Fatalf("overflow: retained=%d dropped=%d", len(retained.Samples), h.droppedSamples.Load())
	}
	if !reflect.DeepEqual(retained.Samples, batch.Samples[:len(retained.Samples)]) {
		t.Fatal("archive did not retain the deterministic prefix")
	}
	var metrics bytes.Buffer
	h.writeMetrics(&metrics)
	if !strings.Contains(metrics.String(), "ts_orch_host_history_dropped_samples_total 182\n") {
		t.Fatalf("dropped accounting absent from metrics: %s", metrics.String())
	}
	found := false
	for _, event := range events.Recent(16) {
		if event.Message == "Host metric archive omitted samples at capacity" && event.Attrs["dropped_samples"] == "182" {
			found = true
		}
	}
	if !found {
		t.Fatal("archive overflow absent from dashboard events")
	}
}

func overflowingHostMetricLoad(t *testing.T, epoch uint64, at time.Time) *hostTelemetry {
	t.Helper()

	fence := &metricTestFence{}
	fence.set(authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Ready: true, Leader: true, Epoch: epoch, Revision: 1, ExpiresAt: time.Now().Add(time.Hour)})
	load := &hostTelemetry{fencer: fence, load: hostload.NewAggregator(hostload.AggregatorConfig{
		Now: func() time.Time { return at },
	})}
	cpu, cores, memory := 0.4, 0.125, uint64(1024)
	report := hostload.Report{SchemaVersion: hostload.SchemaVersion,
		Host: hostload.HostUsage{CPU: &cpu, Memory: &cpu, Disk: &cpu}}
	for role := range hostload.MaxRoles {
		report.Roles = append(report.Roles, hostload.RoleUsage{Role: fmt.Sprintf("role-%02d", role), CPUCores: &cores, MemoryBytes: &memory})
	}
	// Changing report and node arrival order cannot change capacity selection.
	for node := 61; node >= 0; node-- {
		copy := report
		copy.Roles = slices.Clone(report.Roles)
		if node%2 == 0 {
			slices.Reverse(copy.Roles)
		}
		if err := load.record(hostload.Origin{Cell: "gru", Environment: "production", Node: fmt.Sprintf("host-%03d", node)}, copy); err != nil {
			t.Fatal(err)
		}
	}
	return load
}

func TestHostMetricArchiveSkipDoesNotAccountAnotherWriterBatch(t *testing.T) {
	load := overflowingHostMetricLoad(t, 2, time.Now())
	stream, err := observability.OpenHostMetricStream(t.Context(), testRolloutJetStream(t), "gru", 1)
	if err != nil {
		t.Fatal(err)
	}
	// Fill this minute with an earlier leader's batch; the new leader must skip it.
	batch := load.archiveBatch(time.Now())
	batch.Epoch = 1
	batch.Samples = batch.Samples[:1]
	if confirmed, err := stream.Publish(t.Context(), batch); err != nil || !confirmed {
		t.Fatalf("earlier leader publish: confirmed=%t err=%v", confirmed, err)
	}
	// Use the same fixed minute to cover pipeline confirmation without a wall-clock boundary.
	dropped, confirmed, err := publishHostMetricBatch(t.Context(), stream, load, load.archiveBatch(batch.At))
	if err != nil || confirmed || dropped != 182 {
		t.Fatalf("another leader's batch: dropped=%d confirmed=%t err=%v", dropped, confirmed, err)
	}
	h := &hostMetricHistory{}
	events := observability.NewEventBus(16)
	ctx, cancel := context.WithCancel(t.Context())
	h.publish(ctx, metricPublishFunc(func(context.Context, observability.HostMetricBatch) (bool, error) {
		defer cancel()
		return confirmed, nil
	}), load, events)
	if h.droppedSamples.Load() != 0 || h.failures.Load() != 0 || len(events.Recent(16)) != 0 {
		t.Fatalf("skipped batch produced accounting: dropped=%d failures=%d events=%v", h.droppedSamples.Load(), h.failures.Load(), events.Recent(16))
	}
}
