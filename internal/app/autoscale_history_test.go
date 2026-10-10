package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"reflect"
	"slices"
	"strconv"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostload"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionview"
)

func TestHostResourceHistorySkipsMissingAndStaleMeasurements(t *testing.T) {
	now := time.Now()
	load := hostload.NewAggregator(hostload.AggregatorConfig{Now: func() time.Time { return now }})
	cpu, memory, disk, cores := 0.4, 0.7, 0.2, 1.5
	bytes := uint64(128 << 20)
	if err := load.Record(hostload.Origin{Cell: "gru", Environment: "prod", Node: "Host-A"},
		hostload.Report{SchemaVersion: hostload.SchemaVersion,
			Host:  hostload.HostUsage{CPU: &cpu, Memory: &memory, Disk: &disk},
			Roles: []hostload.RoleUsage{{Role: "api", CPUCores: &cores, MemoryBytes: &bytes}, {Role: "unmeasured"}}}); err != nil {
		t.Fatal(err)
	}
	if err := load.Record(hostload.Origin{Cell: "gru", Environment: "prod", Node: "host-b"},
		hostload.Report{SchemaVersion: hostload.SchemaVersion}); err != nil {
		t.Fatal(err)
	}
	samples := hostLoadSamples(load)
	if len(samples) != 9 {
		t.Fatalf("resource samples = %+v, want measured values and both controller receive times", samples)
	}
	history := observability.NewHistory(observability.HistoryConfig{})
	history.Append(now, samples)
	for _, want := range []struct {
		metric  string
		value   float64
		service string
	}{{observability.HistHostCPUUtilization, cpu, ""},
		{observability.HistHostMemoryRatio, memory, ""},
		{observability.HistHostDiskRatio, disk, ""},
		{observability.HistHostReceivedAt, float64(now.UnixMilli()), ""},
		{observability.HistHostFSIncomplete, 0, ""},
		{observability.HistServiceCPUCores, cores, "api"},
		{observability.HistServiceMemoryUsed, float64(bytes), "api"}} {
		labels := map[string]string{"member": "host-a"}
		if want.service != "" {
			labels["service"] = want.service
		}
		result := history.Range(observability.HistoryQuery{Metric: want.metric, Labels: labels,
			Start: now.Add(-time.Minute), End: now})
		if len(result.Series) != 1 || len(result.Series[0].Points) != 1 || result.Series[0].Points[0].Value != want.value {
			t.Fatalf("%s history = %+v, want %v for host-a/%s", want.metric, result, want.value, want.service)
		}
	}
	result := history.Range(observability.HistoryQuery{Metric: observability.HistHostReceivedAt,
		Labels: map[string]string{"member": "host-b"}, Start: now.Add(-time.Minute), End: now})
	if len(result.Series) != 1 || len(result.Series[0].Points) != 1 || result.Series[0].Points[0].Value != float64(now.UnixMilli()) {
		t.Fatalf("empty host report lost controller receive time: %+v", result)
	}
	now = now.Add(hostload.DefaultStaleAfter + time.Second)
	if samples := hostLoadSamples(load); len(samples) != 0 {
		t.Fatalf("stale reports still charted = %+v", samples)
	}
	if samples := hostLoadSamples(nil); len(samples) != 0 {
		t.Fatalf("disabled telemetry = %+v", samples)
	}
}

func TestHostCapacityAndFilesystemCollectorArchiveReplay(t *testing.T) {
	now := time.Now().UTC().Truncate(observability.HostMetricInterval)
	filesystem := observability.FilesystemView{Role: "terrabase_data", Path: "/srv/terrabase/data",
		SizeBytes: 1000, AvailBytes: 250, FreeBytes: 300, Files: 100, FilesFree: 50, Device: 42}
	filesystems := []observability.FilesystemView{
		{Role: "boot", Path: "/", SizeBytes: 100, AvailBytes: 90, FreeBytes: 95, Files: 20, FilesFree: 15},
		{Role: "state", Path: "/state", SizeBytes: 200, AvailBytes: 100, FreeBytes: 120,
			Files: 200, FilesFree: 175, Device: ^uint64(0)},
		filesystem,
	}
	sampler := hostload.NewSampler(hostload.SamplerConfig{
		ReadSystem: func([]observability.FilesystemRole) (observability.SystemView, error) {
			return observability.SystemView{CPUCount: 8, MemTotalBytes: 16 << 30, MemAvailBytes: 4 << 30,
				Filesystems: append(slices.Clone(filesystems), observability.FilesystemView{Role: "unreadable", Path: "/missing"})}, nil
		}})
	data, err := json.Marshal(sampler.Sample(nil))
	if err != nil {
		t.Fatal(err)
	}
	var report hostload.Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(report.Host.Filesystems, filesystems) || !report.Host.FilesystemsIncomplete {
		t.Fatalf("serialized filesystem identity lost: %+v", report.Host)
	}
	fence := &metricTestFence{}
	fence.set(authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Ready: true, Leader: true, Epoch: 1, Revision: 1, ExpiresAt: time.Now().Add(time.Hour)})
	receivedAt := now.Add(39 * time.Second)
	controllerNow := receivedAt
	load := &hostTelemetry{fencer: fence, load: hostload.NewAggregator(hostload.AggregatorConfig{
		Now: func() time.Time { return controllerNow },
	})}
	if err := load.record(hostload.Origin{Cell: "gru", Environment: "prod", Node: "Host-A"}, report); err != nil {
		t.Fatal(err)
	}
	js := testRolloutJetStream(t)
	writer, err := observability.OpenHostMetricStream(t.Context(), js, "gru", 1)
	if err != nil {
		t.Fatal(err)
	}
	if stored, err := writer.Publish(t.Context(), load.archiveBatch(now)); err != nil || !stored {
		t.Fatalf("archive publication stored=%t: %v", stored, err)
	}
	republishedAt := now.Add(3 * observability.HostMetricInterval)
	controllerNow = republishedAt
	if stored, err := writer.Publish(t.Context(), load.archiveBatch(republishedAt)); err != nil || !stored {
		t.Fatalf("unchanged report publication stored=%t: %v", stored, err)
	}
	reader, err := observability.OpenHostMetricStream(t.Context(), js, "gru", 1)
	if err != nil {
		t.Fatal(err)
	}
	history := observability.NewHistory(observability.HistoryConfig{Interval: observability.HostMetricInterval})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- reader.Tail(ctx, history) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("archive replay stopped: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("archive replay did not stop")
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for !reader.CaughtUp() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !reader.CaughtUp() || reader.ReplayFailures() != 0 {
		t.Fatal("archive replay did not accept collected host metrics")
	}
	for _, want := range []struct {
		metric string
		value  float64
	}{
		{observability.HistHostCPUCores, 8},
		{observability.HistHostMemoryTotal, 16 << 30},
		{observability.HistHostMemoryRatio, .75},
		{observability.HistHostDiskRatio, .75},
		{observability.HistHostReceivedAt, float64(receivedAt.UnixMilli())},
		{observability.HistHostFSIncomplete, 1},
	} {
		labels := map[string]string{"member": "host-a"}
		result := history.Range(observability.HistoryQuery{Metric: want.metric, Labels: labels, Start: now.Add(-time.Minute), End: now})
		if len(result.Series) != 1 || len(result.Series[0].Points) != 1 || result.Series[0].Points[0].Value != want.value {
			t.Fatalf("replayed %s = %+v, want %v", want.metric, result, want.value)
		}
	}
	for _, filesystem := range filesystems {
		labels := map[string]string{"member": "host-a", "role": filesystem.Role,
			"path": filesystem.Path, "device": strconv.FormatUint(filesystem.Device, 10)}
		for _, want := range []struct {
			metric string
			value  float64
		}{
			{observability.HistHostFSSize, float64(filesystem.SizeBytes)},
			{observability.HistHostFSUsed, float64(filesystem.SizeBytes - filesystem.AvailBytes)},
			{observability.HistHostFSRatio, float64(filesystem.SizeBytes-filesystem.AvailBytes) / float64(filesystem.SizeBytes)},
			{observability.HistHostFSFiles, float64(filesystem.Files)},
			{observability.HistHostFSFilesFree, float64(filesystem.FilesFree)},
		} {
			result := history.Range(observability.HistoryQuery{Metric: want.metric,
				Labels: map[string]string{"member": "host-a", "role": filesystem.Role}, Start: now.Add(-time.Minute), End: now})
			if len(result.Series) != 1 || !reflect.DeepEqual(result.Series[0].Labels, labels) ||
				len(result.Series[0].Points) != 1 || result.Series[0].Points[0].Value != want.value {
				t.Fatalf("replayed %s identity or value lost: %+v, want %+v = %v", want.metric, result, labels, want.value)
			}
		}
	}
	receipts := history.Range(observability.HistoryQuery{Metric: observability.HistHostReceivedAt,
		Labels: map[string]string{"member": "host-a"}, Start: now.Add(-time.Minute), End: republishedAt})
	if len(receipts.Series) != 1 || len(receipts.Series[0].Points) != 2 {
		t.Fatalf("receive time did not replay for both publication minutes: %+v", receipts)
	}
	for i, point := range receipts.Series[0].Points {
		if point.Value != float64(receivedAt.UnixMilli()) || !point.Time.Equal([]time.Time{now, republishedAt}[i]) {
			t.Fatalf("publication refreshed unchanged report receive time: %+v", receipts)
		}
	}
	resources := regionview.CollectResources(regionview.Node{Name: "host-a"}, history, republishedAt)
	if !resources.Incomplete || len(resources.Filesystems) != len(filesystems) {
		t.Fatalf("replayed collection failure was hidden or invented a measurement: %+v", resources)
	}
}
