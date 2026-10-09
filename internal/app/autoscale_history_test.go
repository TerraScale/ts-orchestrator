package app

import (
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostload"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
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
	if len(samples) != 5 {
		t.Fatalf("resource samples = %+v, want only measured values", samples)
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
	now = now.Add(hostload.DefaultStaleAfter + time.Second)
	if samples := hostLoadSamples(load); len(samples) != 0 {
		t.Fatalf("stale reports still charted = %+v", samples)
	}
	if samples := hostLoadSamples(nil); len(samples) != 0 {
		t.Fatalf("disabled telemetry = %+v", samples)
	}
}
