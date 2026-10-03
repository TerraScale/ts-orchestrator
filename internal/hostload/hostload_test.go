package hostload

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/autoscale"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/memberstatus"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
)

func ptr[T any](value T) *T { return &value }

func TestReportValidateBounds(t *testing.T) {
	valid := Report{SchemaVersion: SchemaVersion, Host: HostUsage{CPU: ptr(0.5), Memory: ptr(1.0), Disk: ptr(0.0)},
		Roles: []RoleUsage{{Role: "api", CPUCores: ptr(2.0), MemoryBytes: ptr(uint64(1 << 30)),
			TerraBase: &memberstatus.Load{Connections: 1, WriteQPS: 3}}}}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	many := Report{SchemaVersion: SchemaVersion}
	for range MaxRoles + 1 {
		many.Roles = append(many.Roles, RoleUsage{Role: "r"})
	}
	invalid := map[string]Report{
		"version":        {SchemaVersion: 2},
		"host above one": {SchemaVersion: 1, Host: HostUsage{CPU: ptr(1.5)}},
		"host NaN":       {SchemaVersion: 1, Host: HostUsage{Disk: ptr(math.NaN())}},
		"role token":     {SchemaVersion: 1, Roles: []RoleUsage{{Role: "API"}}},
		"repeated role":  {SchemaVersion: 1, Roles: []RoleUsage{{Role: "api"}, {Role: "api"}}},
		"negative cores": {SchemaVersion: 1, Roles: []RoleUsage{{Role: "api", CPUCores: ptr(-1.0)}}},
		"infinite cores": {SchemaVersion: 1, Roles: []RoleUsage{{Role: "api", CPUCores: ptr(math.Inf(1))}}},
		"memory":         {SchemaVersion: 1, Roles: []RoleUsage{{Role: "api", MemoryBytes: ptr(uint64(MaxMemoryBytes + 1))}}},
		"terrabase":      {SchemaVersion: 1, Roles: []RoleUsage{{Role: "tb", TerraBase: &memberstatus.Load{WriteQPS: -1}}}},
		"too many roles": many,
	}
	for name, report := range invalid {
		if err := report.Validate(); !errors.Is(err, ErrInvalidReport) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSamplerDiffsCgroupAndHostCounters(t *testing.T) {
	root := t.TempDir()
	now := time.Unix(1_000, 0)
	busy, idle := 100.0, 900.0
	system := func([]observability.FilesystemRole) (observability.SystemView, error) {
		return observability.SystemView{CPUSeconds: observability.CPUSeconds{User: busy, Idle: idle},
			MemTotalBytes: 8 << 30, MemAvailBytes: 6 << 30,
			Filesystems: []observability.FilesystemView{
				{Role: "state", SizeBytes: 100, AvailBytes: 80},
				{Role: "install", SizeBytes: 100, AvailBytes: 40},
				{Role: "broken", SizeBytes: 0},
			}}, nil
	}
	writeFile(t, filepath.Join(root, "api", "cpu.stat"), "usage_usec 1000000\nuser_usec 1\n")
	writeFile(t, filepath.Join(root, "api", "memory.current"), "3000\n")
	writeFile(t, filepath.Join(root, "api", "memory.stat"), "anon 1\ninactive_file 1000\n")
	sampler := NewSampler(SamplerConfig{CgroupRoot: root, Roles: []string{"api", "absent", "terrabase"},
		ReadSystem: system, Now: func() time.Time { return now }})

	first := sampler.Sample(nil)
	if first.Host.CPU != nil {
		t.Fatalf("first sample reported CPU without a baseline: %v", *first.Host.CPU)
	}
	if first.Host.Memory == nil || *first.Host.Memory != 0.25 || first.Host.Disk == nil || *first.Host.Disk != 0.6 {
		t.Fatalf("host memory/disk: %+v", first.Host)
	}
	if len(first.Roles) != 1 || first.Roles[0].CPUCores != nil || *first.Roles[0].MemoryBytes != 2000 {
		t.Fatalf("first role sample: %+v", first.Roles)
	}

	now = now.Add(10 * time.Second)
	busy, idle = 130, 970                                                         // 30 busy of 100 elapsed CPU seconds
	writeFile(t, filepath.Join(root, "api", "cpu.stat"), "usage_usec 16000000\n") // 15s CPU in 10s
	second := sampler.Sample(map[string]memberstatus.Load{"terrabase": {Connections: 5},
		"absent": {WriteQPS: -1}})
	if second.Host.CPU == nil || math.Abs(*second.Host.CPU-0.3) > 1e-9 {
		t.Fatalf("host CPU: %v", second.Host.CPU)
	}
	if len(second.Roles) != 2 || second.Roles[0].Role != "api" || *second.Roles[0].CPUCores != 1.5 {
		t.Fatalf("role CPU: %+v", second.Roles)
	}
	if tb := second.Roles[1]; tb.Role != "terrabase" || tb.TerraBase == nil || tb.TerraBase.Connections != 5 {
		t.Fatalf("terrabase load: %+v", second.Roles[1])
	}
	if err := second.Validate(); err != nil {
		t.Fatal(err)
	}

	// A restarted workload (counter went backwards after the group vanished)
	// starts a new baseline instead of reporting a burst.
	if err := os.RemoveAll(filepath.Join(root, "api")); err != nil {
		t.Fatal(err)
	}
	now = now.Add(10 * time.Second)
	sampler.Sample(nil)
	writeFile(t, filepath.Join(root, "api", "cpu.stat"), "usage_usec 10\n")
	now = now.Add(10 * time.Second)
	if restarted := sampler.Sample(nil); len(restarted.Roles) != 0 {
		t.Fatalf("restarted role reported CPU before a new baseline: %+v", restarted.Roles)
	}
}

func TestAggregatorNormalizesByRequestAndThrottles(t *testing.T) {
	now := time.Unix(10_000, 0)
	aggregator := NewAggregator(AggregatorConfig{
		Requests: map[string]Request{"api": {CPUCores: 2, MemoryBytes: 1000}},
		Now:      func() time.Time { return now },
	})
	origin := Origin{Cell: "gru", Environment: "prod", Node: "pool-1"}
	report := Report{SchemaVersion: 1, Host: HostUsage{Disk: ptr(0.4)}, Roles: []RoleUsage{
		{Role: "api", CPUCores: ptr(1.0), MemoryBytes: ptr(uint64(250))},
		{Role: "unprofiled", CPUCores: ptr(1.0)},
	}}
	if err := aggregator.Record(origin, report); err != nil {
		t.Fatal(err)
	}
	if err := aggregator.Record(origin, report); !errors.Is(err, ErrTooFrequent) {
		t.Fatalf("second report inside the minimum interval: %v", err)
	}
	other := origin
	other.Node = "pool-2"
	report.Roles[0].CPUCores = ptr(2.0)
	if err := aggregator.Record(other, report); err != nil {
		t.Fatal(err)
	}
	target := autoscale.Target{Cell: "gru", Environment: "prod", Role: "api"}
	read := func(name autoscale.SignalName, target autoscale.Target) autoscale.Reading {
		reading, err := aggregator.Read(t.Context(), target, autoscale.Signal{Name: name, Target: 1}, now)
		if err != nil {
			t.Fatal(err)
		}
		return reading
	}
	if got := read(autoscale.SignalCPUUtilization, target); got.Samples != 2 || got.Value != 0.75 {
		t.Fatalf("cpu_util = %+v, want mean of 0.5 and 1.0 over 2 samples", got)
	}
	if got := read(autoscale.SignalMemoryUtilization, target); got.Value != 0.25 {
		t.Fatalf("mem_util = %+v", got)
	}
	if got := read(autoscale.SignalDiskUtilization, target); got.Value != 0.4 {
		t.Fatalf("disk_util = %+v", got)
	}
	unprofiled := target
	unprofiled.Role = "unprofiled"
	if got := read(autoscale.SignalCPUUtilization, unprofiled); got.Samples != 0 {
		t.Fatalf("a role without a signed request produced cpu_util: %+v", got)
	}
	if nodes := aggregator.Nodes(); len(nodes) != 2 || nodes[0].Origin.Node != "pool-1" {
		t.Fatalf("nodes = %+v", nodes)
	}
	now = now.Add(DefaultStaleAfter + time.Second)
	if nodes := aggregator.Nodes(); len(nodes) != 0 {
		t.Fatalf("stale nodes kept: %+v", nodes)
	}
	if err := aggregator.Record(origin, Report{SchemaVersion: 7}); !errors.Is(err, ErrInvalidReport) {
		t.Fatalf("invalid report: %v", err)
	}
}

func TestAggregatorTerraBaseSignals(t *testing.T) {
	now := time.Unix(10_000, 0)
	aggregator := NewAggregator(AggregatorConfig{Now: func() time.Time { return now }})
	report := Report{SchemaVersion: 1, Roles: []RoleUsage{{Role: "terrabase",
		TerraBase: &memberstatus.Load{Connections: 40, StorageBytes: 1 << 20, ReplicationLagSeq: 9, WriteQPS: 12.5}}}}
	if err := aggregator.Record(Origin{Cell: "gru", Environment: "prod", Node: "tb-1"}, report); err != nil {
		t.Fatal(err)
	}
	target := autoscale.Target{Cell: "gru", Environment: "prod", Role: "terrabase"}
	for name, want := range map[autoscale.SignalName]float64{
		autoscale.SignalTerraBaseConnectionsPerMember: 40, autoscale.SignalTerraBaseStorageBytes: 1 << 20,
		autoscale.SignalTerraBaseReplicationLag: 9, autoscale.SignalTerraBaseWriteQPS: 12.5,
	} {
		reading, _ := aggregator.Read(t.Context(), target, autoscale.Signal{Name: name, Target: 1}, now)
		if reading.Samples != 1 || reading.Value != want {
			t.Errorf("%s = %+v, want %v", name, reading, want)
		}
	}
	// Without CPU or memory usage the host's disk is not attributed to the
	// role.
	if reading, _ := aggregator.Read(t.Context(), target, autoscale.Signal{Name: autoscale.SignalDiskUtilization, Target: 1}, now); reading.Samples != 0 {
		t.Fatalf("disk attributed without usage: %+v", reading)
	}
	if !StatelessSignal(autoscale.SignalCPUUtilization) || StatelessSignal(autoscale.SignalTerraBaseWriteQPS) ||
		StatelessSignal(autoscale.SignalRequestRatePerReplica) {
		t.Fatal("stateless signal set changed")
	}
}

func TestAggregatorConcurrentRecordAndRead(t *testing.T) {
	aggregator := NewAggregator(AggregatorConfig{Requests: map[string]Request{"api": {CPUCores: 1, MemoryBytes: 1}},
		MinInterval: time.Nanosecond})
	target := autoscale.Target{Cell: "gru", Environment: "prod", Role: "api"}
	var group sync.WaitGroup
	for worker := range 8 {
		group.Go(func() {
			origin := Origin{Cell: "gru", Environment: "prod", Node: "pool-" + string(rune('a'+worker))}
			for range 200 {
				_ = aggregator.Record(origin, Report{SchemaVersion: 1, Roles: []RoleUsage{{Role: "api", CPUCores: ptr(0.5)}}})
				_, _ = aggregator.Read(t.Context(), target, autoscale.Signal{Name: autoscale.SignalCPUUtilization, Target: 1}, time.Now())
				_ = aggregator.Nodes()
			}
		})
	}
	group.Wait()
	if nodes := aggregator.Nodes(); len(nodes) != 8 {
		t.Fatalf("nodes = %d", len(nodes))
	}
}
