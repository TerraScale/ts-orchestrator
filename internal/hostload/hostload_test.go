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
	now = now.Add(10 * time.Second)
	writeFile(t, filepath.Join(root, "api", "cpu.stat"), "usage_usec 5000010\n")
	if steady := sampler.Sample(nil); len(steady.Roles) != 1 || *steady.Roles[0].CPUCores != 0.5 {
		t.Fatalf("steady role CPU: %+v", steady.Roles)
	}
	// A group recreated between two samples (never seen missing) whose new
	// counter already exceeds the old one also restarts the baseline.
	if err := os.Rename(filepath.Join(root, "api"), filepath.Join(root, "api-old")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "api", "cpu.stat"), "usage_usec 6000000\n")
	now = now.Add(10 * time.Second)
	if recreated := sampler.Sample(nil); len(recreated.Roles) != 0 {
		t.Fatalf("recreated group diffed against its predecessor: %+v", recreated.Roles)
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
		reading, err := aggregator.Read(t.Context(), target, autoscale.Signal{Name: name, Target: 1}, now.Add(time.Minute))
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
		reading, _ := aggregator.Read(t.Context(), target, autoscale.Signal{Name: name, Target: 1}, now.Add(time.Minute))
		if reading.Samples != 1 || reading.Value != want {
			t.Errorf("%s = %+v, want %v", name, reading, want)
		}
	}
	// Without CPU or memory usage the host's disk is not attributed to the
	// role.
	if reading, _ := aggregator.Read(t.Context(), target, autoscale.Signal{Name: autoscale.SignalDiskUtilization, Target: 1}, now.Add(time.Minute)); reading.Samples != 0 {
		t.Fatalf("disk attributed without usage: %+v", reading)
	}
	if !StatelessSignal(autoscale.SignalCPUUtilization) || StatelessSignal(autoscale.SignalTerraBaseWriteQPS) ||
		StatelessSignal(autoscale.SignalRequestRatePerReplica) {
		t.Fatal("stateless signal set changed")
	}
}

// Every reporting replica counts once, whatever its report interval, and a
// many-replica service keeps its full one-hour window.
func TestAggregatorWeighsNodesEquallyOverTheWholeWindow(t *testing.T) {
	start := time.Unix(50_000, 0)
	now := start
	aggregator := NewAggregator(AggregatorConfig{Requests: map[string]Request{"api": {CPUCores: 1, MemoryBytes: 1}},
		Now: func() time.Time { return now }})
	report := func(cores float64) Report {
		return Report{SchemaVersion: 1, Roles: []RoleUsage{{Role: "api", CPUCores: ptr(cores)}}}
	}
	// 30 chatty nodes at 5s and one quiet node every minute, for an hour.
	for step := 0; step < 720; step++ {
		now = start.Add(time.Duration(step) * 5 * time.Second)
		for node := range 30 {
			value := 0.1
			if step < 360 {
				// The first half hour was busy: a truncated window would
				// miss it.
				value = 0.5
			}
			if err := aggregator.Record(Origin{Cell: "gru", Environment: "prod", Node: "chatty-" + string(rune('a'+node%26)) + string(rune('a'+node/26))}, report(value)); err != nil {
				t.Fatal(err)
			}
		}
		if step%12 == 0 {
			if err := aggregator.Record(Origin{Cell: "gru", Environment: "prod", Node: "quiet"}, report(0.9)); err != nil {
				t.Fatal(err)
			}
		}
	}
	target := autoscale.Target{Cell: "gru", Environment: "prod", Role: "api"}
	hour := autoscale.Signal{Name: autoscale.SignalCPUUtilization, Target: 1, WindowSeconds: 3600}
	// Reports have not covered the whole hour yet: no reading.
	if early, _ := aggregator.Read(t.Context(), target, hour, start.Add(30*time.Minute)); early.Samples != 0 {
		t.Fatalf("reading before a full window of reports: %+v", early)
	}
	reading, err := aggregator.Read(t.Context(), target, hour, start.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// Each chatty node averages 0.3 over the hour, the quiet one 0.9.
	want := (30*0.3 + 0.9) / 31
	if math.Abs(reading.Value-want) > 1e-9 || reading.Samples != 30*720+60 {
		t.Fatalf("reading = %+v, want value %v over %d samples", reading, want, 30*720+60)
	}
}

// After a break in reports longer than StaleAfter, for example while
// another member led, the aggregator waits for a full window again.
func TestAggregatorWarmUpRestartsAfterAGap(t *testing.T) {
	now := time.Unix(90_000, 0)
	aggregator := NewAggregator(AggregatorConfig{Requests: map[string]Request{"api": {CPUCores: 1, MemoryBytes: 1}},
		Now: func() time.Time { return now }})
	origin := Origin{Cell: "gru", Environment: "prod", Node: "pool-1"}
	target := autoscale.Target{Cell: "gru", Environment: "prod", Role: "api"}
	signal := autoscale.Signal{Name: autoscale.SignalCPUUtilization, Target: 1}
	record := func() {
		t.Helper()
		if err := aggregator.Record(origin, Report{SchemaVersion: 1, Roles: []RoleUsage{{Role: "api", CPUCores: ptr(0.4)}}}); err != nil {
			t.Fatal(err)
		}
	}
	read := func() autoscale.Reading {
		reading, _ := aggregator.Read(t.Context(), target, signal, now)
		return reading
	}
	if got := read(); got.Samples != 0 {
		t.Fatalf("empty aggregator read %+v", got)
	}
	for range 11 { // 0s..50s: the first report is not yet within one interval of the window start
		record()
		if got := read(); got.Samples != 0 {
			t.Fatalf("read before a full window: %+v", got)
		}
		now = now.Add(5 * time.Second)
	}
	record()
	if got := read(); got.Samples != 12 || math.Abs(got.Value-0.4) > 1e-9 {
		t.Fatalf("warm read = %+v", got)
	}
	// Another service that starts reporting is not warmed by this one.
	other := target
	other.Role = "worker"
	aggregator.config.Requests["worker"] = Request{CPUCores: 1, MemoryBytes: 1}
	now = now.Add(5 * time.Second)
	if err := aggregator.Record(Origin{Cell: "gru", Environment: "prod", Node: "pool-2"},
		Report{SchemaVersion: 1, Roles: []RoleUsage{{Role: "worker", CPUCores: ptr(0.9)}}}); err != nil {
		t.Fatal(err)
	}
	if got, _ := aggregator.Read(t.Context(), other, signal, now); got.Samples != 0 {
		t.Fatalf("a newly reporting service read before its own window: %+v", got)
	}
	// Silence longer than StaleAfter ends the run even before a new report.
	now = now.Add(DefaultStaleAfter + time.Second)
	if got := read(); got.Samples != 0 {
		t.Fatalf("read after the hosts went silent: %+v", got)
	}
	record()
	if got := read(); got.Samples != 0 {
		t.Fatalf("read right after a gap: %+v", got)
	}
	// A reset (new authority term) forgets everything.
	for range 13 {
		now = now.Add(5 * time.Second)
		record()
	}
	if got := read(); got.Samples == 0 {
		t.Fatal("not warm after a full window")
	}
	aggregator.Reset()
	if got := read(); got.Samples != 0 || len(aggregator.Nodes()) != 0 {
		t.Fatalf("read after reset: %+v", got)
	}
}

// A node that stops supplying a series (scaled down, replaced or silent)
// stops contributing after StaleAfter, even inside a longer window, while
// another node keeps the series fresh.
func TestAggregatorDropsSilentContributors(t *testing.T) {
	start := time.Unix(120_000, 0)
	now := start
	aggregator := NewAggregator(AggregatorConfig{Requests: map[string]Request{"api": {CPUCores: 1, MemoryBytes: 1}},
		Now: func() time.Time { return now }})
	record := func(node string, cores float64) {
		t.Helper()
		if err := aggregator.Record(Origin{Cell: "gru", Environment: "prod", Node: node},
			Report{SchemaVersion: 1, Roles: []RoleUsage{{Role: "api", CPUCores: ptr(cores)}}}); err != nil {
			t.Fatal(err)
		}
	}
	target := autoscale.Target{Cell: "gru", Environment: "prod", Role: "api"}
	hour := autoscale.Signal{Name: autoscale.SignalCPUUtilization, Target: 1, WindowSeconds: 3600}
	for step := range 721 {
		now = start.Add(time.Duration(step) * 5 * time.Second)
		record("live", 0.2)
		if now.Before(start.Add(50 * time.Minute)) {
			record("gone", 0.9)
		} else if step%12 == 0 {
			// Still reporting, but no longer running the role.
			if err := aggregator.Record(Origin{Cell: "gru", Environment: "prod", Node: "gone"},
				Report{SchemaVersion: 1}); err != nil {
				t.Fatal(err)
			}
		}
	}
	reading, err := aggregator.Read(t.Context(), target, hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(reading.Value-0.2) > 1e-9 || reading.Samples != 721 {
		t.Fatalf("reading = %+v, want only the live node (0.2 over 721 samples)", reading)
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
