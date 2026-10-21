package hostload

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/autoscale"
	"github.com/TerraScale/ts-orchestrator/internal/memberstatus"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

func ptr[T any](value T) *T { return &value }

func TestReportNetworkAndLoadJSONNames(t *testing.T) {
	report := Report{SchemaVersion: SchemaVersion, Host: HostUsage{NetworkRxBps: ptr(100.0), NetworkTxBps: ptr(200.0), Load1: ptr(0.5)}}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"net_rx_bps":100`, `"net_tx_bps":200`, `"load1":0.5`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("JSON lacks %s: %s", want, data)
		}
	}
	var decoded Report
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if *decoded.Host.NetworkRxBps != 100 || *decoded.Host.NetworkTxBps != 200 || *decoded.Host.Load1 != 0.5 {
		t.Fatalf("round trip = %+v", decoded.Host)
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

func TestSamplerReadsFiniteAndUnlimitedLimits(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root+"/cgroup.controllers", "cpu memory\n")
	writeFile(t, root+"/cpu.max", "150000 100000\n")
	writeFile(t, root+"/memory.max", "1048576\n")
	cpu, memory, ok := readLimits(root, root)
	if !ok || cpu == nil || *cpu != 1.5 || memory == nil || *memory != 1048576 {
		t.Fatalf("finite limits %v %v %t", cpu, memory, ok)
	}
	writeFile(t, root+"/cpu.max", "max 100000\n")
	writeFile(t, root+"/memory.max", "max\n")
	cpu, memory, ok = readLimits(root, root)
	if !ok || cpu != nil || memory != nil {
		t.Fatal("unlimited limits lost")
	}
	writeFile(t, root+"/cpu.max", "NaN 100000\n")
	if _, _, ok := readLimits(root, root); ok {
		t.Fatal("accepted malformed quota")
	}
}

func TestSamplerResolvesInheritedMemoryLimits(t *testing.T) {
	for _, test := range []struct {
		name, ancestor, leaf, root string
		want                       uint64
		valid                      bool
	}{
		{"inherited", "5368709120", "max", "", 5 << 30, true},
		{"leaf tighter", "5368709120", "2147483648", "", 2 << 30, true},
		{"root tighter", "5368709120", "max", "1073741824", 1 << 30, true},
		{"physical tighter", "17179869184", "max", "", 8 << 30, true},
		{"unlimited", "max", "max", "", 0, true},
		{"missing ancestor", "", "max", "", 0, false},
		{"malformed ancestor", "invalid", "max", "", 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			mount := t.TempDir()
			parent := filepath.Join(mount, "service")
			writeFile(t, filepath.Join(mount, "cgroup.controllers"), "cpu memory\n")
			if test.root != "" {
				writeFile(t, filepath.Join(mount, "memory.max"), test.root)
			}
			if test.ancestor != "" {
				writeFile(t, filepath.Join(parent, "memory.max"), test.ancestor)
			}
			writeFile(t, filepath.Join(parent, "api", "memory.max"), test.leaf)
			writeFile(t, filepath.Join(parent, "api", "cpu.max"), "max 100000")
			writeFile(t, filepath.Join(parent, "api", "memory.current"), "1024")
			sampler := NewSampler(SamplerConfig{CgroupRoot: parent, CgroupMount: mount, Roles: []string{"api"},
				ReadSystem: func([]observability.FilesystemRole) (observability.SystemView, error) {
					return observability.SystemView{MemTotalBytes: 8 << 30}, nil
				}})
			report := sampler.Sample(nil)
			if len(report.Roles) != 1 {
				t.Fatalf("missing role: %+v", report)
			}
			role := report.Roles[0]
			if role.LimitsRead != test.valid || test.want == 0 && role.MemoryLimit != nil || test.want > 0 && (role.MemoryLimit == nil || *role.MemoryLimit != test.want) {
				t.Fatalf("inherited limit: %+v, want %d valid=%t", role, test.want, test.valid)
			}
		})
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
				{Role: "state", Path: "/state", SizeBytes: 100, AvailBytes: 80, FreeBytes: 80},
				{Role: "install", Path: "/install", SizeBytes: 100, AvailBytes: 40, FreeBytes: 40},
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

func TestSamplerNetworkRatesAndLoad(t *testing.T) {
	now := time.Unix(1_000, 0)
	var rx, tx uint64 = 1000, 2000
	system := func([]observability.FilesystemRole) (observability.SystemView, error) {
		return observability.SystemView{CPUCount: 2, Load1: 0.75, NetRxBytes: rx, NetTxBytes: tx}, nil
	}
	sampler := NewSampler(SamplerConfig{ReadSystem: system, Now: func() time.Time { return now }})

	first := sampler.Sample(nil)
	if first.Host.NetworkRxBps != nil || first.Host.NetworkTxBps != nil {
		t.Fatalf("first sample reported rates without a baseline: %+v", first.Host)
	}
	if first.Host.Load1 == nil || *first.Host.Load1 != 0.75 {
		t.Fatalf("load1 = %v", first.Host.Load1)
	}

	now = now.Add(15 * time.Second)
	rx, tx = 2500, 5000
	second := sampler.Sample(nil)
	if second.Host.NetworkRxBps == nil || *second.Host.NetworkRxBps != 100 ||
		second.Host.NetworkTxBps == nil || *second.Host.NetworkTxBps != 200 {
		t.Fatalf("rates = %+v", second.Host)
	}
	if err := second.Validate(); err != nil {
		t.Fatal(err)
	}

	now = now.Add(15 * time.Second)
	rx, tx = 100, 6000
	if reset := sampler.Sample(nil); reset.Host.NetworkRxBps != nil || reset.Host.NetworkTxBps != nil {
		t.Fatalf("counter reset reported rates: %+v", reset.Host)
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
		reading, err := aggregator.Read(t.Context(), target, autoscale.Signal{Name: name, Target: 1, WindowSeconds: 10}, now.Add(5*time.Second))
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

func TestAggregatorSetRequestsAppliesToLaterReports(t *testing.T) {
	now := time.Unix(10_000, 0)
	aggregator := NewAggregator(AggregatorConfig{
		Requests: map[string]Request{"api": {CPUCores: 2}},
		Now:      func() time.Time { return now },
	})
	report := Report{SchemaVersion: 1, Roles: []RoleUsage{
		{Role: "api", CPUCores: ptr(1.0)}, {Role: "worker", CPUCores: ptr(1.0)},
	}}
	if err := aggregator.Record(Origin{Cell: "gru", Environment: "prod", Node: "pool-1"}, report); err != nil {
		t.Fatal(err)
	}
	// A new cell spec amendment resizes api and adds worker.
	aggregator.SetRequests(map[string]Request{"api": {CPUCores: 4}, "worker": {CPUCores: 1}})
	if err := aggregator.Record(Origin{Cell: "gru", Environment: "prod", Node: "pool-2"}, report); err != nil {
		t.Fatal(err)
	}
	read := func(role string) autoscale.Reading {
		reading, err := aggregator.Read(t.Context(), autoscale.Target{Cell: "gru", Environment: "prod", Role: role},
			autoscale.Signal{Name: autoscale.SignalCPUUtilization, Target: 1, WindowSeconds: 10}, now.Add(5*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		return reading
	}
	if got := read("api"); got.Samples != 2 || got.Value != 0.375 {
		t.Fatalf("api cpu_util = %+v, want mean of 0.5 and 0.25", got)
	}
	if got := read("worker"); got.Samples != 1 || got.Value != 1 {
		t.Fatalf("worker cpu_util = %+v, want the one report after it got a request", got)
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
		reading, _ := aggregator.Read(t.Context(), target, autoscale.Signal{Name: name, Target: 1, WindowSeconds: 10}, now.Add(5*time.Second))
		if reading.Samples != 1 || reading.Value != want {
			t.Errorf("%s = %+v, want %v", name, reading, want)
		}
	}
	// Without CPU or memory usage the host's disk is not attributed to the
	// role.
	if reading, _ := aggregator.Read(t.Context(), target, autoscale.Signal{Name: autoscale.SignalDiskUtilization, Target: 1, WindowSeconds: 10}, now.Add(5*time.Second)); reading.Samples != 0 {
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
	// A window no longer than the report interval still needs more than
	// the first report after a reset.
	short := autoscale.Signal{Name: autoscale.SignalCPUUtilization, Target: 1, WindowSeconds: 3}
	now = now.Add(5 * time.Second)
	record()
	if got, _ := aggregator.Read(t.Context(), target, short, now); got.Samples != 0 {
		t.Fatalf("short window read on the first report after a reset: %+v", got)
	}
	now = now.Add(5 * time.Second)
	record()
	if got, _ := aggregator.Read(t.Context(), target, short, now); got.Samples != 1 {
		t.Fatalf("short window after one interval: %+v", got)
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
			record("000000000050XVKQQF0BK88ENZ", 0.9)
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

// A window that the reports cover only sparsely (hosts reporting less
// often than half the window, or a publication outage inside it) reads as
// unavailable, even within an unbroken run.
func TestAggregatorRefusesSparselyCoveredWindows(t *testing.T) {
	start := time.Unix(150_000, 0)
	now := start
	aggregator := NewAggregator(AggregatorConfig{Requests: map[string]Request{"api": {CPUCores: 1, MemoryBytes: 1}},
		Now: func() time.Time { return now }})
	origin := Origin{Cell: "gru", Environment: "prod", Node: "pool-1"}
	record := func() {
		t.Helper()
		if err := aggregator.Record(origin, Report{SchemaVersion: 1, Roles: []RoleUsage{{Role: "api", CPUCores: ptr(0.7)}}}); err != nil {
			t.Fatal(err)
		}
	}
	target := autoscale.Target{Cell: "gru", Environment: "prod", Role: "api"}
	minute := autoscale.Signal{Name: autoscale.SignalCPUUtilization, Target: 1}
	read := func() autoscale.Reading {
		reading, _ := aggregator.Read(t.Context(), target, minute, now)
		return reading
	}
	// Reports every two minutes against a one-minute window.
	for range 4 {
		record()
		if got := read(); got.Samples != 0 {
			t.Fatalf("sparse window read at %v: %+v", now.Sub(start), got)
		}
		now = now.Add(2 * time.Minute)
	}
	// Dense 15s reports cover it once a window has passed without a hole.
	for range 5 {
		record()
		now = now.Add(15 * time.Second)
	}
	now = now.Add(-15 * time.Second)
	if got := read(); got.Samples == 0 {
		t.Fatalf("dense window unavailable: %+v", got)
	}
	// A 45s outage inside the window makes it unavailable until the hole
	// leaves the window.
	now = now.Add(45 * time.Second)
	record()
	if got := read(); got.Samples != 0 {
		t.Fatalf("window with a 45s hole read: %+v", got)
	}
	for range 4 {
		now = now.Add(15 * time.Second)
		record()
	}
	if got := read(); got.Samples == 0 {
		t.Fatalf("window unavailable after the hole left it: %+v", got)
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
