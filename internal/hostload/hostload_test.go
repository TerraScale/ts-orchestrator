package hostload

import (
	"math"
	"os"
	"path/filepath"

	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/autoscale"
	"github.com/TerraScale/ts-orchestrator/internal/memberstatus"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

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
