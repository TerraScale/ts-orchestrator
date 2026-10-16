package nodescale

import (
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/hostload"
	"github.com/TerraScale/ts-orchestrator/internal/memberstatus"
)

func TestMeasure(t *testing.T) {
	tests := []struct {
		name      string
		nodes     int
		loads     []NodeLoad
		reporting int
		want      map[Signal]float64
	}{
		{
			name:  "means over fresh loads",
			nodes: 2,
			loads: []NodeLoad{
				{At: t0, CPU: 0.4, Memory: 0.2, Disk: 0.1, Cores: 2},
				{At: t0, CPU: 0.8, Memory: 0.6, Disk: 0.3, Cores: 2},
			},
			reporting: 2,
			want:      map[Signal]float64{SignalCPU: 0.6, SignalMemory: 0.4, SignalDisk: 0.2, SignalRequests: 0},
		},
		{
			name:  "writes dominate requests",
			nodes: 2,
			loads: []NodeLoad{
				{At: t0, CPU: 0.5, Cores: 2, WriteQPS: 1000, Connections: 0},
				{At: t0, CPU: 0.5, Cores: 2, WriteQPS: 1000, Connections: 0},
			},
			reporting: 2,
			want:      map[Signal]float64{SignalCPU: 0.5, SignalRequests: 1},
		},
		{
			name:  "connections dominate requests",
			nodes: 2,
			loads: []NodeLoad{
				{At: t0, CPU: 0.5, Cores: 2, WriteQPS: 100, Connections: 1000},
				{At: t0, CPU: 0.5, Cores: 2, WriteQPS: 100, Connections: 1000},
			},
			reporting: 2,
			want:      map[Signal]float64{SignalCPU: 0.5, SignalRequests: 0.5},
		},
		{
			name:  "stale loads are ignored",
			nodes: 2,
			loads: []NodeLoad{
				{At: t0, CPU: 0.2, Cores: 1},
				{At: ago(3 * time.Minute), CPU: 0.9, Cores: 1},
			},
			reporting: 1,
			want:      map[Signal]float64{SignalCPU: 0.2, SignalRequests: 0},
		},
		{
			name:      "zero cores count as one",
			nodes:     1,
			loads:     []NodeLoad{{At: t0, Cores: 0, WriteQPS: 250}},
			reporting: 1,
			want:      map[Signal]float64{SignalCPU: 0, SignalRequests: 0.5},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Measure(tt.nodes, tt.loads, t0)
			if got.Nodes != tt.nodes || got.Reporting != tt.reporting || got.At != t0 {
				t.Fatalf("Nodes %d Reporting %d At %s, want %d %d %s", got.Nodes, got.Reporting, got.At, tt.nodes, tt.reporting, t0)
			}
			for sig, want := range tt.want {
				if !almostEqual(got.Utilization[sig], want) {
					t.Fatalf("%s = %.4f, want %.4f", sig, got.Utilization[sig], want)
				}
			}
		})
	}
}

func TestMeasureWithoutFreshLoads(t *testing.T) {
	got := Measure(3, []NodeLoad{{At: ago(3 * time.Minute), CPU: 0.9, Cores: 1}}, t0)
	if got.Utilization != nil || got.Reporting != 0 || got.Complete() {
		t.Fatalf("got %+v, want no utilization and no fresh reports", got)
	}
}

func TestFromHostLoad(t *testing.T) {
	missing := []struct {
		name string
		host hostload.HostUsage
	}{
		{"cpu", hostload.HostUsage{Memory: new(0.5), Disk: new(0.2)}},
		{"memory", hostload.HostUsage{CPU: new(0.5), Disk: new(0.2)}},
		{"disk", hostload.HostUsage{CPU: new(0.5), Memory: new(0.5)}},
	}
	for _, tt := range missing {
		t.Run("missing "+tt.name, func(t *testing.T) {
			_, ok := FromHostLoad(hostload.NodeLoad{Report: hostload.Report{Host: tt.host}})
			if ok {
				t.Fatal("ok = true, want false")
			}
		})
	}

	load := hostload.NodeLoad{
		Origin: hostload.Origin{Node: "n1"},
		At:     t0,
		Report: hostload.Report{
			Host: hostload.HostUsage{CPU: new(0.5), Memory: new(0.4), Disk: new(0.3), CPUCores: 2},
			Roles: []hostload.RoleUsage{
				{Role: "terrabase", TerraBase: &memberstatus.Load{Connections: 10, WriteQPS: 5}},
				{Role: "terrabase2", TerraBase: &memberstatus.Load{Connections: 20, WriteQPS: 7}},
				{Role: "app", CPUCores: new(1.0)},
			},
		},
	}
	got, ok := FromHostLoad(load)
	if !ok {
		t.Fatal("ok = false, want true")
	}
	want := NodeLoad{Node: "n1", At: t0, CPU: 0.5, Memory: 0.4, Disk: 0.3, Cores: 2, WriteQPS: 12, Connections: 30}
	if got != want {
		t.Fatalf("FromHostLoad = %+v, want %+v", got, want)
	}
}

func almostEqual(a, b float64) bool {
	const eps = 1e-9
	return a-b < eps && b-a < eps
}
