package hostload

import (
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/autoscale"
)

func TestCommittedRequestsNormalizeEachHostsActualTasks(t *testing.T) {
	now := time.Now().UTC()
	load := NewAggregator(AggregatorConfig{Requests: map[string]Request{"api": {CPUCores: 99}}, Now: func() time.Time { return now }})
	cpu := 0.5
	report := Report{SchemaVersion: SchemaVersion, Roles: []RoleUsage{{Role: "api", CPUCores: &cpu}}}
	origin := Origin{Cell: "gru", Environment: "production"}
	for sample := range 3 {
		if sample > 0 {
			now = now.Add(DefaultMinInterval)
		}
		for _, host := range []struct {
			node  string
			cores float64
		}{{"one-task", 1}, {"two-tasks", 2}} {
			origin.Node = host.node
			if err := load.RecordRequests(origin, report, map[string]Request{"api": {CPUCores: host.cores}}); err != nil {
				t.Fatal(err)
			}
		}
	}
	target := autoscale.Target{Cell: origin.Cell, Environment: origin.Environment, Role: "api"}
	reading, err := load.Read(t.Context(), target, autoscale.Signal{Name: autoscale.SignalCPUUtilization, WindowSeconds: 10}, now)
	if err != nil || reading.Samples != 6 || reading.Value != 0.375 {
		t.Fatalf("requests from different task counts were mixed: %+v %v", reading, err)
	}
	for _, node := range load.Nodes() {
		if len(node.Report.Roles) != 1 || *node.Report.Roles[0].CPUCores != cpu {
			t.Fatal("normalization changed absolute usage history")
		}
	}
	load.Reset()
	for sample := range 3 {
		now = now.Add(DefaultMinInterval)
		if err := load.RecordRequests(origin, report, nil); err != nil {
			t.Fatal(err)
		}
	}
	reading, err = load.Read(t.Context(), target, autoscale.Signal{Name: autoscale.SignalCPUUtilization, WindowSeconds: 10}, now)
	if err != nil || reading.Samples != 0 {
		t.Fatalf("missing task reservations reused configured request: %+v %v", reading, err)
	}
}
