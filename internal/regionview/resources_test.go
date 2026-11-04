package regionview

import (
	"context"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

func TestRegionResourceAPIAndCapacity(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Minute)
	history := observability.NewHistory(observability.HistoryConfig{})
	history.Append(now, []observability.Sample{
		{Metric: observability.HistHostReceivedAt, Labels: observability.L("member", "host"), Value: float64(now.UnixMilli())},
		{Metric: observability.HistHostReceivedAt, Labels: observability.L("member", "node"), Value: float64(now.UnixMilli())},
		{Metric: observability.HistCPUUtilization, Labels: observability.L("member", "controller"), Value: 0},
		{Metric: observability.HistHostCPUCores, Labels: observability.L("member", "host"), Value: 2},
		{Metric: observability.HistHostCPUUtilization, Labels: observability.L("member", "host"), Value: 0},
		{Metric: observability.HistHostMemoryTotal, Labels: observability.L("member", "host"), Value: 100},
		{Metric: observability.HistHostMemoryRatio, Labels: observability.L("member", "host"), Value: 0},
		// Colocated host readings must not add the controller twice.
		{Metric: observability.HistHostCPUCores, Labels: observability.L("member", "node"), Value: 4},
		{Metric: observability.HistHostCPUUtilization, Labels: observability.L("member", "node"), Value: 0},
		{Metric: observability.HistHostMemoryTotal, Labels: observability.L("member", "node"), Value: 200},
		{Metric: observability.HistHostMemoryRatio, Labels: observability.L("member", "node"), Value: 0},
	})
	provider := &Provider{Cell: "gru", Now: func() time.Time { return now }, History: history,
		Cluster: staticCluster{observability.ClusterSnapshot{Members: []observability.MemberSnapshot{
			{Member: "controller", Role: "controller", ObservedAt: now,
				System: &observability.SystemView{CPUCount: 4, MemTotalBytes: 200, MemAvailBytes: 200}},
		}}}, Nodes: func(_ context.Context) []Node {
			return []Node{{Name: "node", Member: "controller"}, {Name: "host"}, {Name: "missing"}}
		}}
	summary := provider.Local(t.Context())
	if summary.Capacity.CPUs != 6 || summary.Capacity.MemoryBytes != 300 || summary.Capacity.MemoryUsedBytes != 0 {
		t.Fatalf("capacity = %+v", summary.Capacity)
	}
	if summary.Nodes[0].Resources.CPU == nil || summary.Nodes[0].Resources.CPU.Value != 0 || !summary.Nodes[0].Resources.CPU.ObservedAt.Equal(now) {
		t.Fatalf("API dropped observed zero: %+v", summary.Nodes[0].Resources.CPU)
	}
	if summary.Nodes[2].Resources.CPU != nil || summary.Nodes[2].Resources.Memory != nil {
		t.Fatalf("API invented missing readings: %+v", summary.Nodes[2].Resources)
	}
}
