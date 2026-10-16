package regionview

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

func TestResourcesUseCanonicalHostOrigin(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Minute)
	history := observability.NewHistory(observability.HistoryConfig{})
	history.Append(now, []observability.Sample{
		{Metric: observability.HistHostReceivedAt, Labels: observability.L("member", "node-a"), Value: float64(now.UnixMilli())},
		{Metric: observability.HistHostReceivedAt, Labels: observability.L("member", "controller-a"), Value: float64(now.UnixMilli())},
		{Metric: observability.HistCPUUtilization, Labels: observability.L("member", "controller-a"), Value: 0},
		{Metric: observability.HistCPUUtilization, Labels: observability.L("member", "node-a"), Value: .95},
		{Metric: observability.HistHostCPUUtilization, Labels: observability.L("member", "node-a"), Value: .75},
		{Metric: observability.HistHostCPUCores, Labels: observability.L("member", "node-a"), Value: 4},
		{Metric: observability.HistHostMemoryTotal, Labels: observability.L("member", "node-a"), Value: 2048},
		{Metric: observability.HistHostMemoryRatio, Labels: observability.L("member", "node-a"), Value: 0},
		{Metric: observability.HistHostDiskRatio, Labels: observability.L("member", "node-a"), Value: 0},
		{Metric: observability.HistHostCPUUtilization, Labels: observability.L("member", "controller-a"), Value: .25},
		{Metric: observability.HistHostCPUCores, Labels: observability.L("member", "controller-a"), Value: 2},
		{Metric: observability.HistHostMemoryTotal, Labels: observability.L("member", "controller-a"), Value: 1024},
		{Metric: observability.HistHostMemoryRatio, Labels: observability.L("member", "controller-a"), Value: 0},
		{Metric: observability.HistHostDiskRatio, Labels: observability.L("member", "controller-a"), Value: 0},
	})
	controller := CollectResources(Node{Name: "node-a", Member: "controller-a"}, history, now)
	if controller.CPU == nil || controller.CPU.Value != .75 || controller.CPUCores.Value != 4 || controller.Memory.Value != 0 {
		t.Fatalf("declared controller resources = %+v", controller)
	}
	host := CollectResources(Node{Name: "controller-a"}, history, now)
	if host.CPU.Value != .25 || host.CPUCores.Value != 2 || host.MemoryUsedBytes.Value != 0 || host.Disk.Value != 0 {
		t.Fatalf("host-only resources = %+v", host)
	}
	missing := CollectResources(Node{Name: "missing", Member: "controller-a"}, history, now)
	if missing.CPU != nil || missing.CPUCores != nil || missing.MemoryBytes != nil {
		t.Fatalf("unmapped member borrowed another source: %+v", missing)
	}
}

func TestResourcesPreserveMissingAndStale(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Minute)
	history := observability.NewHistory(observability.HistoryConfig{})
	at := now.Add(-ResourceFreshFor - time.Minute)
	history.Append(now, []observability.Sample{
		{Metric: observability.HistHostReceivedAt, Labels: observability.L("member", "host"), Value: float64(at.UnixMilli())},
		{Metric: observability.HistHostCPUUtilization, Labels: observability.L("member", "host"), Value: 0},
	})
	resources := CollectResources(Node{Name: "host"}, history, now)
	if resources.CPU == nil || resources.CPU.Value != 0 || resources.CPU.Fresh(now) || !resources.CPU.ObservedAt.Equal(at) {
		t.Fatalf("stale reading = %+v", resources.CPU)
	}
	if resources.Memory != nil || resources.MemoryBytes != nil || resources.Disk != nil {
		t.Fatalf("missing data became zero: %+v", resources)
	}
}

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

func TestRegionCapacityMarksNodePresentationTruncation(t *testing.T) {
	t.Parallel()
	for _, count := range []int{maxTopologyMembers, maxTopologyMembers + 1} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Minute)
			history := observability.NewHistory(observability.HistoryConfig{})
			nodes := make([]Node, count)
			for index := range nodes {
				name := fmt.Sprintf("node-%d", index)
				nodes[index] = Node{Name: name}
				labels := observability.L("member", name)
				filesystem := observability.L("member", name, "role", "boot", "path", "/", "device", "1")
				history.Append(now, []observability.Sample{
					{Metric: observability.HistHostReceivedAt, Labels: labels, Value: float64(now.UnixMilli())},
					{Metric: observability.HistHostCPUCores, Labels: labels, Value: 2},
					{Metric: observability.HistHostCPUUtilization, Labels: labels, Value: .25},
					{Metric: observability.HistHostMemoryTotal, Labels: labels, Value: 100},
					{Metric: observability.HistHostMemoryRatio, Labels: labels, Value: .5},
					{Metric: observability.HistHostFSSize, Labels: filesystem, Value: 200},
					{Metric: observability.HistHostFSUsed, Labels: filesystem, Value: 100},
				})
			}
			provider := &Provider{Cell: "gru", Now: func() time.Time { return now }, History: history,
				Nodes: func(context.Context) []Node { return nodes }}
			summary := provider.Local(t.Context())
			if len(summary.Nodes) != maxTopologyMembers || summary.Capacity.CPUs != 2*maxTopologyMembers ||
				summary.Capacity.MemoryBytes != 100*maxTopologyMembers || summary.Capacity.DiskBytes != 200*maxTopologyMembers ||
				summary.Capacity.Partial != (count > maxTopologyMembers) {
				t.Fatalf("%d reported nodes: capacity = %+v, presented nodes = %d", count, summary.Capacity, len(summary.Nodes))
			}
		})
	}
}

func TestFilesystemReplacedRoleKeepsOnlyCoherentLatestReport(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Minute)
	history := observability.NewHistory(observability.HistoryConfig{})
	old := observability.L("member", "node", "role", "data", "path", "/old", "device", "7")
	current := observability.L("member", "node", "role", "data", "path", "/new", "device", "8")
	history.Append(now.Add(-time.Minute), []observability.Sample{
		{Metric: observability.HistHostFSSize, Labels: old, Value: 100},
		{Metric: observability.HistHostFSUsed, Labels: old, Value: 90},
		{Metric: observability.HistHostFSRatio, Labels: old, Value: .9},
		{Metric: observability.HistHostFSUsed, Labels: current, Value: 80},
		{Metric: observability.HistHostFSRatio, Labels: current, Value: .8},
	})
	// A partial newest report must not borrow an older used value or device.
	history.Append(now, []observability.Sample{{Metric: observability.HistHostFSSize, Labels: current, Value: 200}})
	history.Append(now, []observability.Sample{{Metric: observability.HistHostReceivedAt, Labels: observability.L("member", "node"), Value: float64(now.UnixMilli())}})
	resources := CollectResources(Node{Name: "node", Member: "unavailable-controller"}, history, now)
	if len(resources.Filesystems) != 1 {
		t.Fatalf("old filesystem retained: %+v", resources.Filesystems)
	}
	filesystem := resources.Filesystems[0]
	if filesystem.Path != "/new" || filesystem.Device != "8" || filesystem.SizeBytes.Value != 200 || filesystem.UsedBytes != nil || filesystem.UsedRatio != nil {
		t.Fatalf("mixed filesystem observations: %+v", filesystem)
	}
	history.Append(now, []observability.Sample{
		{Metric: observability.HistHostFSUsed, Labels: current, Value: 0},
		{Metric: observability.HistHostFSRatio, Labels: current, Value: 0},
	})
	filesystem = CollectResources(Node{Name: "node"}, history, now).Filesystems[0]
	if filesystem.UsedBytes.Value != 0 || filesystem.UsedRatio.Value != 0 || !filesystem.UsedBytes.ObservedAt.Equal(filesystem.SizeBytes.ObservedAt) {
		t.Fatalf("coherent zero lost: %+v", filesystem)
	}
}

func TestFilesystemUnknownSizeRemainsUnavailable(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Minute)
	history := observability.NewHistory(observability.HistoryConfig{})
	labels := observability.L("member", "node", "role", "unreadable")
	history.Append(now, []observability.Sample{
		{Metric: observability.HistHostFSSize, Labels: labels, Value: 0},
		{Metric: observability.HistHostFSUsed, Labels: labels, Value: 0},
		{Metric: observability.HistHostReceivedAt, Labels: observability.L("member", "node"), Value: float64(now.UnixMilli())},
	})
	resources := CollectResources(Node{Name: "node"}, history, now)
	if len(resources.Filesystems) != 1 || resources.Filesystems[0].SizeBytes != nil {
		t.Fatalf("unknown size became observed zero: %+v", resources.Filesystems)
	}
}

func TestLatestHostReportCannotBorrowMissingMetricsFromOlderReports(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Minute)
	history := observability.NewHistory(observability.HistoryConfig{})
	labels := observability.L("member", "node")
	filesystem := observability.L("member", "node", "role", "data", "path", "/data", "device", "7")
	history.Append(now.Add(-time.Minute), []observability.Sample{
		{Metric: observability.HistHostReceivedAt, Labels: labels, Value: float64(now.Add(-time.Minute).UnixMilli())},
		{Metric: observability.HistHostCPUUtilization, Labels: labels, Value: .25},
		{Metric: observability.HistHostMemoryRatio, Labels: labels, Value: .5},
		{Metric: observability.HistHostFSSize, Labels: filesystem, Value: 100},
		{Metric: observability.HistHostFSUsed, Labels: filesystem, Value: 50},
	})
	history.Append(now, []observability.Sample{{Metric: observability.HistHostReceivedAt, Labels: labels, Value: float64(now.UnixMilli())}})
	resources := CollectResources(Node{Name: "node"}, history, now)
	if resources.CPU != nil || resources.Memory != nil || len(resources.Filesystems) != 0 {
		t.Fatalf("missing latest measurements borrowed healthy older values: %+v", resources)
	}
}

func TestCapacityExcludesMissingStaleAndIncoherentUsage(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	reading := func(value float64, at time.Time) *Reading { return &Reading{Value: value, ObservedAt: at} }
	for name, usage := range map[string]*Reading{
		"missing": nil, "stale": reading(90, now.Add(-6*time.Minute)),
		"different report": reading(90, now.Add(-time.Minute)),
	} {
		t.Run(name, func(t *testing.T) {
			summary := Summary{ObservedAt: now, Nodes: []Node{
				{Name: "known", Resources: &ResourceView{CPUCores: reading(4, now), CPU: reading(.75, now),
					MemoryBytes: reading(100, now), MemoryUsedBytes: reading(90, now),
					Filesystems: []Filesystem{{SizeBytes: reading(100, now), UsedBytes: reading(90, now)}}}},
				{Name: "partial", Resources: &ResourceView{CPUCores: reading(2, now), CPU: reading(.5, now),
					MemoryBytes: reading(900, now), MemoryUsedBytes: usage,
					Filesystems: []Filesystem{{SizeBytes: reading(900, now), UsedBytes: usage}}}},
			}}
			fillNodeCapacity(&summary)
			capacity := summary.Capacity
			if capacity.MemoryBytes != 100 || capacity.MemoryUsedBytes != 90 || capacity.DiskBytes != 100 ||
				capacity.DiskUsedBytes != 90 || !capacity.Partial || capacity.CPUs != 6 || capacity.CPUUtilization != 2.0/3 {
				t.Fatalf("unknown usage diluted utilization: %+v", capacity)
			}
		})
	}
	// Measured zero remains complete coverage.
	summary := Summary{ObservedAt: now, Nodes: []Node{{Name: "idle", Resources: &ResourceView{
		CPUCores: reading(4, now), CPU: reading(0, now), MemoryBytes: reading(100, now), MemoryUsedBytes: reading(0, now),
		Filesystems: []Filesystem{{SizeBytes: reading(100, now), UsedBytes: reading(0, now)}},
	}}}}
	fillNodeCapacity(&summary)
	if summary.Capacity.Partial || summary.Capacity.MemoryBytes != 100 || summary.Capacity.MemoryUsedBytes != 0 {
		t.Fatalf("measured zero lost coverage: %+v", summary.Capacity)
	}
}

func TestFilesystemCollectionFailureMarksCoverageAndRecovers(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Minute)
	history := observability.NewHistory(observability.HistoryConfig{})
	labels := observability.L("member", "host")
	filesystem := observability.L("member", "host", "role", "boot", "path", "/", "device", "7")
	samples := []observability.Sample{
		{Metric: observability.HistHostReceivedAt, Labels: labels, Value: float64(now.UnixMilli())},
		{Metric: observability.HistHostFSIncomplete, Labels: labels, Value: 1},
		{Metric: observability.HistHostCPUCores, Labels: labels, Value: 4},
		{Metric: observability.HistHostCPUUtilization, Labels: labels, Value: .1},
		{Metric: observability.HistHostMemoryTotal, Labels: labels, Value: 100},
		{Metric: observability.HistHostMemoryRatio, Labels: labels, Value: .1},
		{Metric: observability.HistHostFSSize, Labels: filesystem, Value: 100},
		{Metric: observability.HistHostFSUsed, Labels: filesystem, Value: 10},
	}
	history.Append(now, samples)
	resources := CollectResources(Node{Name: "host"}, history, now)
	summary := Summary{ObservedAt: now, Nodes: []Node{{Name: "host", Resources: resources}}}
	fillNodeCapacity(&summary)
	if !resources.Incomplete || !summary.Capacity.Partial || len(resources.Filesystems) != 1 || summary.Capacity.DiskUsedBytes != 10 {
		t.Fatalf("failed data filesystem claimed complete coverage: resources=%+v capacity=%+v", resources, summary.Capacity)
	}
	now = now.Add(time.Minute)
	samples[0].Value, samples[1].Value = float64(now.UnixMilli()), 0
	history.Append(now, samples)
	resources = CollectResources(Node{Name: "host"}, history, now)
	summary.ObservedAt, summary.Nodes[0].Resources = now, resources
	fillNodeCapacity(&summary)
	if resources.Incomplete || summary.Capacity.Partial {
		t.Fatalf("successful collection kept the earlier failure: %+v", summary.Capacity)
	}
}
