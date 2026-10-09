package regionview

import (
	"cmp"
	"maps"
	"math"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
)

// ResourceFreshFor matches the host report's five-minute freshness window.
const ResourceFreshFor = 5 * time.Minute

// Reading keeps an observed zero distinct from an absent measurement.
type Reading struct {
	Value      float64   `json:"value"`
	ObservedAt time.Time `json:"observed_at"`
}

func (reading *Reading) Fresh(now time.Time) bool {
	return reading != nil && !reading.ObservedAt.IsZero() && !reading.ObservedAt.After(now) && now.Sub(reading.ObservedAt) <= ResourceFreshFor
}

type ResourceView struct {
	ObservedAt      time.Time    `json:"observed_at,omitzero"`
	CPUCores        *Reading     `json:"cpu_cores,omitempty"`
	CPU             *Reading     `json:"cpu,omitempty"`
	MemoryBytes     *Reading     `json:"memory_bytes,omitempty"`
	MemoryUsedBytes *Reading     `json:"memory_used_bytes,omitempty"`
	Memory          *Reading     `json:"memory,omitempty"`
	Disk            *Reading     `json:"disk,omitempty"`
	Filesystems     []Filesystem `json:"filesystems,omitempty"`
	Pending         bool         `json:"pending,omitzero"`
	Incomplete      bool         `json:"incomplete,omitzero"`
	batchAt         time.Time
}

type Filesystem struct {
	Role      string   `json:"role,omitempty"`
	Path      string   `json:"path,omitempty"`
	Device    string   `json:"device,omitempty"`
	SizeBytes *Reading `json:"size_bytes,omitempty"`
	UsedBytes *Reading `json:"used_bytes,omitempty"`
	UsedRatio *Reading `json:"used_ratio,omitempty"`
	Files     *Reading `json:"files,omitempty"`
	FilesFree *Reading `json:"files_free,omitempty"`
}

// CollectResources reads authenticated whole-node reports by their host origin.
// Controller member names never select a node's physical resources.
func CollectResources(node Node, history observability.HistorySource, now time.Time) *ResourceView {
	resources := new(ResourceView)
	received := resources.latest(history, observability.HistHostReceivedAt, node.Name, now)
	if received == nil || received.Value <= 0 || received.Value > float64(now.UnixMilli()) {
		return resources
	}
	resources.batchAt = received.ObservedAt
	resources.ObservedAt = time.UnixMilli(int64(received.Value)).UTC()
	if incomplete := resources.latest(history, observability.HistHostFSIncomplete, node.Name, now); incomplete != nil && incomplete.Value == 1 {
		resources.Incomplete = true
	}
	resources.CPUCores = resources.latest(history, observability.HistHostCPUCores, node.Name, now)
	resources.CPU = resources.latest(history, observability.HistHostCPUUtilization, node.Name, now)
	resources.MemoryBytes = resources.latest(history, observability.HistHostMemoryTotal, node.Name, now)
	resources.Memory = resources.latest(history, observability.HistHostMemoryRatio, node.Name, now)
	resources.Disk = resources.latest(history, observability.HistHostDiskRatio, node.Name, now)
	if resources.MemoryBytes != nil && resources.Memory != nil && resources.MemoryBytes.ObservedAt.Equal(resources.Memory.ObservedAt) {
		resources.MemoryUsedBytes = &Reading{Value: resources.MemoryBytes.Value * resources.Memory.Value, ObservedAt: resources.Memory.ObservedAt}
	}
	resources.filesystems(history, node.Name, now)
	return resources
}

func (resources *ResourceView) latest(history observability.HistorySource, metric, member string, now time.Time) *Reading {
	result := resources.query(history, metric, member, now)
	var reading *Reading
	for _, series := range result.Series {
		if latest := latestReading(series.Points, now); latest != nil && (reading == nil || latest.ObservedAt.After(reading.ObservedAt)) {
			reading = latest
		}
	}
	if reading != nil && reading.Value == 0 && (metric == observability.HistHostCPUCores || metric == observability.HistHostMemoryTotal) {
		return nil
	}
	if reading != nil && metric != observability.HistHostReceivedAt {
		if !reading.ObservedAt.Equal(resources.batchAt) {
			return nil
		}
		reading.ObservedAt = resources.ObservedAt
	}
	return reading
}

func (resources *ResourceView) query(history observability.HistorySource, metric, member string, now time.Time) observability.HistoryResult {
	if history == nil {
		return observability.HistoryResult{}
	}
	result := history.Range(observability.HistoryQuery{Metric: metric, Labels: map[string]string{"member": strings.ToLower(member)},
		Start: now.Add(-time.Hour), End: now, Tier: observability.TierRaw})
	resources.Pending = resources.Pending || result.Pending
	resources.Incomplete = resources.Incomplete || result.Incomplete || result.Truncated
	return result
}

func latestReading(points []observability.Point, now time.Time) *Reading {
	var reading *Reading
	for _, point := range points {
		if math.IsNaN(point.Value) || math.IsInf(point.Value, 0) || point.Value < 0 || point.Time.After(now) {
			continue
		}
		if reading == nil || point.Time.After(reading.ObservedAt) {
			reading = &Reading{Value: point.Value, ObservedAt: point.Time}
		}
	}
	return reading
}

func (resources *ResourceView) filesystems(history observability.HistorySource, member string, now time.Time) {
	type identity struct {
		role, path, device string
	}
	entries := map[identity]*Filesystem{}
	for _, metric := range []string{observability.HistHostFSSize, observability.HistHostFSUsed, observability.HistHostFSRatio,
		observability.HistHostFSFiles, observability.HistHostFSFilesFree} {
		for _, series := range resources.query(history, metric, member, now).Series {
			reading := latestReading(series.Points, now)
			if reading == nil || !reading.ObservedAt.Equal(resources.batchAt) {
				continue
			}
			reading.ObservedAt = resources.ObservedAt
			key := identity{role: series.Labels["role"], path: series.Labels["path"], device: series.Labels["device"]}
			entry := entries[key]
			if entry == nil {
				entry = &Filesystem{Role: key.role, Path: key.path, Device: key.device}
				entries[key] = entry
			}
			switch metric {
			case observability.HistHostFSSize:
				if reading.Value > 0 {
					entry.SizeBytes = reading
				}
			case observability.HistHostFSUsed:
				entry.UsedBytes = reading
			case observability.HistHostFSRatio:
				entry.UsedRatio = reading
			case observability.HistHostFSFiles:
				entry.Files = reading
			case observability.HistHostFSFilesFree:
				entry.FilesFree = reading
			}
		}
	}
	devices := map[string]int{}
	for _, key := range slices.SortedFunc(maps.Keys(entries), func(left, right identity) int {
		return cmp.Or(cmp.Compare(left.role, right.role), cmp.Compare(left.path, right.path), cmp.Compare(left.device, right.device))
	}) {
		entry := entries[key]
		if entry.Device != "" && entry.Device != "0" {
			if index, found := devices[entry.Device]; found {
				resources.Filesystems[index].Role += ", " + entry.Role
				continue
			}
			devices[entry.Device] = len(resources.Filesystems)
		}
		resources.Filesystems = append(resources.Filesystems, *entry)
	}
}

func fillNodeCapacity(summary *Summary) {
	capacity := Capacity{StoreUsedBytes: summary.Capacity.StoreUsedBytes, StoreLimitBytes: summary.Capacity.StoreLimitBytes,
		Partial: len(summary.Nodes) == 0}
	seen := map[string]bool{}
	for _, node := range summary.Nodes {
		if seen[node.Name] {
			continue
		}
		seen[node.Name] = true
		resources := node.Resources
		if resources == nil {
			capacity.Partial = true
			continue
		}
		capacity.Partial = capacity.Partial || resources.Pending || resources.Incomplete
		if resources.CPUCores.Fresh(summary.ObservedAt) && resources.CPU.Fresh(summary.ObservedAt) &&
			resources.CPUCores.ObservedAt.Equal(resources.CPU.ObservedAt) {
			capacity.CPUs += int(resources.CPUCores.Value)
			capacity.CPUUtilization += resources.CPU.Value * resources.CPUCores.Value
		} else {
			capacity.Partial = true
		}
		if resources.MemoryBytes.Fresh(summary.ObservedAt) && resources.MemoryUsedBytes.Fresh(summary.ObservedAt) &&
			resources.MemoryBytes.ObservedAt.Equal(resources.MemoryUsedBytes.ObservedAt) {
			capacity.MemoryBytes += uint64(resources.MemoryBytes.Value)
			capacity.MemoryUsedBytes += uint64(resources.MemoryUsedBytes.Value)
		} else {
			capacity.Partial = true
		}
		if len(resources.Filesystems) == 0 {
			capacity.Partial = true
		}
		for _, filesystem := range resources.Filesystems {
			if filesystem.SizeBytes.Fresh(summary.ObservedAt) && filesystem.UsedBytes.Fresh(summary.ObservedAt) &&
				filesystem.SizeBytes.ObservedAt.Equal(filesystem.UsedBytes.ObservedAt) {
				capacity.DiskBytes += uint64(filesystem.SizeBytes.Value)
				capacity.DiskUsedBytes += uint64(filesystem.UsedBytes.Value)
			} else {
				capacity.Partial = true
			}
		}
	}
	if capacity.CPUs > 0 {
		capacity.CPUUtilization /= float64(capacity.CPUs)
	}
	summary.Capacity = capacity
}
