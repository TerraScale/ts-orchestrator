package app

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/hostload"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

// withAutoscaleSamples adds the workload autoscaler's per-service replica,
// goal and signal readings, and the host load aggregator's node and service
// resource usage and TerraBase load blocks, to every history sample. Both
// are filled only on the authority leader, so followers record nothing extra.
func withAutoscaleSamples(collect func(context.Context) []observability.Sample, reconciler workloadObservation,
	load *hostTelemetry,
) func(context.Context) []observability.Sample {
	if reconciler == nil && load == nil {
		return collect
	}
	return func(ctx context.Context) []observability.Sample {
		samples := collect(ctx)
		if reconciler != nil && reconciler.Leading() {
			samples = append(samples, autoscaleSamples(reconciler)...)
		}
		if load != nil {
			samples = append(samples, load.samples()...)
		}
		return samples
	}
}

// autoscaleSamples reports every reconciled service that has a result.
func autoscaleSamples(reconciler workloadObservation) []observability.Sample {
	last := reconciler.Last()
	roles := make([]string, 0, len(last))
	for role := range last {
		roles = append(roles, role)
	}
	slices.Sort(roles)
	var samples []observability.Sample
	for _, role := range roles {
		result := last[role]
		if result.Reason == "awaiting-release" {
			continue
		}
		spec, owned := reconciler.Owns(role)
		if !owned {
			continue
		}
		service := observability.L("service", role)
		samples = append(samples,
			observability.Sample{Metric: observability.HistAutoscaleReplicas, Labels: service, Value: float64(result.Replicas)},
			observability.Sample{Metric: observability.HistAutoscaleGoal, Labels: service, Value: float64(result.Target)})
		if spec.Scaling == nil {
			continue
		}
		for _, signal := range spec.Scaling.Signals {
			labels := observability.L("service", role, "signal", string(signal.Name))
			samples = append(samples, observability.Sample{Metric: observability.HistAutoscaleSignalTarget,
				Labels: labels, Value: signal.Target})
			for _, reading := range result.Readings {
				if reading.Signal == signal.Name && reading.Samples > 0 {
					samples = append(samples, observability.Sample{Metric: observability.HistAutoscaleSignal,
						Labels: labels, Value: reading.Value})
				}
			}
		}
	}
	return samples
}

// hostLoadSamples reports the latest non-stale authenticated host reports.
func hostLoadSamples(load *hostload.Aggregator) []observability.Sample {
	if load == nil {
		return nil
	}
	var samples []observability.Sample
	for _, node := range load.Nodes() {
		member := strings.ToLower(node.Origin.Node)
		labels := observability.L("member", member)
		samples = append(samples, observability.Sample{Metric: observability.HistHostReceivedAt,
			Labels: labels, Value: float64(node.At.UnixMilli())})
		incomplete := 0.0
		if node.Report.Host.FilesystemsIncomplete {
			incomplete = 1
		}
		samples = append(samples, observability.Sample{Metric: observability.HistHostFSIncomplete, Labels: labels, Value: incomplete})
		for _, value := range []struct {
			metric string
			value  *float64
		}{{observability.HistHostCPUUtilization, node.Report.Host.CPU},
			{observability.HistHostMemoryRatio, node.Report.Host.Memory},
			{observability.HistHostDiskRatio, node.Report.Host.Disk}} {
			if value.value != nil {
				samples = append(samples, observability.Sample{Metric: value.metric, Labels: labels, Value: *value.value})
			}
		}
		if node.Report.Host.CPUCores > 0 {
			samples = append(samples, observability.Sample{Metric: observability.HistHostCPUCores,
				Labels: labels, Value: float64(node.Report.Host.CPUCores)})
		}
		if node.Report.Host.MemoryBytes > 0 {
			samples = append(samples, observability.Sample{Metric: observability.HistHostMemoryTotal,
				Labels: labels, Value: float64(node.Report.Host.MemoryBytes)})
		}
		for _, filesystem := range node.Report.Host.Filesystems {
			labels := observability.L("member", member, "role", filesystem.Role,
				"path", filesystem.Path, "device", strconv.FormatUint(filesystem.Device, 10))
			used := float64(filesystem.SizeBytes - filesystem.AvailBytes)
			samples = append(samples,
				observability.Sample{Metric: observability.HistHostFSUsed, Labels: labels, Value: used},
				observability.Sample{Metric: observability.HistHostFSSize, Labels: labels, Value: float64(filesystem.SizeBytes)},
				observability.Sample{Metric: observability.HistHostFSRatio, Labels: labels, Value: used / float64(filesystem.SizeBytes)},
				observability.Sample{Metric: observability.HistHostFSFiles, Labels: labels, Value: float64(filesystem.Files)},
				observability.Sample{Metric: observability.HistHostFSFilesFree, Labels: labels, Value: float64(filesystem.FilesFree)})
		}
		for _, role := range node.Report.Roles {
			service := observability.L("member", member, "service", role.Role)
			if role.CPUCores != nil {
				samples = append(samples, observability.Sample{Metric: observability.HistServiceCPUCores,
					Labels: service, Value: *role.CPUCores})
			}
			if role.MemoryBytes != nil {
				samples = append(samples, observability.Sample{Metric: observability.HistServiceMemoryUsed,
					Labels: service, Value: float64(*role.MemoryBytes)})
			}
			if wan := role.WAN; wan != nil && wan.Fresh(time.Now()) && wan.Validate() == nil {
				for _, source := range wan.Sources {
					labels := observability.L("member", member, "node", node.Origin.Node, "role", role.Role,
						"receiver_region", wan.ReceiverRegion, "source_region", source.SourceRegion)
					samples = append(samples, observability.Sample{Metric: observability.HistTerraBaseWANObservedAt,
						Labels: labels, Value: float64(wan.ObservedAt.UnixMilli())})
					for _, reading := range []struct {
						metric string
						value  *float64
					}{{observability.HistTerraBaseWANLagGroups, source.LagGroups},
						{observability.HistTerraBaseWANStaleness, source.StalenessSeconds},
						{observability.HistTerraBaseWANMembers, source.Members},
						{observability.HistTerraBaseWANUnregistered, source.Unregistered},
						{observability.HistTerraBaseWANConflicts, source.Conflicts},
						{observability.HistTerraBaseWANAheadFailures, source.AheadFailuresTotal}} {
						if reading.value != nil {
							samples = append(samples, observability.Sample{Metric: reading.metric, Labels: labels, Value: *reading.value})
						}
					}
				}
			}
			block := role.TerraBase
			if block == nil {
				continue
			}
			labels := observability.L("member", member, "role", role.Role)
			samples = append(samples,
				observability.Sample{Metric: observability.HistTerraBaseConnections, Labels: labels, Value: float64(block.Connections)},
				observability.Sample{Metric: observability.HistTerraBaseStorage, Labels: labels, Value: float64(block.StorageBytes)},
				observability.Sample{Metric: observability.HistTerraBaseLagSeq, Labels: labels, Value: float64(block.ReplicationLagSeq)},
				observability.Sample{Metric: observability.HistTerraBaseWriteQPS, Labels: labels, Value: block.WriteQPS})
		}
	}
	return samples
}
