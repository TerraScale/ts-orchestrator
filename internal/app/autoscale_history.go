package app

import (
	"context"
	"slices"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostload"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/workload"
)

// withAutoscaleSamples adds the workload autoscaler's per-service replica,
// goal and signal readings, and the host load aggregator's node and service
// resource usage and TerraBase load blocks, to every history sample. Both
// are filled only on the authority leader, so followers record nothing extra.
// A nil reconciler returns collect unchanged.
func withAutoscaleSamples(collect func(context.Context) []observability.Sample, reconciler *workload.Reconciler,
) func(context.Context) []observability.Sample {
	if reconciler == nil {
		return collect
	}
	load, _ := reconciler.Signals().(*hostload.Aggregator)
	return func(ctx context.Context) []observability.Sample {
		samples := collect(ctx)
		if !reconciler.Leading() {
			// A former leader's last results and cached host reports, or a
			// re-acquired lease's not yet reset ones, are not current;
			// recording them would chart stale state as live.
			return samples
		}
		return append(samples, leaderAutoscaleSamples(reconciler, load)...)
	}
}

// leaderAutoscaleSamples is what the current term's leader records.
func leaderAutoscaleSamples(reconciler *workload.Reconciler, load *hostload.Aggregator) []observability.Sample {
	return append(autoscaleSamples(reconciler), hostLoadSamples(load)...)
}

// autoscaleSamples reports every reconciled service that has a result.
func autoscaleSamples(reconciler *workload.Reconciler) []observability.Sample {
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
