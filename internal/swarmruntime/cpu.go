package swarmruntime

import (
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/moby/swarmkit/v2/api"
)

// NanoCPUs in Limits becomes the cgroup CFS quota, not its scheduler weight.
// Split budgets also set proportional shares from Reservations so bursting
// tasks compete by their packed CPU. Equal budgets keep the existing OCI spec.
func containerCPU(resources *api.ResourceRequirements) oci.SpecOpts {
	quota := oci.WithCPUCFS(resources.Limits.NanoCPUs/10_000, 100_000)
	if reserved := resources.Reservations; reserved != nil && reserved.NanoCPUs < resources.Limits.NanoCPUs {
		shares := uint64(max(int64(2), reserved.NanoCPUs*1024/1_000_000_000))
		return oci.Compose(quota, oci.WithCPUShares(shares))
	}
	return quota
}
