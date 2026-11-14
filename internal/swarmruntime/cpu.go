package swarmruntime

import (
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/moby/swarmkit/v2/api"
)

// NanoCPUs in Limits becomes the cgroup CFS quota. Every task keeps the
// default scheduler weight: TerraBase and other equal-budget tasks run at it,
// so a lower weight for a bursting app starved its startup on 2-CPU hosts
// (the sjc dashboard took 65 s to become ready on 2026-10-28 instead of 13 s).
func containerCPU(resources *api.ResourceRequirements, dataOwner bool) oci.SpecOpts {
	quota := resources.Limits.NanoCPUs
	if dataOwner {
		quota = max(quota, dataOwnerCPULimit)
	}
	return oci.WithCPUCFS(quota/10_000, 100_000)
}

// dataOwnerCPULimit is the CFS limit of a data owner (a task with mounts:
// TerraBase, its region's only writer) on every host, above its 1000m
// scheduler reservation (user decision Q-TB-CPU-LIMIT). A 1-CPU quota
// throttled TerraBase in 85-97 % of periods (2026-10-28): the ~60 s catalog
// gate after a restart, multi-second writer holds, ts-auth 503s and slow
// dashboard reads.
const dataOwnerCPULimit = 2_000_000_000
