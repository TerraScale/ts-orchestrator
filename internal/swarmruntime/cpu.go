package swarmruntime

import (
	"runtime"

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
		quota = max(quota, int64(hostCPUs())*1_000_000_000*dataOwnerCPUShare/100)
	}
	return oci.WithCPUCFS(quota/10_000, 100_000)
}

// dataOwnerCPUShare is the percent of the host's cores a data owner (a task
// with mounts: TerraBase, its region's only writer) may burst to. A 1-CPU
// quota throttled TerraBase in 92-97 % of periods on all three hosts
// (2026-10-28): the ~60 s catalog gate after a restart, multi-second writer
// holds, ts-auth 503s and slow dashboard reads. 75 % is 3 of gru's 4 cores
// and 1.5 of sjc's and fra's 2, leaving the rest to ts-auth and the
// dashboard. Its scheduler reservation is unchanged, so placement is too.
const dataOwnerCPUShare = 75

// hostCPUs is the host's core count; tests replace it.
var hostCPUs = runtime.NumCPU
