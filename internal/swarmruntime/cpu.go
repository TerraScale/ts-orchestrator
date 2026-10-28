package swarmruntime

import (
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/moby/swarmkit/v2/api"
)

// NanoCPUs in Limits becomes the cgroup CFS quota. Every task keeps the
// default scheduler weight: TerraBase and other equal-budget tasks run at it,
// so a lower weight for a bursting app starved its startup on 2-CPU hosts
// (the sjc dashboard took 65 s to become ready on 2026-10-28 instead of 13 s).
func containerCPU(resources *api.ResourceRequirements) oci.SpecOpts {
	return oci.WithCPUCFS(resources.Limits.NanoCPUs/10_000, 100_000)
}
