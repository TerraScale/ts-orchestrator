package swarmruntime

import (
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/api/genericresource"
)

func containerTestResources(cpu, memory int64) *api.ResourceRequirements {
	limits := &api.Resources{NanoCPUs: cpu, MemoryBytes: memory, Generic: []*api.GenericResource{genericresource.NewDiscrete(DiskResource, 64<<20)}}
	return &api.ResourceRequirements{Limits: limits, Reservations: limits.Copy()}
}
