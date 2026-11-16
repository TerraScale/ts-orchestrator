package swarmruntime

import (
	"context"
	"maps"

	"github.com/TerraScale/ts-orchestrator/internal/hostload"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

type ReplicaTelemetry struct {
	NodeID   string
	Tasks    map[string]hostload.RoleUsage
	Requests map[string]uint64
}

func (e *Executor) ReplicaLoad(ctx context.Context) (ReplicaTelemetry, error) {
	e.mu.Lock()
	tasks, nodeID := maps.Clone(e.loadTasks), e.functionNodeID
	e.mu.Unlock()
	groups := make([]string, 0, len(tasks))
	ids := make(map[string]string, len(tasks))
	for id, task := range tasks {
		if _, err := task.loadPID(ctx); err == nil {
			groups = append(groups, task.id)
			ids[task.id] = id
		}
	}
	e.replicaMu.Lock()
	defer e.replicaMu.Unlock()
	if e.replicaSampler == nil {
		e.replicaSampler = hostload.NewSampler(hostload.SamplerConfig{CgroupRoot: "/sys/fs/cgroup/terrascale"})
	}
	result := ReplicaTelemetry{NodeID: nodeID, Tasks: make(map[string]hostload.RoleUsage), Requests: observability.ServiceRequestCounts()}
	for _, usage := range e.replicaSampler.SampleCgroups(groups) {
		result.Tasks[ids[usage.Role]] = usage
	}
	return result, ctx.Err()
}
