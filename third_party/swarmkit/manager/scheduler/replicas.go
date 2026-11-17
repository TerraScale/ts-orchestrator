package scheduler

import (
	"strconv"

	"github.com/moby/swarmkit/v2/api"
)

func ReplicaCapacity(service *api.Service, nodes []*api.Node, tasks []*api.Task, maximum int) int {
	candidate := &api.Task{ServiceID: service.ID, Spec: *service.Spec.Task.Copy(), Endpoint: service.Endpoint.Copy(), DesiredState: api.TaskStateRunning}
	if service.Spec.Endpoint != nil {
		candidate.Endpoint = &api.Endpoint{Spec: service.Spec.Endpoint.Copy(), Ports: service.Spec.Endpoint.Copy().Ports}
	}
	filters := []Filter{&ReadyFilter{}, &ResourceFilter{}, &ConstraintFilter{}, &PlatformFilter{}, &HostPortFilter{}, &MaxReplicasFilter{}}
	active := make([]Filter, 0, len(filters))
	for _, filter := range filters {
		if filter.SetTask(candidate) {
			active = append(active, filter)
		}
	}
	total := 0
	for _, node := range nodes {
		if node.Description == nil || node.Description.Resources == nil {
			continue
		}
		info := newNodeInfo(node, nil, *node.Description.Resources.Copy())
		for _, task := range tasks {
			if task.NodeID == node.ID && task.Status.State < api.TaskStateCompleted {
				info.addTask(task.Copy())
			}
		}
		for total < maximum {
			fits := true
			for _, filter := range active {
				if !filter.Check(&info) {
					fits = false
					break
				}
			}
			if !fits {
				break
			}
			candidate.ID = "replica-capacity-" + strconv.Itoa(total)
			info.addTask(candidate.Copy())
			total++
		}
	}
	return total
}
