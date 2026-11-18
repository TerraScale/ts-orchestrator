package scheduler

import (
	"context"
	"time"

	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/api/genericresource"
	"github.com/moby/swarmkit/v2/log"
)

// hostPortSpec specifies a used host port.
type hostPortSpec struct {
	protocol      api.PortConfig_Protocol
	publishedPort uint32
}

// versionedService defines a tuple that contains a service ID and a spec
// version, so that failures can be tracked per spec version. Note that if the
// task predates spec versioning, specVersion will contain the zero value, and
// this will still work correctly.
type versionedService struct {
	serviceID   string
	specVersion api.Version
}

// NodeInfo contains a node and some additional metadata.
type NodeInfo struct {
	*api.Node
	Tasks                     map[string]*api.Task
	ActiveTasksCount          int
	ActiveTasksCountByService map[string]int
	AvailableResources        *api.Resources
	usedHostPorts             map[hostPortSpec]struct{}
	heldRooms                 map[roomKey]room

	// recentFailures is a map from service ID/version to the timestamps of
	// the most recent failures the node has experienced from replicas of
	// that service.
	recentFailures map[versionedService][]time.Time

	// lastCleanup is the last time recentFailures was cleaned up. This is
	// done periodically to avoid recentFailures growing without any limit.
	lastCleanup time.Time
}

func newNodeInfo(n *api.Node, tasks map[string]*api.Task, availableResources api.Resources) NodeInfo {
	nodeInfo := NodeInfo{
		Node:                      n,
		Tasks:                     make(map[string]*api.Task),
		ActiveTasksCountByService: make(map[string]int),
		AvailableResources:        availableResources.Copy(),
		usedHostPorts:             make(map[hostPortSpec]struct{}),
		heldRooms:                 make(map[roomKey]room),
		recentFailures:            make(map[versionedService][]time.Time),
		lastCleanup:               time.Now(),
	}

	for _, t := range tasks {
		nodeInfo.addTask(t)
	}

	return nodeInfo
}

// removeTask removes a task from nodeInfo if it's tracked there, and returns true
// if nodeInfo was modified.
func (nodeInfo *NodeInfo) removeTask(t *api.Task) bool {
	oldTask, ok := nodeInfo.Tasks[t.ID]
	if !ok {
		return false
	}

	delete(nodeInfo.Tasks, t.ID)
	if oldTask.DesiredState <= api.TaskStateCompleted {
		nodeInfo.ActiveTasksCount--
		nodeInfo.ActiveTasksCountByService[t.ServiceID]--
	}

	if t.Endpoint != nil {
		for _, port := range t.Endpoint.Ports {
			if port.PublishMode == api.PublishModeHost && port.PublishedPort != 0 {
				portSpec := hostPortSpec{protocol: port.Protocol, publishedPort: port.PublishedPort}
				delete(nodeInfo.usedHostPorts, portSpec)
			}
		}
	}

	nodeInfo.recount(roomOf(oldTask))
	resources := nodeInfo.AvailableResources

	if nodeInfo.Description == nil || nodeInfo.Description.Resources == nil ||
		nodeInfo.Description.Resources.Generic == nil {
		return true
	}

	taskAssigned := t.AssignedGenericResources
	nodeAvailableResources := &resources.Generic
	nodeRes := nodeInfo.Description.Resources.Generic
	genericresource.Reclaim(nodeAvailableResources, taskAssigned, nodeRes)

	return true
}

// addTask adds or updates a task on nodeInfo, and returns true if nodeInfo was
// modified.
func (nodeInfo *NodeInfo) addTask(t *api.Task) bool {
	oldTask, ok := nodeInfo.Tasks[t.ID]
	if ok {
		if t.DesiredState <= api.TaskStateCompleted && oldTask.DesiredState > api.TaskStateCompleted {
			nodeInfo.Tasks[t.ID] = t
			nodeInfo.ActiveTasksCount++
			nodeInfo.ActiveTasksCountByService[t.ServiceID]++
			return true
		} else if t.DesiredState > api.TaskStateCompleted && oldTask.DesiredState <= api.TaskStateCompleted {
			nodeInfo.Tasks[t.ID] = t
			nodeInfo.ActiveTasksCount--
			nodeInfo.ActiveTasksCountByService[t.ServiceID]--
			return true
		}
		return false
	}

	nodeInfo.Tasks[t.ID] = t
	nodeInfo.recount(roomOf(t))

	reservations := taskReservations(t.Spec)
	resources := nodeInfo.AvailableResources

	// minimum size required
	t.AssignedGenericResources = make([]*api.GenericResource, 0, len(resources.Generic))
	taskAssigned := &t.AssignedGenericResources

	genericresource.Claim(&resources.Generic, taskAssigned, reservations.Generic)

	if t.Endpoint != nil {
		for _, port := range t.Endpoint.Ports {
			if port.PublishMode == api.PublishModeHost && port.PublishedPort != 0 {
				portSpec := hostPortSpec{protocol: port.Protocol, publishedPort: port.PublishedPort}
				nodeInfo.usedHostPorts[portSpec] = struct{}{}
			}
		}
	}

	if t.DesiredState <= api.TaskStateCompleted {
		nodeInfo.ActiveTasksCount++
		nodeInfo.ActiveTasksCountByService[t.ServiceID]++
	}

	return true
}

type roomKey struct {
	serviceID string
	slot      uint64
	port      uint32
	taskID    string
}

type room struct {
	memoryBytes int64
	nanoCPUs    int64
}

func roomOf(t *api.Task) roomKey {
	if port := lowestPublishedPort(t); port != 0 {
		return roomKey{serviceID: t.ServiceID, slot: t.Slot, port: port}
	}
	return roomKey{taskID: t.ID}
}

func lowestPublishedPort(t *api.Task) uint32 {
	if t.Endpoint == nil {
		return 0
	}
	ports := t.Endpoint.Ports
	if t.Endpoint.Spec != nil {
		ports = t.Endpoint.Spec.Ports
	}
	var lowest uint32
	for _, port := range ports {
		if port != nil && port.PublishedPort != 0 && (lowest == 0 || port.PublishedPort < lowest) {
			lowest = port.PublishedPort
		}
	}
	return lowest
}

func (nodeInfo *NodeInfo) recount(key roomKey) {
	var needed room
	for _, t := range nodeInfo.Tasks {
		if roomOf(t) == key {
			reservations := taskReservations(t.Spec)
			needed.memoryBytes = max(needed.memoryBytes, reservations.MemoryBytes)
			needed.nanoCPUs = max(needed.nanoCPUs, reservations.NanoCPUs)
		}
	}
	held := nodeInfo.heldRooms[key]
	nodeInfo.AvailableResources.MemoryBytes += held.memoryBytes - needed.memoryBytes
	nodeInfo.AvailableResources.NanoCPUs += held.nanoCPUs - needed.nanoCPUs
	if needed == (room{}) {
		delete(nodeInfo.heldRooms, key)
	} else {
		nodeInfo.heldRooms[key] = needed
	}
}

func (nodeInfo *NodeInfo) roomNeeded(t *api.Task) room {
	reservations := taskReservations(t.Spec)
	held := nodeInfo.heldRooms[roomOf(t)]
	return room{
		memoryBytes: max(held.memoryBytes, reservations.MemoryBytes) - held.memoryBytes,
		nanoCPUs:    max(held.nanoCPUs, reservations.NanoCPUs) - held.nanoCPUs,
	}
}

func taskReservations(spec api.TaskSpec) (reservations api.Resources) {
	if spec.Resources != nil && spec.Resources.Reservations != nil {
		reservations = *spec.Resources.Reservations
	}
	return
}

func (nodeInfo *NodeInfo) cleanupFailures(now time.Time) {
entriesLoop:
	for key, failuresEntry := range nodeInfo.recentFailures {
		for _, timestamp := range failuresEntry {
			if now.Sub(timestamp) < monitorFailures {
				continue entriesLoop
			}
		}
		delete(nodeInfo.recentFailures, key)
	}
	nodeInfo.lastCleanup = now
}

// taskFailed records a task failure from a given service.
func (nodeInfo *NodeInfo) taskFailed(ctx context.Context, t *api.Task) {
	expired := 0
	now := time.Now()

	if now.Sub(nodeInfo.lastCleanup) >= monitorFailures {
		nodeInfo.cleanupFailures(now)
	}

	versionedService := versionedService{serviceID: t.ServiceID}
	if t.SpecVersion != nil {
		versionedService.specVersion = *t.SpecVersion
	}

	for _, timestamp := range nodeInfo.recentFailures[versionedService] {
		if now.Sub(timestamp) < monitorFailures {
			break
		}
		expired++
	}

	if len(nodeInfo.recentFailures[versionedService])-expired == maxFailures-1 {
		log.G(ctx).Warnf("underweighting node %s for service %s because it experienced %d failures or rejections within %s", nodeInfo.ID, t.ServiceID, maxFailures, monitorFailures.String())
	}

	nodeInfo.recentFailures[versionedService] = append(nodeInfo.recentFailures[versionedService][expired:], now)
}

// countRecentFailures returns the number of times the service has failed on
// this node within the lookback window monitorFailures.
func (nodeInfo *NodeInfo) countRecentFailures(now time.Time, t *api.Task) int {
	versionedService := versionedService{serviceID: t.ServiceID}
	if t.SpecVersion != nil {
		versionedService.specVersion = *t.SpecVersion
	}

	recentFailureCount := len(nodeInfo.recentFailures[versionedService])
	for i := recentFailureCount - 1; i >= 0; i-- {
		if now.Sub(nodeInfo.recentFailures[versionedService][i]) > monitorFailures {
			recentFailureCount -= i + 1
			break
		}
	}

	return recentFailureCount
}
