package swarmruntime

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/flock"
)

const portsLabel = "terrascale.ports"

// SwarmKit's inert network allocator leaves generic task ports unallocated;
// container metadata reserves them locally until the container is removed.
func (c *controller) reservePorts(ctx context.Context) (string, func(), error) {
	var requested []string
	if c.task.Endpoint != nil {
		ports := c.task.Endpoint.Ports
		if c.task.Endpoint.Spec != nil {
			ports = c.task.Endpoint.Spec.Ports
		}
		for _, port := range ports {
			requested = append(requested, strconv.FormatUint(uint64(port.PublishedPort), 10))
		}
	}
	slices.Sort(requested)
	encoded := strings.Join(requested, ",")
	if len(requested) == 0 {
		return encoded, func() {}, nil
	}
	lock := flock.New(c.executor.socket + ".ports.lock")
	locked, err := lock.TryLockContext(ctx, 25*time.Millisecond)
	if err != nil {
		return "", nil, err
	}
	if !locked {
		return "", nil, fmt.Errorf("runtime port reservation interrupted")
	}
	unlock := func() { _ = lock.Unlock() }
	containers, err := c.executor.client.Containers(runtimeContext(ctx))
	if err != nil {
		unlock()
		return "", nil, err
	}
	for _, container := range containers {
		if container.ID() == c.id {
			continue
		}
		labels, err := container.Labels(runtimeContext(ctx))
		if err != nil {
			unlock()
			return "", nil, err
		}
		claimed, known := labels[portsLabel]
		if !known {
			unlock()
			return "", nil, fmt.Errorf("container %s has unknown host-port ownership", container.ID())
		}
		for port := range strings.SplitSeq(claimed, ",") {
			if slices.Contains(requested, port) {
				unlock()
				return "", nil, fmt.Errorf("host port %s is reserved by container %s", port, container.ID())
			}
		}
	}
	return encoded, unlock, nil
}
