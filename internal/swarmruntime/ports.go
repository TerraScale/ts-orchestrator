package swarmruntime

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/containerd/containerd/v2/client"
	"github.com/containerd/errdefs"
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
		// A failed task's container lingers until SwarmKit reaps the task; with
		// its process gone it holds no port and must not block the replacement.
		if held, err := holdsPorts(ctx, container); err != nil {
			unlock()
			return "", nil, err
		} else if !held {
			continue
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

// holdsPorts reports whether container may still bind its host ports: it has
// no task yet (prepared, not started) or its task has not stopped. A task that
// failed to create released its claim in Start (releasePorts).
func holdsPorts(ctx context.Context, container client.Container) (bool, error) {
	task, err := container.Task(runtimeContext(ctx), nil)
	if errdefs.IsNotFound(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	status, err := task.Status(runtimeContext(ctx))
	if err != nil {
		return false, err
	}
	return status.Status != client.Stopped, nil
}

// releasePorts drops a container's host-port claim after its task failed to
// start, so the replacement task is not blocked until SwarmKit reaps this one.
func releasePorts(ctx context.Context, container client.Container) error {
	_, err := container.SetLabels(runtimeContext(ctx), map[string]string{portsLabel: ""})
	return err
}
