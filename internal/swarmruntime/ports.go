package swarmruntime

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/errdefs"
	"github.com/gofrs/flock"
	"github.com/moby/swarmkit/v2/agent/exec"
)

const portsLabel = "terrascale.ports"

// SwarmKit's inert network allocator leaves generic task ports unallocated;
// container metadata reserves them locally. An exited container releases its
// ports at once: its task never runs again, and SwarmKit retains stopped
// tasks (and their containers) long after a replacement needs the port.
//
// Prepare (starting=false) refuses a port held by another service's live or
// prepared container; a replacement task of the same service may prepare
// while its predecessor still serves. Start (starting=true) refuses any live
// holder, so one port never has two running owners.
func (c *controller) reservePorts(ctx context.Context, starting bool) (string, func(), error) {
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
	if err := c.checkPortHolders(runtimeContext(ctx), requested, starting); err != nil {
		unlock()
		return "", nil, err
	}
	return encoded, unlock, nil
}

func (c *controller) checkPortHolders(ctx context.Context, requested []string, starting bool) error {
	containers, err := c.executor.client.Containers(ctx)
	if err != nil {
		return err
	}
	for _, container := range containers {
		if container.ID() == c.id {
			continue
		}
		labels, err := container.Labels(ctx)
		if err != nil {
			return err
		}
		claimed, known := labels[portsLabel]
		if !known {
			return fmt.Errorf("container %s has unknown host-port ownership", container.ID())
		}
		if !slices.ContainsFunc(strings.Split(claimed, ","), func(port string) bool { return slices.Contains(requested, port) }) {
			continue
		}
		holder, err := portHolderState(ctx, container)
		if err != nil {
			return err
		}
		sameService := labels["terrascale.service"] == c.task.ServiceID
		if portConflict(holder, sameService, starting) {
			err := fmt.Errorf("host port %s is reserved by container %s", claimed, container.ID())
			if starting && sameService {
				// The predecessor is still stopping (up to dataStopGrace); the agent retries each second.
				return exec.MakeTemporary(err)
			}
			return err
		}
	}
	return nil
}

// releasedPorts is the claim of a container that holds no host port (created
// without ports, or a failed task's). Never "": containerd deletes such a label.
const releasedPorts = "released"

type portHolder int

const (
	holderPrepared portHolder = iota // container without a runtime task
	holderLive                       // runtime task created, running or paused
	holderExited
)

func portHolderState(ctx context.Context, container containerd.Container) (portHolder, error) {
	task, err := container.Task(ctx, nil)
	if errdefs.IsNotFound(err) {
		return holderPrepared, nil
	}
	if err != nil {
		return 0, err
	}
	status, err := task.Status(ctx)
	if errdefs.IsNotFound(err) {
		return holderPrepared, nil
	}
	if err != nil {
		return 0, err
	}
	if status.Status == containerd.Stopped {
		return holderExited, nil
	}
	return holderLive, nil
}

func portConflict(holder portHolder, sameService, starting bool) bool {
	switch {
	case holder == holderExited:
		return false
	case starting:
		return holder == holderLive
	default:
		return !sameService
	}
}

// releaseFailedPorts drops the host-port claim of a task that failed to
// prepare or start: its container lingers until SwarmKit reaps the task and
// would otherwise block every replacement.
func (c *controller) releaseFailedPorts(ctx context.Context, err error) {
	// Stateful tasks fence their runtime separately; never touch their claim.
	if err == nil || c.stateful != nil || errors.Is(err, exec.ErrTaskStarted) || errors.Is(err, exec.ErrTaskPrepared) || exec.IsTemporary(err) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return
	}
	ctx = runtimeContext(context.WithoutCancel(ctx))
	if container, loadErr := c.executor.client.LoadContainer(ctx, c.id); loadErr == nil {
		// containerd deletes a label set to "", which would read as unknown ownership.
		_, _ = container.SetLabels(ctx, map[string]string{portsLabel: releasedPorts})
	}
}
