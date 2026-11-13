package swarmruntime

import (
	"context"
	"net"
	"slices"
	"strconv"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/errdefs"
	"github.com/moby/swarmkit/v2/api"
)

type sloFileContainer struct {
	labels map[string]string
	pid    uint32
}

func (e *Executor) FileSLOTargets(ctx context.Context, services []*api.Service, region string) ([]SLOTarget, error) {
	ctx = runtimeContext(ctx)
	containers, err := e.client.Containers(ctx)
	if err != nil {
		return nil, err
	}
	var containersRunning []sloFileContainer
	for _, container := range containers {
		metadata, err := container.Labels(ctx)
		if errdefs.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		task, err := container.Task(ctx, nil)
		if errdefs.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		status, err := task.Status(ctx)
		if errdefs.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if status.Status == containerd.Running {
			containersRunning = append(containersRunning, sloFileContainer{metadata, task.Pid()})
		}
	}
	return fileSLOTargets(ctx, services, containersRunning, region)
}

func fileSLOTargets(ctx context.Context, services []*api.Service, containers []sloFileContainer, region string) ([]SLOTarget, error) {
	names := map[string]string{}
	for _, service := range services {
		if service == nil || service.PendingDelete {
			continue
		}
		name := service.Spec.Annotations.Name
		if name == "ts-auth" || name == "ts-dashboard" {
			names[service.ID] = name
		}
	}
	targets := make([]SLOTarget, 0)
	for _, container := range containers {
		labels := container.labels
		name, task := names[labels["terrascale.service"]], labels["terrascale.task"]
		port, err := strconv.ParseUint(labels[portsLabel], 10, 16)
		if name == "" || task == "" || err != nil || port == 0 {
			continue
		}
		address := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
		if name == "ts-auth" {
			address = discoverSLOListener(ctx, container.pid, uint16(port))
			if address == "" {
				continue
			}
		}
		targets = append(targets, SLOTarget{
			Targets: []string{address},
			Labels:  map[string]string{"service": name, "region": region, "instance": task},
		})
	}
	slices.SortFunc(targets, func(a, b SLOTarget) int {
		return slices.Compare(a.Targets, b.Targets)
	})
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return targets, nil
}
