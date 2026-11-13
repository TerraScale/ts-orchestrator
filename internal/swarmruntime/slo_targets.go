package swarmruntime

import (
	"context"
	"net"
	"slices"
	"strconv"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/errdefs"
)

type SLOTarget struct {
	Targets []string          `json:"targets"`
	Labels  map[string]string `json:"labels"`
}

type sloContainer struct {
	labels map[string]string
	pid    uint32
	name   string
}

func (e *Executor) SLOTargets(ctx context.Context, region string) ([]SLOTarget, error) {
	containers, err := e.runningSLOContainers(ctx)
	if err != nil {
		return nil, err
	}
	return sloTargets(ctx, containers, region)
}

func (e *Executor) SLOTaskCounts(ctx context.Context) (map[string]int, error) {
	containers, err := e.runningSLOContainers(ctx)
	if err != nil {
		return nil, err
	}
	counts := map[string]int{"terrabase": 0, "ts-auth": 0, "ts-dashboard": 0}
	for _, container := range containers {
		counts[container.name]++
	}
	return counts, nil
}

func (e *Executor) runningSLOContainers(ctx context.Context) ([]sloContainer, error) {
	ctx = runtimeContext(ctx)
	containers, err := e.client.Containers(ctx)
	if err != nil {
		return nil, err
	}
	var containersRunning []sloContainer
	for _, container := range containers {
		info, err := container.Info(ctx)
		if errdefs.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		name := ""
		for _, service := range []string{"terrabase", "ts-auth", "ts-dashboard"} {
			if DeploymentImageBelongsToService(service, info.Image) {
				name = service
				break
			}
		}
		if name == "" || info.Labels["terrascale.task"] == "" {
			continue
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
			containersRunning = append(containersRunning, sloContainer{info.Labels, task.Pid(), name})
		}
	}
	return containersRunning, ctx.Err()
}

func sloTargets(ctx context.Context, containers []sloContainer, region string) ([]SLOTarget, error) {
	targets := make([]SLOTarget, 0)
	for _, container := range containers {
		labels := container.labels
		name, task := container.name, labels["terrascale.task"]
		port, err := strconv.ParseUint(labels[portsLabel], 10, 16)
		if name == "terrabase" {
			port, err = 9091, nil
		}
		if name == "" || task == "" {
			continue
		}
		address := ""
		if err == nil && port > 0 {
			address = net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
		}
		if name == "ts-auth" {
			address = discoverSLOListener(ctx, container.pid, uint16(port))
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
