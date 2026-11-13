package swarmruntime

import (
	"context"
	"maps"
	"net"
	"slices"
	"strconv"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/errdefs"
	"github.com/moby/swarmkit/v2/api"
)

type SLOTarget struct {
	Targets []string          `json:"targets"`
	Labels  map[string]string `json:"labels"`
}

type sloContainer struct {
	labels map[string]string
	pid    uint32
}

func (e *Executor) SLOTargets(ctx context.Context, region string) ([]SLOTarget, error) {
	e.mu.Lock()
	names := maps.Clone(e.sloTasks)
	e.mu.Unlock()
	ctx = runtimeContext(ctx)
	containers, err := e.client.Containers(ctx)
	if err != nil {
		return nil, err
	}
	var containersRunning []sloContainer
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
			containersRunning = append(containersRunning, sloContainer{metadata, task.Pid()})
		}
	}
	return sloTargets(ctx, names, containersRunning, region)
}

func sloTargets(ctx context.Context, names map[string]string, containers []sloContainer, region string) ([]SLOTarget, error) {
	targets := make([]SLOTarget, 0)
	for _, container := range containers {
		labels := container.labels
		name, task := names[labels["terrascale.task"]], labels["terrascale.task"]
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

func (e *Executor) trackSLOTask(task *api.Task) {
	name := task.ServiceAnnotations.Name
	if name != "terrabase" && name != "ts-auth" && name != "ts-dashboard" {
		return
	}
	if e.sloTasks == nil {
		e.sloTasks = map[string]string{}
	}
	e.sloTasks[task.ID] = name
}
