package swarmruntime

import (
	"context"
	"maps"
	"net"
	"slices"
	"strconv"
	"sync"
	"time"

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

type sloCache struct {
	sync.Mutex
	at         time.Time
	containers []sloContainer
	err        error
	targetsAt  time.Time
	targets    []SLOTarget
	targetsErr error
	region     string
}

func (e *Executor) SLOTargets(ctx context.Context, region string) ([]SLOTarget, error) {
	e.slo.Lock()
	defer e.slo.Unlock()
	containers, err := e.cachedSLOContainers(ctx)
	if err != nil {
		return nil, err
	}
	if e.slo.targetsAt != e.slo.at || e.slo.region != region {
		e.slo.targets, e.slo.targetsErr = sloTargets(ctx, containers, region)
		e.slo.targetsAt, e.slo.region = e.slo.at, region
	}
	targets := make([]SLOTarget, len(e.slo.targets))
	for i, target := range e.slo.targets {
		targets[i] = SLOTarget{Targets: slices.Clone(target.Targets), Labels: maps.Clone(target.Labels)}
	}
	return targets, e.slo.targetsErr
}

func (e *Executor) SLOTaskCounts(ctx context.Context) (map[string]int, error) {
	e.slo.Lock()
	defer e.slo.Unlock()
	containers, err := e.cachedSLOContainers(ctx)
	if err != nil {
		return nil, err
	}
	counts := map[string]int{"terrabase": 0, "ts-auth": 0, "ts-dashboard": 0}
	for _, container := range containers {
		counts[container.name]++
	}
	return counts, nil
}

func (e *Executor) cachedSLOContainers(ctx context.Context) ([]sloContainer, error) {
	if time.Since(e.slo.at) >= 5*time.Second {
		e.slo.at = time.Now()
		e.slo.containers, e.slo.err = e.runningSLOContainers(ctx)
	}
	return e.slo.containers, e.slo.err
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
		name := info.Labels[LabelServiceSpec]
		if !slices.Contains([]string{"terrabase", "ts-auth", "ts-dashboard"}, name) ||
			info.Labels["terrascale.service"] == "" || info.Labels["terrascale.task"] == "" ||
			container.ID() != "ts-"+info.Labels["terrascale.task"] || !DeploymentImageBelongsToService(name, info.Image) {
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
