package swarmruntime

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"net"
	"slices"
	"strconv"
	"sync"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/errdefs"
	"github.com/moby/swarmkit/v2/agent"
	"github.com/moby/swarmkit/v2/api"
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
	at          time.Time
	containers  []sloContainer
	err         error
	targetsAt   time.Time
	targets     []SLOTarget
	targetsErr  error
	region      string
	assignments func() ([]*api.Task, error)
	rejected    map[string]int
	logged      map[string]bool
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

type SLOInventory struct {
	Expected   map[string]int
	Running    map[string]int
	Discovered map[string]int
	Rejected   map[string]int
}

func (e *Executor) SLOTaskInventory(ctx context.Context, region string) (SLOInventory, error) {
	e.slo.Lock()
	defer e.slo.Unlock()
	inventory := SLOInventory{Expected: map[string]int{}, Running: map[string]int{}, Discovered: map[string]int{}}
	if e.slo.assignments == nil {
		return inventory, errors.New("node assignments unavailable")
	}
	assignments, err := e.slo.assignments()
	if err != nil {
		return inventory, err
	}
	for _, task := range assignments {
		name := task.ServiceAnnotations.Labels[LabelServiceSpec]
		if task.DesiredState == api.TaskStateRunning && slices.Contains([]string{"terrabase", "ts-auth", "ts-dashboard"}, name) {
			inventory.Expected[name]++
		}
	}
	containers, err := e.cachedSLOContainers(ctx)
	if err != nil {
		return inventory, err
	}
	for _, container := range containers {
		inventory.Running[container.name]++
	}
	targets, err := sloTargets(ctx, containers, region)
	if err != nil {
		return inventory, err
	}
	for _, target := range targets {
		inventory.Discovered[target.Labels["service"]]++
	}
	inventory.Rejected = maps.Clone(e.slo.rejected)
	return inventory, nil
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
	bindings := map[string]*api.Task{}
	if e.slo.assignments != nil {
		tasks, err := e.slo.assignments()
		if err != nil {
			return nil, err
		}
		for _, task := range tasks {
			if slices.Contains([]string{"terrabase", "ts-auth", "ts-dashboard"}, task.ServiceAnnotations.Labels[LabelServiceSpec]) {
				bindings["ts-"+task.ID] = task
			}
		}
	}
	var containersRunning []sloContainer
	e.slo.rejected = map[string]int{"task_identity": 0, "service_identity": 0, "image_identity": 0}
	if e.slo.logged == nil {
		e.slo.logged = map[string]bool{}
	}
	present := map[string]bool{}

	for _, container := range containers {
		info, err := container.Info(ctx)
		if errdefs.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		name := info.Labels[LabelServiceSpec]
		binding := bindings[container.ID()]
		if binding == nil && !slices.Contains([]string{"terrabase", "ts-auth", "ts-dashboard"}, name) {
			continue
		}
		present[container.ID()] = true
		reason := ""
		switch {
		case info.Labels["terrascale.task"] == "" || container.ID() != "ts-"+info.Labels["terrascale.task"]:
			reason = "task_identity"
		case info.Labels["terrascale.service"] == "" || (binding != nil && (name != binding.ServiceAnnotations.Labels[LabelServiceSpec] || info.Labels["terrascale.service"] != binding.ServiceID)):
			reason = "service_identity"
		case !DeploymentImageBelongsToService(name, info.Image):
			reason = "image_identity"
		}
		if reason != "" {
			e.slo.rejected[reason]++
			if !e.slo.logged[container.ID()] {
				slog.WarnContext(ctx, "Task monitoring identity rejected", "task", container.ID(), "reason", reason)
				e.slo.logged[container.ID()] = true
			}
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
	for task := range e.slo.logged {
		if !present[task] {
			delete(e.slo.logged, task)
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

func (e *Executor) BindSLOAgent(source func() *agent.Agent) {
	e.slo.Lock()
	defer e.slo.Unlock()
	e.slo.assignments = func() ([]*api.Task, error) {
		current := source()
		if current == nil {
			return nil, errors.New("node assignments unavailable")
		}
		return current.AssignedTasks()
	}
}
