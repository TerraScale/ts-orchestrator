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

// SLOTarget is a Prometheus file-discovery group for one serving process.
type SLOTarget struct {
	Targets []string          `json:"targets"`
	Labels  map[string]string `json:"labels"`
}

type sloContainer struct {
	labels map[string]string
	pid    uint32
}

// SLOTargets discovers native exporters, never the switching service proxy.
// Auth has a dedicated listener; dashboard uses its application listener.
// TerraBase retains its dedicated metrics listener on 9091.
func (e *Executor) SLOTargets(ctx context.Context, services []*api.Service, region string) ([]SLOTarget, error) {
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
	return sloTargets(ctx, services, containersRunning, region)
}

func sloTargets(ctx context.Context, services []*api.Service, containers []sloContainer, region string) ([]SLOTarget, error) {
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
	// Never publish a partial inventory after the refresh budget expires.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return targets, nil
}
