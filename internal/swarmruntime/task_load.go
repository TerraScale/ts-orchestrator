package swarmruntime

import (
	"context"
	"errors"
	"maps"
	"math"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/hostload"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
	containerd "github.com/containerd/containerd/v2/client"
)

// The caller holds e.mu; only the configured upstream node owns these tasks.
func (e *Executor) trackLoadTask(task *controller) {
	if e.functionNodeID == "" || task.task.NodeID != e.functionNodeID {
		return
	}
	if e.loadTasks == nil {
		e.loadTasks = make(map[string]*controller)
	}
	e.loadTasks[task.task.ID] = task
}

// ReadTaskLoad observes only this executor's current upstream task controllers.
// Measurements never replace admission; the controller independently binds
// every reported role to its current registration and manager allocation.
func (e *Executor) ReadTaskLoad(ctx context.Context) ([]hostload.RoleUsage, error) {
	e.loadMu.Lock()
	defer e.loadMu.Unlock()
	e.mu.Lock()
	tasks := maps.Clone(e.loadTasks)
	nodeID := e.functionNodeID
	e.mu.Unlock()
	if nodeID == "" {
		return nil, errors.New("task load awaits the authenticated local node")
	}
	if e.loadSampler == nil {
		e.loadSampler = hostload.NewSampler(hostload.SamplerConfig{CgroupRoot: "/sys/fs/cgroup/terrascale"})
	}
	roles := make(map[string][]*controller)
	groups := make([]string, 0, len(tasks))
	pids := make(map[string]uint32, len(tasks))
	for _, task := range tasks {
		role := task.task.ServiceAnnotations.Labels[LabelRole]
		if task.task.NodeID != nodeID || role == terrabase.Role ||
			(hostload.Report{SchemaVersion: hostload.SchemaVersion, Roles: []hostload.RoleUsage{{Role: role}}}).Validate() != nil {
			continue
		}
		roles[role] = append(roles[role], task)
		if pid, err := task.loadPID(ctx); err == nil {
			groups = append(groups, task.id)
			pids[task.id] = pid
		}
	}
	measured := make(map[string]hostload.RoleUsage, len(groups))
	for _, usage := range e.loadSampler.SampleCgroups(groups) {
		measured[usage.Role] = usage
	}
	result := make([]hostload.RoleUsage, 0, len(roles))
	for _, role := range slices.Sorted(maps.Keys(roles)) {
		usage := hostload.RoleUsage{Role: role, CPUCores: new(0.0), MemoryBytes: new(uint64(0)),
			CPULimit: new(0.0), MemoryLimit: new(uint64(0)), LimitsRead: true}
		slices.SortFunc(roles[role], func(a, b *controller) int { return strings.Compare(a.task.ID, b.task.ID) })
		for _, task := range roles[role] {
			usage.Tasks = append(usage.Tasks, hostload.TaskPin{TaskID: task.task.ID, ServiceID: task.task.ServiceID,
				NodeID: nodeID, Fingerprint: task.fingerprint})
			part, found := measured[task.id]
			pid, err := task.loadPID(ctx)
			e.mu.Lock()
			current := e.loadTasks[task.task.ID] == task && e.functionNodeID == nodeID
			e.mu.Unlock()
			if !found || err != nil || pid != pids[task.id] || !current {
				part = hostload.RoleUsage{}
			}
			addTaskLoad(&usage, part)
		}
		result = append(result, usage)
	}
	e.mu.Lock()
	unchanged := nodeID == e.functionNodeID && maps.Equal(tasks, e.loadTasks)
	e.mu.Unlock()
	if !unchanged {
		return nil, errors.New("local task assignments changed during load sampling")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := (hostload.Report{SchemaVersion: hostload.SchemaVersion, Roles: result}).Validate(); err != nil {
		return nil, err
	}
	return result, nil
}

func (c *controller) loadPID(ctx context.Context) (uint32, error) {
	task, err := c.runtimeTask(ctx)
	if err != nil {
		return 0, err
	}
	status, err := task.Status(runtimeContext(ctx))
	if err != nil {
		return 0, err
	}
	pid := task.Pid()
	if status.Status != containerd.Running || pid == 0 {
		return 0, errors.New("task load requires its current running process")
	}
	if err := verifyRuntimeGuardCgroup(pid, c.id); err != nil {
		return 0, err
	}
	return pid, nil
}

// A partial role sum would understate usage; retain unknown per missing field.
func addTaskLoad(total *hostload.RoleUsage, part hostload.RoleUsage) {
	if total.CPUCores != nil && part.CPUCores != nil {
		*total.CPUCores += *part.CPUCores
		if math.IsNaN(*total.CPUCores) || math.IsInf(*total.CPUCores, 0) || *total.CPUCores > hostload.MaxCPUCores {
			total.CPUCores = nil
		}
	} else {
		total.CPUCores = nil
	}
	if total.MemoryBytes != nil && part.MemoryBytes != nil {
		if *part.MemoryBytes <= hostload.MaxMemoryBytes-*total.MemoryBytes {
			*total.MemoryBytes += *part.MemoryBytes
		} else {
			total.MemoryBytes = nil
		}
	} else {
		total.MemoryBytes = nil
	}
	if total.CPULimit != nil && part.CPULimit != nil {
		*total.CPULimit += *part.CPULimit
		if math.IsNaN(*total.CPULimit) || math.IsInf(*total.CPULimit, 0) || *total.CPULimit > hostload.MaxCPUCores {
			total.CPULimit = nil
		}
	} else {
		total.CPULimit = nil
	}
	if total.MemoryLimit != nil && part.MemoryLimit != nil {
		if *part.MemoryLimit <= hostload.MaxMemoryBytes-*total.MemoryLimit {
			*total.MemoryLimit += *part.MemoryLimit
		} else {
			total.MemoryLimit = nil
		}
	} else {
		total.MemoryLimit = nil
	}
	total.LimitsRead = total.LimitsRead && part.LimitsRead
}
