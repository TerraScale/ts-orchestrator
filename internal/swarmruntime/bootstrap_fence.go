package swarmruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/handoff"
	"github.com/TerraScale/ts-orchestrator/internal/rolloutmaintenance"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/errdefs"
	"github.com/moby/swarmkit/v2/agent/exec"
	"github.com/moby/swarmkit/v2/api"
)

func (c *controller) bootstrapPin() rolloutmaintenance.Pin {
	return rolloutmaintenance.Pin{Node: c.task.NodeID, Service: c.task.ServiceID, Task: c.task.ID, Fingerprint: c.fingerprint, Image: c.spec.Image}
}
func (c *controller) bootstrapOperation(ctx context.Context, action string) (context.Context, func(), error) {
	if c.executor.bootstrap == nil {
		return ctx, func() {}, nil
	}
	next, done, err := c.executor.bootstrap.Enter(ctx, c.bootstrapPin(), c.regionalTerraBase(), action)
	if err != nil {
		return ctx, done, exec.MakeTemporary(err)
	}
	return next, done, nil
}

// BootstrapRuntime operates only on controllers received from the authenticated
// Swarm dispatcher. A caller cannot introduce a task or replace its spec here.
type BootstrapRuntime struct{ executor *Executor }

func (r BootstrapRuntime) Staged(ctx context.Context, j rolloutmaintenance.Job) error {
	return handoff.Bootstrap(ctx, "staged", j)
}

func (e *Executor) BootstrapDriver() rolloutmaintenance.Driver {
	return rolloutmaintenance.Driver{Store: e.bootstrap, Runtime: BootstrapRuntime{executor: e}}
}
func (r BootstrapRuntime) find(pin rolloutmaintenance.Pin) (*controller, error) {
	r.executor.mu.Lock()
	defer r.executor.mu.Unlock()
	c := r.executor.bootstrapTasks[pin.Task]
	if c == nil || c.bootstrapPin() != pin || c.task.NodeID != r.executor.functionNodeID {
		return nil, rolloutmaintenance.ErrFenced
	}
	return c, nil
}
func (r BootstrapRuntime) Resolve(ctx context.Context, j rolloutmaintenance.Job) (rolloutmaintenance.Pin, error) {
	r.executor.mu.Lock()
	defer r.executor.mu.Unlock()
	var result rolloutmaintenance.Pin
	for _, c := range r.executor.bootstrapTasks {
		pin := c.bootstrapPin()
		if pin.Node == j.Source.Node && pin.Service == j.Source.Service && pin.Image == j.Target.Image && pin.Task != j.Source.Task && c.task.DesiredState == api.TaskStateRunning {
			if result.Task != "" && result != pin {
				return result, errors.New("multiple admitted bootstrap replacements")
			}
			result = pin
		}
	}
	if result.Task == "" {
		return result, errors.New("pinned candidate has no admitted local task")
	}
	return result, ctx.Err()
}
func (r BootstrapRuntime) Prepare(ctx context.Context, p rolloutmaintenance.Pin) error {
	c, err := r.find(p)
	if err != nil {
		return err
	}
	err = c.Prepare(ctx)
	if errors.Is(err, exec.ErrTaskPrepared) {
		return nil
	}
	return err
}
func (r BootstrapRuntime) Quiesce(ctx context.Context, j rolloutmaintenance.Job) (func(context.Context) error, error) {
	if err := handoff.Bootstrap(ctx, "hold", j); err != nil {
		return nil, err
	}
	return func(ctx context.Context) error { return handoff.Bootstrap(ctx, "release", j) }, nil
}
func (r BootstrapRuntime) Stop(ctx context.Context, p rolloutmaintenance.Pin) error {
	c, err := r.find(p)
	if err != nil {
		j, e := r.executor.bootstrap.Status(ctx)
		if e == nil && j != nil && j.Source == p {
			return r.Exited(ctx, p, j.Process)
		}
		return err
	}
	return c.stopTask(ctx)
}
func (r BootstrapRuntime) Start(ctx context.Context, p rolloutmaintenance.Pin) error {
	c, err := r.find(p)
	if err != nil {
		return err
	}
	err = c.Start(ctx)
	if errors.Is(err, exec.ErrTaskStarted) {
		return nil
	}
	return err
}
func (r BootstrapRuntime) Exited(ctx context.Context, p rolloutmaintenance.Pin, process rolloutmaintenance.Process) error {
	current, err := processIdentity(process.PID)
	if err == nil && current == process {
		return errors.New("retained source process is still alive")
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	ctr, err := r.executor.client.LoadContainer(runtimeContext(ctx), "ts-"+p.Task)
	if errdefs.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	labels, err := ctr.Labels(runtimeContext(ctx))
	if err != nil {
		return err
	}
	if labels["terrascale.task"] != p.Task || labels["terrascale.service"] != p.Service || labels["terrascale.spec"] != p.Fingerprint {
		return rolloutmaintenance.ErrFenced
	}
	task, err := ctr.Task(runtimeContext(ctx), nil)
	if errdefs.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	status, err := task.Status(runtimeContext(ctx))
	if err != nil {
		return err
	}
	if status.Status != containerd.Stopped {
		return errors.New("retained source runtime has not exited")
	}
	return nil
}

// sourceCompleted reports an already proved exit to Swarm's STOP_FIRST updater;
// it cannot signal a process, run legacy handoff, or act on an unselected task.
func (c *controller) bootstrapSourceCompleted(ctx context.Context) (bool, error) {
	if c.executor.bootstrap == nil {
		return false, nil
	}
	j, err := c.executor.bootstrap.Status(ctx)
	if err != nil {
		return false, err
	}
	if j == nil || j.Source != c.bootstrapPin() {
		return false, nil
	}
	switch j.Phase {
	case "exited", "preparing", "starting", "verified":
		err = (BootstrapRuntime{executor: c.executor}).Exited(ctx, j.Source, j.Process)
		return err == nil, err
	default:
		return false, nil
	}
}

func (r BootstrapRuntime) Verify(ctx context.Context, j rolloutmaintenance.Job) error {
	c, err := r.find(j.Target)
	if err != nil {
		return err
	}
	t, err := c.runtimeTask(ctx)
	if err != nil {
		return err
	}
	status, err := t.Status(runtimeContext(ctx))
	if err != nil {
		return err
	}
	if status.Status != containerd.Running {
		return errors.New("pinned replacement is not running")
	}
	return handoff.Bootstrap(ctx, "verify", j)
}

func processIdentity(pid uint32) (rolloutmaintenance.Process, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10), "stat"))
	if err != nil {
		return rolloutmaintenance.Process{}, err
	}
	// comm may contain spaces and parentheses; fields after its final ')' start
	// with state (field 3). starttime is field 22, index 19 in this suffix.
	end := strings.LastIndex(string(data), ") ")
	if end < 0 {
		return rolloutmaintenance.Process{}, errors.New("invalid process identity")
	}
	fields := strings.Fields(string(data)[end+2:])
	if len(fields) < 20 {
		return rolloutmaintenance.Process{}, errors.New("invalid process identity")
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return rolloutmaintenance.Process{}, fmt.Errorf("read process identity: %w", err)
	}
	return rolloutmaintenance.Process{PID: pid, Start: start}, nil
}

// A manually driven candidate still reports its existing runtime through the
// normal dispatcher. These acknowledgments never recreate/start a process.
func (c *controller) bootstrapTargetRunning(ctx context.Context) (bool, error) {
	if c.executor.bootstrap == nil {
		return false, nil
	}
	j, err := c.executor.bootstrap.Status(ctx)
	if err != nil {
		return false, err
	}
	if j == nil || j.Phase != "verified" || j.Target != c.bootstrapPin() {
		return false, nil
	}
	task, err := c.runtimeTask(ctx)
	if err != nil {
		return false, err
	}
	status, err := task.Status(runtimeContext(ctx))
	if err != nil {
		return false, err
	}
	if status.Status != containerd.Running {
		return false, rolloutmaintenance.ErrFenced
	}
	return true, nil
}
