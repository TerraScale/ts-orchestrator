package swarmruntime

import (
	"context"
	"errors"
	"log/slog"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/errdefs"
)

// SwarmKit keeps a terminal task's container until the task leaves its
// history (5 per slot), and containerd keeps an exited process's shim and
// its ts-orch --runtime-logger alive until the runtime task is deleted: on
// gru 2026-10-27 that was 18 shims and loggers (1.1 GiB) for 5 running
// tasks. An exited runtime task never starts again (start refuses it), so
// the reaper deletes it once the controller has read its exit; the container
// and its logs stay for history and Remove.
const (
	// reapExitedAfter leaves Wait time to read the exit status and OOM events.
	reapExitedAfter = time.Minute
	reapInterval    = time.Minute
	// exitedLabel marks a container whose runtime task the reaper deleted, so
	// port and disk accounting do not count it as prepared.
	exitedLabel = "terrascale.exited"
)

// ReapExitedTasks deletes exited runtime tasks every reapInterval until ctx
// ends. The first pass waits one interval: after a restart, Wait re-attaches
// and reads an exit that happened while ts-orch was down.
func (e *Executor) ReapExitedTasks(ctx context.Context) {
	tick := time.NewTicker(reapInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if reaped, err := e.reapExited(ctx, time.Now()); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "exited runtime tasks not reaped", "reaped", reaped, "error", err)
		} else if reaped != 0 {
			slog.InfoContext(ctx, "reaped exited runtime tasks", "reaped", reaped)
		}
	}
}

func (e *Executor) reapExited(ctx context.Context, now time.Time) (int, error) {
	ctx = runtimeContext(ctx)
	containers, err := e.client.Containers(ctx)
	if err != nil {
		return 0, err
	}
	var reaped int
	var errs []error
	for _, container := range containers {
		done, err := e.reapContainer(ctx, container, now)
		if done {
			reaped++
		}
		errs = append(errs, err)
	}
	return reaped, errors.Join(errs...)
}

func (e *Executor) reapContainer(ctx context.Context, container containerd.Container, now time.Time) (bool, error) {
	labels, err := container.Labels(ctx)
	if err != nil {
		return false, ignoreNotFound(err)
	}
	// Stateful tasks fence their runtime through their own hooks.
	if labels["terrascale.task"] == "" || labels["terrascale.task-binding"] != "" {
		return false, nil
	}
	task, err := container.Task(ctx, nil)
	if err != nil {
		return false, ignoreNotFound(err)
	}
	status, err := task.Status(ctx)
	if err != nil {
		return false, ignoreNotFound(err)
	}
	if status.Status != containerd.Stopped || status.ExitTime.IsZero() || now.Sub(status.ExitTime) < reapExitedAfter {
		return false, nil
	}
	// Serialise with Prepare/Start/Remove, which read the same runtime state.
	e.mu.Lock()
	defer e.mu.Unlock()
	// Label first: a reaped container without its task would otherwise read
	// as prepared and hold its ports and disk budget.
	if _, err := container.SetLabels(ctx, map[string]string{exitedLabel: status.ExitTime.UTC().Format(time.RFC3339), portsLabel: releasedPorts}); err != nil {
		return false, ignoreNotFound(err)
	}
	if _, err := task.Delete(ctx); err != nil {
		return false, ignoreNotFound(err)
	}
	return true, nil
}

func ignoreNotFound(err error) error {
	if errdefs.IsNotFound(err) {
		return nil
	}
	return err
}
