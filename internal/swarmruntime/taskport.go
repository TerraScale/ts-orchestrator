package swarmruntime

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/handoff"
	"github.com/gofrs/flock"
)

// TaskPortEnv in a spec's env value stands for the task's own port. Such a task
// listens there, the executor serves the service port from the newest ready
// task (internal/handoff), and an update starts the new task first: the old one
// serves until the new one is ready.
const TaskPortEnv = "${PORT}"

// LabelPort is the service port of a spec using TaskPortEnv, which publishes no
// host port: two tasks of one service share a host during an update.
const LabelPort = "terrascale.port"

func usesTaskPort(env []string) bool {
	return slices.ContainsFunc(env, func(kv string) bool { return strings.Contains(kv, TaskPortEnv) })
}

func withTaskPort(env []string, port uint16) []string {
	out := make([]string, len(env))
	for i, kv := range env {
		out[i] = strings.ReplaceAll(kv, TaskPortEnv, strconv.Itoa(int(port)))
	}
	return out
}

// pickTaskPort returns a free port no other container claims. The port lock
// serializes it with every other reservation.
// shortcut: a free port can be taken by another socket before the task binds it; the task then fails to start and SwarmKit replaces it.
func (c *controller) pickTaskPort(ctx context.Context) (uint16, error) {
	lock := flock.New(c.executor.socket + ".ports.lock")
	locked, err := lock.TryLockContext(ctx, 25*time.Millisecond)
	if err != nil {
		return 0, err
	}
	if !locked {
		return 0, fmt.Errorf("runtime port reservation interrupted")
	}
	defer func() { _ = lock.Unlock() }()
	containers, err := c.executor.client.Containers(runtimeContext(ctx))
	if err != nil {
		return 0, err
	}
	claimed := map[string]bool{}
	for _, container := range containers {
		labels, err := container.Labels(runtimeContext(ctx))
		if err != nil {
			return 0, err
		}
		for port := range strings.SplitSeq(labels[portsLabel], ",") {
			claimed[port] = true
		}
	}
	for range 16 {
		ln, err := net.Listen("tcp", ":0")
		if err != nil {
			return 0, err
		}
		port := ln.Addr().(*net.TCPAddr).Port
		ln.Close()
		if !claimed[strconv.Itoa(port)] {
			return uint16(port), nil
		}
	}
	return 0, fmt.Errorf("no free task port")
}

// taskPorts returns the service port and this task's own port, when its spec uses TaskPortEnv.
func (c *controller) taskPorts(ctx context.Context) (service, task uint16, ok bool) {
	if c.stateful != nil || !usesTaskPort(c.spec.Env) {
		return 0, 0, false
	}
	service, err := hostPort(c.task)
	if err != nil {
		return 0, 0, false
	}
	ctr, err := c.container(runtimeContext(ctx))
	if err != nil {
		return 0, 0, false
	}
	labels, err := ctr.Labels(runtimeContext(ctx))
	if err != nil {
		return 0, 0, false
	}
	port, err := strconv.ParseUint(labels[portsLabel], 10, 16)
	if err != nil {
		return 0, 0, false
	}
	return service, uint16(port), true
}

// serve routes the service port to this ready task until unserve.
func (c *controller) serve(ctx context.Context) func() {
	service, task, ok := c.taskPorts(ctx)
	if !ok {
		return func() {}
	}
	handoff.Serve(service, task)
	return func() { handoff.Unserve(service, task) }
}
