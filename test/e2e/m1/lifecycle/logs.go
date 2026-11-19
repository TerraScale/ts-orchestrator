package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/app"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
)

func serviceLogs(ctx context.Context, state string, args []string) error {
	if err := os.MkdirAll("/var/lib/ts-orch", 0700); err != nil {
		return err
	}
	if err := syscall.Mount(state, "/var/lib/ts-orch", "", syscall.MS_BIND, ""); err != nil {
		return err
	}
	return app.RunServiceCLI(ctx, append([]string{"logs"}, args...), os.Stdout)
}

func (j *journey) remoteLogs(image string) (func() error, error) {
	workerID, err := os.ReadFile(filepath.Join(j.root, "c18b", "ready"))
	if err != nil {
		return nil, err
	}
	declaration := swarmruntime.ServiceSpec{Name: "c17-logs", Image: image, Env: map[string]string{"PORT": "18088"},
		Args: []string{"sh", "-c", "wget -q -O /tmp/lifecycle http://127.0.0.1:19090/binary && chmod +x /tmp/lifecycle && exec /tmp/lifecycle serve"},
		Port: 18088, ReadyPath: "/missing", Replicas: 1}
	spec, err := declaration.SwarmSpec()
	if err != nil {
		return nil, err
	}
	spec.Task.Restart.Condition = api.RestartOnNone
	spec.Task.Placement = &api.Placement{Constraints: []string{"node.id==" + string(workerID)}}
	created, err := j.control.CreateService(j.ctx, &api.CreateServiceRequest{Spec: spec})
	if err != nil {
		return nil, err
	}
	var task *api.Task
	if err := until(j.ctx, func() error {
		tasks, err := j.control.ListTasks(j.ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{created.Service.ID}}})
		if err != nil {
			return err
		}
		for _, candidate := range tasks.Tasks {
			if candidate.Status.State == api.TaskStateStarting {
				task = candidate
				for _, stream := range []string{"stdout", "stderr"} {
					data, err := os.ReadFile(swarmruntime.RuntimeLogFile(filepath.Join(j.root, "c18b"), task.ID, stream))
					if err != nil || !strings.Contains(string(data), "service-log-"+stream) {
						return fmt.Errorf("waiting for worker %s: %w", stream, err)
					}
				}
				return nil
			}
		}
		return errors.New("waiting for starting worker task")
	}); err != nil {
		return nil, err
	}
	if _, err := os.Stat(swarmruntime.RuntimeLogFile(filepath.Join(j.root, "c18a"), task.ID, "stdout")); !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("worker logs unexpectedly exist on manager: %v", err)
	}
	command := func(ctx context.Context, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "ip", append([]string{"netns", "exec", "c18a", "unshare", "--mount", "--propagation", "private", os.Args[0], "service-logs", filepath.Join(j.root, "c18a")}, args...)...)
	}
	check := func(want []string, args ...string) error {
		data, err := command(j.ctx, args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("manager logs %v: %w: %s", args, err, data)
		}
		for _, line := range append([]string{"service-log-stdout", "service-log-stderr"}, want...) {
			if !strings.Contains(string(data), line) {
				return fmt.Errorf("manager logs %v missing %q: %s", args, line, data)
			}
		}
		if args[0] == "--previous" && !strings.HasPrefix(string(data), "== task "+task.ID+" node=c18b slot=1 ") {
			return fmt.Errorf("previous logs selected another task: %s", data)
		}
		fmt.Printf("C17 manager logs %v from worker task %s: %v verified, %d bytes\n", args, task.ID, want, len(data))
		return nil
	}
	if err := check(nil, "c17-logs"); err != nil {
		return nil, err
	}
	refusal, cancel := context.WithTimeout(j.ctx, 30*time.Second)
	defer cancel()
	data, err := command(refusal, "-f", "c17-logs").CombinedOutput()
	if want := "follow works only on the node that runs the task: run it on c18b"; err == nil || refusal.Err() != nil || !strings.Contains(string(data), want) {
		return nil, fmt.Errorf("manager follow of worker task %s: want refusal %q, got %v: %s", task.ID, want, err, data)
	}
	fmt.Printf("C17 manager follow of worker task %s refused at once: %s", task.ID, data)
	return func() error {
		if err := until(j.ctx, func() error {
			node, err := j.control.GetNode(j.ctx, &api.GetNodeRequest{NodeID: string(workerID)})
			if err == nil && node.Node.Status.State != api.NodeStatus_READY {
				return fmt.Errorf("waiting for worker READY after agent restart: %s", node.Node.Status.State)
			}
			return err
		}); err != nil {
			return err
		}
		current, err := j.control.GetTask(j.ctx, &api.GetTaskRequest{TaskID: task.ID})
		if err != nil {
			return err
		}
		if current.Task.Status.State != api.TaskStateStarting {
			return fmt.Errorf("worker task %s is %s after agent restart, want its pre-restart STARTING task", task.ID, current.Task.Status.State)
		}
		if err := request(j.ctx, "10.231.0.3:18088", "/log-after-restart", http.StatusOK); err != nil {
			return err
		}
		if err := until(j.ctx, func() error {
			data, err := os.ReadFile(swarmruntime.RuntimeLogFile(filepath.Join(j.root, "c18b"), task.ID, "stdout"))
			if err != nil || !strings.Contains(string(data), "service-log-after-restart") {
				return fmt.Errorf("waiting for worker logger to persist the post-restart line: %w", err)
			}
			return nil
		}); err != nil {
			return err
		}
		if err := check([]string{"service-log-after-restart"}, "c17-logs"); err != nil {
			return err
		}
		output, err := exec.CommandContext(j.ctx, "ctr", "--address", filepath.Join(j.root, "c18b", "containerd.sock"), "--namespace", "terrascale", "tasks", "kill", "--signal", "SIGKILL", "--all", "ts-"+task.ID).CombinedOutput()
		if err != nil {
			return fmt.Errorf("exit worker task while retaining replica slot: %w: %s", err, output)
		}
		if err := until(j.ctx, func() error {
			current, err := j.control.GetTask(j.ctx, &api.GetTaskRequest{TaskID: task.ID})
			if err == nil && current.Task.Status.State <= api.TaskStateRunning {
				return errors.New("waiting for worker task exit")
			}
			return err
		}); err != nil {
			return err
		}
		if err := check([]string{"service-log-after-restart"}, "--previous", "c17-logs"); err != nil {
			return err
		}
		unassigned := func(revision string) (id string, err error) {
			service, err := j.control.GetService(j.ctx, &api.GetServiceRequest{ServiceID: created.Service.ID})
			if err != nil {
				return "", err
			}
			spec := service.Service.Spec.Copy()
			spec.Task.Placement.Constraints = []string{"node.id==c17-unassigned-" + revision}
			if _, err := j.control.UpdateService(j.ctx, &api.UpdateServiceRequest{ServiceID: created.Service.ID, ServiceVersion: &service.Service.Meta.Version, Spec: spec}); err != nil {
				return "", err
			}
			err = until(j.ctx, func() error {
				tasks, err := j.control.ListTasks(j.ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{created.Service.ID}}})
				if err != nil {
					return err
				}
				for _, candidate := range tasks.Tasks {
					if candidate.NodeID == "" && candidate.Status.State == api.TaskStatePending && len(candidate.Spec.Placement.Constraints) == 1 && candidate.Spec.Placement.Constraints[0] == spec.Task.Placement.Constraints[0] {
						id = candidate.ID
						return nil
					}
				}
				return errors.New("waiting for unassigned replica slot")
			})
			return id, err
		}
		pending, err := unassigned("first")
		if err != nil {
			return err
		}
		if _, err := unassigned("second"); err != nil {
			return err
		}
		if err := until(j.ctx, func() error {
			result, err := j.control.GetTask(j.ctx, &api.GetTaskRequest{TaskID: pending})
			if err == nil && (result.Task.NodeID != "" || result.Task.Status.State != api.TaskStateShutdown) {
				return errors.New("waiting for superseded unassigned task shutdown")
			}
			return err
		}); err != nil {
			return err
		}
		return check([]string{"service-log-after-restart"}, "--previous", "c17-logs")
	}, nil
}
