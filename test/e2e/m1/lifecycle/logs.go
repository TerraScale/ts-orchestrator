package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

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

func (j *journey) remoteLogs(image string) error {
	workerID, err := os.ReadFile(filepath.Join(j.root, "c18b", "ready"))
	if err != nil {
		return err
	}
	declaration := swarmruntime.ServiceSpec{Name: "c17-logs", Image: image, Env: map[string]string{"PORT": "18088"},
		Args: []string{"sh", "-c", "wget -q -O /tmp/lifecycle http://127.0.0.1:19090/binary && chmod +x /tmp/lifecycle && exec /tmp/lifecycle serve"},
		Port: 18088, ReadyPath: "/missing", Replicas: 1}
	spec, err := declaration.SwarmSpec()
	if err != nil {
		return err
	}
	spec.Task.Placement = &api.Placement{Constraints: []string{"node.id==" + string(workerID)}}
	created, err := j.control.CreateService(j.ctx, &api.CreateServiceRequest{Spec: spec})
	if err != nil {
		return err
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
		return err
	}
	if _, err := os.Stat(swarmruntime.RuntimeLogFile(filepath.Join(j.root, "c18a"), task.ID, "stdout")); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("worker logs unexpectedly exist on manager: %v", err)
	}
	command := func(ctx context.Context, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "ip", append([]string{"netns", "exec", "c18a", "unshare", "--mount", "--propagation", "private", os.Args[0], "service-logs", filepath.Join(j.root, "c18a")}, args...)...)
	}
	check := func(args ...string) error {
		data, err := command(j.ctx, args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("manager logs %v: %w: %s", args, err, data)
		}
		for _, stream := range []string{"stdout", "stderr"} {
			if !strings.Contains(string(data), "service-log-"+stream) {
				return fmt.Errorf("manager logs %v missing %s: %s", args, stream, data)
			}
		}
		fmt.Printf("C17 manager logs %v from worker task %s: %s", args, task.ID, data)
		return nil
	}
	if err := check("c17-logs"); err != nil {
		return err
	}
	followCtx, cancel := context.WithCancel(j.ctx)
	defer cancel()
	follow := command(followCtx, "-f", "c17-logs")
	pipe, err := follow.StdoutPipe()
	if err != nil {
		return err
	}
	follow.Stderr = os.Stderr
	if err := follow.Start(); err != nil {
		return err
	}
	defer func() { cancel(); _ = follow.Wait() }()
	initial := make([]byte, len("service-log-stdout\nservice-log-stderr\n"))
	if _, err := io.ReadFull(pipe, initial); err != nil || string(initial) != "service-log-stdout\nservice-log-stderr\n" {
		return fmt.Errorf("remote follow snapshot: %q: %w", initial, err)
	}
	if err := request(j.ctx, "10.231.0.3:18088", "/log-follow", http.StatusOK); err != nil {
		return err
	}
	appended := make([]byte, len("service-log-follow\n"))
	if _, err := io.ReadFull(pipe, appended); err != nil || string(appended) != "service-log-follow\n" {
		return fmt.Errorf("remote follow: %q: %w", appended, err)
	}
	cancel()
	fmt.Println("C17 manager followed appended stdout from STARTING worker task")
	service := created.Service
	service.Spec.GetReplicated().Replicas = 0
	if _, err := j.control.UpdateService(j.ctx, &api.UpdateServiceRequest{ServiceID: service.ID, ServiceVersion: &service.Meta.Version, Spec: &service.Spec}); err != nil {
		return err
	}
	if err := until(j.ctx, func() error {
		current, err := j.control.GetTask(j.ctx, &api.GetTaskRequest{TaskID: task.ID})
		if err == nil && current.Task.Status.State <= api.TaskStateRunning {
			return errors.New("waiting for worker task shutdown")
		}
		return err
	}); err != nil {
		return err
	}
	return check("--previous", "c17-logs")
}
