package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/errdefs"
	"github.com/moby/swarmkit/v2/api"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var err error
	switch os.Args[1] {
	case "native":
		err = nativeDrain(ctx)
	case "native-worker":
		err = nativeWorker(ctx, os.Args[2], os.Args[3])
	default:
		err = run(ctx, os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, state string) error {
	control, conn, err := swarmruntime.DialSingleHost(state)
	if err != nil {
		return err
	}
	defer conn.Close()
	watch, err := api.NewWatchClient(conn).Watch(ctx, &api.WatchRequest{Entries: []*api.WatchRequest_WatchEntry{
		{Kind: "task", Action: api.WatchActionKindCreate | api.WatchActionKindUpdate},
	}})
	if err != nil {
		return err
	}
	if _, err := watch.Recv(); err != nil {
		return err
	}
	service, err := swarmruntime.ServiceByName(ctx, control, "e2e-whoami")
	if err != nil {
		return err
	}
	tasks, err := control.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{service.ID}, DesiredStates: []api.TaskState{api.TaskStateRunning}}})
	if err != nil {
		return err
	}
	if len(tasks.Tasks) != 1 || tasks.Tasks[0].Status.State != api.TaskStateRunning {
		return errors.New("expected exactly one running task before hanging the service")
	}
	original := tasks.Tasks[0]
	if err := swarmruntime.ProbeLocalTask(ctx, original); err != nil {
		return err
	}
	runtime, err := containerd.New(swarmruntime.HostContainerdSocket)
	if err != nil {
		return err
	}
	defer runtime.Close()
	runtimeCtx := namespaces.WithNamespace(ctx, "terrascale")
	container, err := runtime.LoadContainer(runtimeCtx, "ts-"+original.ID)
	if err != nil {
		return err
	}
	task, err := container.Task(runtimeCtx, nil)
	if err != nil {
		return err
	}
	if err := task.Kill(runtimeCtx, syscall.SIGSTOP, containerd.WithKillAll); err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = task.Kill(namespaces.WithNamespace(cleanup, "terrascale"), syscall.SIGCONT, containerd.WithKillAll)
	}()
	fmt.Println("hung running task", original.ID)
	failed := false
	for {
		message, err := watch.Recv()
		if err != nil {
			return err
		}
		for _, event := range message.Events {
			current := event.Object.GetTask()
			if current == nil || current.ServiceID != service.ID {
				continue
			}
			if current.ID == original.ID && current.Status.State == api.TaskStateFailed {
				if !strings.Contains(current.Status.Err, "consecutive readiness probes") {
					return fmt.Errorf("task failed for an unexpected reason: %s", current.Status.Err)
				}
				failed = true
				fmt.Println("hung task failed by readiness", current.ID)
			}
			if failed && current.ID != original.ID && current.Status.State == api.TaskStateRunning {
				if err := swarmruntime.ProbeLocalTask(ctx, current); err != nil {
					return err
				}
				status, err := task.Status(runtimeCtx)
				if err != nil && !errdefs.IsNotFound(err) {
					return err
				}
				if err == nil && status.Status != containerd.Stopped {
					return errors.New("replacement ready while the hung process survives")
				}
				fmt.Println("replacement ready; hung process stopped", current.ID)
				return nil
			}
		}
	}
}
