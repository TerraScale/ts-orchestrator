package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/moby/swarmkit/v2/agent/exec"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/api/genericresource"
)

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	ctx = namespaces.WithNamespace(ctx, "terrascale")
	client, err := containerd.New(swarmruntime.HostContainerdSocket)
	if err != nil {
		return err
	}
	defer client.Close()
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		return err
	}
	var spec swarmruntime.ServiceSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return err
	}
	image, err := client.GetImage(ctx, spec.Image)
	if err != nil {
		return err
	}
	alias := "ghcr.io/terrascale/terrascale-dashboard@" + image.Target().Digest.String()
	if _, err := client.ImageService().Create(ctx, images.Image{Name: alias, Target: image.Target()}); err != nil {
		return err
	}
	defer client.ImageService().Delete(context.WithoutCancel(ctx), alias)
	state, err := os.MkdirTemp("", "monitoring-e2e-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(state)
	executor, err := swarmruntime.NewExecutor(swarmruntime.HostContainerdSocket, filepath.Join(state, "runtime"))
	if err != nil {
		return fmt.Errorf("open monitoring executor: %w", err)
	}
	defer executor.Close()
	var tasks []*api.Task
	var controllers []exec.Controller
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		for _, controller := range controllers {
			if err := controller.Shutdown(cleanup); err != nil {
				panic(err)
			}
			if err := controller.Remove(cleanup); err != nil {
				panic(err)
			}
		}
	}()
	for i, name := range []string{"ts-dashboard", "e2e-dashboard"} {
		runtime, err := swarmruntime.ContainerRuntime(&api.ContainerSpec{Image: alias, Args: []string{"--port", strconv.Itoa(18084 + i)}, User: "65532:65532"})
		if err != nil {
			return err
		}
		resources := &api.Resources{NanoCPUs: 50_000_000, MemoryBytes: 64 << 20, Generic: []*api.GenericResource{genericresource.NewDiscrete(swarmruntime.DiskResource, 1<<30)}}
		task := &api.Task{ID: fmt.Sprintf("e2emonitoring%d", i), ServiceID: fmt.Sprintf("e2emonitoringservice%d", i),
			Spec:               api.TaskSpec{Runtime: runtime, Resources: &api.ResourceRequirements{Limits: resources, Reservations: resources.Copy()}},
			ServiceAnnotations: api.Annotations{Name: name, Labels: map[string]string{swarmruntime.LabelServiceSpec: name, swarmruntime.LabelPort: strconv.Itoa(18084 + i)}}}
		controller, err := executor.Controller(task)
		if err != nil {
			return err
		}
		controllers = append(controllers, controller)
		tasks = append(tasks, task)
		if err := controller.Prepare(ctx); err != nil {
			return fmt.Errorf("prepare %s: %w", name, err)
		}
		if err := controller.Start(ctx); err != nil {
			return fmt.Errorf("start %s: %w", name, err)
		}
	}
	verify := func(executor *swarmruntime.Executor) error {
		for _, task := range tasks {
			container, err := client.LoadContainer(ctx, "ts-"+task.ID)
			if err != nil {
				return err
			}
			process, err := container.Task(ctx, nil)
			if err != nil {
				return err
			}
			status, err := process.Status(ctx)
			if err != nil {
				return err
			}
			if status.Status != containerd.Running {
				return fmt.Errorf("task %s is not running: %s", task.ID, status.Status)
			}
		}
		targets, err := executor.SLOTargets(ctx, "local")
		if err != nil {
			return err
		}
		if len(targets) != 1 || targets[0].Labels["service"] != "ts-dashboard" || targets[0].Labels["instance"] != tasks[0].ID {
			return fmt.Errorf("service identity mismatch: %+v", targets)
		}
		targets[0].Labels["service"] = "caller mutation"
		again, err := executor.SLOTargets(ctx, "local")
		if err != nil {
			return err
		}
		if again[0].Labels["service"] != "ts-dashboard" {
			return fmt.Errorf("cache mutated by caller")
		}
		counts, err := executor.SLOTaskCounts(ctx)
		if err != nil {
			return err
		}
		if counts["ts-dashboard"] != 1 || counts["ts-auth"] != 0 || counts["terrabase"] != 0 {
			return fmt.Errorf("unexpected service task counts: %v", counts)
		}
		return nil
	}
	if err := verify(executor); err != nil {
		return err
	}
	restarted, err := swarmruntime.NewExecutor(swarmruntime.HostContainerdSocket, filepath.Join(state, "runtime"))
	if err != nil {
		return err
	}
	defer restarted.Close()
	if err := verify(restarted); err != nil {
		return err
	}
	for _, task := range tasks {
		container, err := client.LoadContainer(ctx, "ts-"+task.ID)
		if err != nil {
			return err
		}
		if _, err := container.SetLabels(ctx, map[string]string{swarmruntime.LabelServiceSpec: ""}); err != nil {
			return err
		}
		adopted, err := restarted.Controller(task)
		if err != nil {
			return err
		}
		if err := adopted.Prepare(ctx); err != nil {
			return fmt.Errorf("adopt %s: %w", task.ID, err)
		}
	}
	adopted, err := swarmruntime.NewExecutor(swarmruntime.HostContainerdSocket, filepath.Join(state, "runtime"))
	if err != nil {
		return err
	}
	defer adopted.Close()
	if err := verify(adopted); err != nil {
		return err
	}
	fmt.Println("monitoring: same-image second service excluded; task counts, restart, adoption and cache isolation passed")
	return nil
}

func main() {
	if len(os.Args) == 3 && os.Args[1] == "--runtime-logger" {
		swarmruntime.RunRuntimeLogger(os.Args[2])
		return
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
