package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/handoff"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/errdefs"
	"github.com/moby/swarmkit/v2/api"
)

func main() {
	if len(os.Args) == 3 && os.Args[1] == "--runtime-logger" {
		swarmruntime.RunRuntimeLogger(os.Args[2])
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 12*time.Minute)
	defer cancel()
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(ctx)
	case "runtime":
		err = until(ctx, func() error {
			client, err := containerd.New(os.Args[2])
			if err != nil {
				return err
			}
			defer client.Close()
			_, err = client.Version(ctx)
			return err
		})
	case "node":
		err = node(ctx, os.Args[2], os.Args[3])
	default:
		err = run(ctx, os.Args[1], os.Args[2])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serve(ctx context.Context) error {
	var unavailable atomic.Bool
	server := &http.Server{Addr: ":18083", ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/unavailable":
			unavailable.Store(true)
		case "/recover":
			unavailable.Store(false)
		case "/ready":
			if unavailable.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			fmt.Fprint(w, os.Getpid())
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})}
	stop := context.AfterFunc(ctx, func() { _ = server.Close() })
	defer stop()
	err := server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func until(ctx context.Context, check func() error) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if err := check(); err == nil {
			return nil
		} else {
			select {
			case <-ctx.Done():
				return errors.Join(ctx.Err(), err)
			case <-ticker.C:
			}
		}
	}
}

func node(ctx context.Context, root, name string) error {
	state := filepath.Join(root, name)
	executor, err := swarmruntime.NewExecutor(filepath.Join(state, "containerd.sock"), state)
	if err != nil {
		return err
	}
	defer executor.Close()
	address := "10.231.0.2:4242"
	admission := swarmruntime.FounderAdmission()
	if name == "c18b" {
		address = "10.231.0.3:4242"
		var token []byte
		if err := until(ctx, func() error {
			var err error
			token, err = os.ReadFile(filepath.Join(root, "join-token"))
			return err
		}); err != nil {
			return err
		}
		admission = swarmruntime.JoinerAdmission(name, name, "10.231.0.2:4242", string(token))
	}
	node, err := swarmruntime.StartSingleHost(ctx, state, executor, address, address, admission)
	if err != nil {
		return err
	}
	defer func() {
		stop, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = node.Stop(stop)
	}()
	if name == "c18a" {
		client, err := node.ControlClient(ctx)
		if err != nil {
			return err
		}
		clusters, err := client.ListClusters(ctx, &api.ListClustersRequest{})
		if err != nil {
			return err
		}
		if len(clusters.Clusters) != 1 {
			return errors.New("expected one regional cluster")
		}
		if err := os.WriteFile(filepath.Join(root, "join-token"), []byte(clusters.Clusters[0].RootCA.JoinTokens.Worker), 0600); err != nil {
			return err
		}
	}
	control, conn, err := swarmruntime.DialSingleHost(filepath.Join(root, "c18a"))
	if err != nil {
		return err
	}
	defer conn.Close()
	source := "single-host"
	if name == "c18b" {
		source = name
	}
	addresses := map[string]netip.Addr{"single-host": netip.MustParseAddr("10.231.0.2"), "c18b": netip.MustParseAddr("10.231.0.3")}
	handoff.SetTaskPeerProbe(func(ctx context.Context, task string) error {
		return swarmruntime.ProbeRegionalTaskPeer(ctx, control, task, source, "single-host", addresses)
	})
	if err := os.WriteFile(filepath.Join(state, "ready"), []byte(node.ID()), 0600); err != nil {
		return err
	}
	<-ctx.Done()
	return nil
}

func request(ctx context.Context, address, path string, want int) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+":18083"+path, nil)
	if err != nil {
		return err
	}
	response, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != want {
		return fmt.Errorf("%s: HTTP %d, expected %d", path, response.StatusCode, want)
	}
	return nil
}

func run(ctx context.Context, root, image string) error {
	if err := until(ctx, func() error {
		_, err := os.Stat(swarmruntime.SingleHostSocket(filepath.Join(root, "c18a")))
		return err
	}); err != nil {
		return err
	}
	control, conn, err := swarmruntime.DialSingleHost(filepath.Join(root, "c18a"))
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := until(ctx, func() error {
		for _, name := range []string{"c18a", "c18b"} {
			if _, err := os.Stat(filepath.Join(root, name, "ready")); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	spec, err := (swarmruntime.ServiceSpec{Name: "c18-data", Image: image, Args: []string{"/tmp/lifecycle", "serve"}, Mounts: []swarmruntime.ServiceMount{{Source: "/var/lib/ts-data/c18", Target: "/tmp"}}, Port: 18083, ReadyPath: "/ready", Replicas: 2}).SwarmSpec()
	if err != nil {
		return err
	}
	created, err := control.CreateService(ctx, &api.CreateServiceRequest{Spec: spec})
	if err != nil {
		return err
	}
	serviceID := created.Service.ID
	running := func() ([]*api.Task, error) {
		tasks, err := control.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{serviceID}, DesiredStates: []api.TaskState{api.TaskStateRunning}}})
		if err != nil {
			return nil, err
		}
		if len(tasks.Tasks) != 2 {
			return nil, fmt.Errorf("expected two tasks, got %d", len(tasks.Tasks))
		}
		for _, task := range tasks.Tasks {
			if task.Status.State != api.TaskStateRunning {
				return nil, fmt.Errorf("task %s is %s: %s", task.ID, task.Status.State, task.Status.Err)
			}
		}
		return tasks.Tasks, nil
	}
	var originals []*api.Task
	if err := until(ctx, func() error { var err error; originals, err = running(); return err }); err != nil {
		return err
	}
	for _, address := range []string{"10.231.0.2", "10.231.0.3"} {
		if err := request(ctx, address, "/ready", http.StatusOK); err != nil {
			return err
		}
	}
	founderID, err := os.ReadFile(filepath.Join(root, "c18a", "ready"))
	if err != nil {
		return err
	}
	var original *api.Task
	for _, task := range originals {
		if task.NodeID == string(founderID) {
			original = task
		}
	}
	if original == nil {
		return errors.New("no source task on founder")
	}
	runtime, err := containerd.New(filepath.Join(root, "c18a", "containerd.sock"))
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
	if err := request(ctx, "10.231.0.3", "/unavailable", http.StatusOK); err != nil {
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
	fmt.Println("frozen data owner with peer returning 503; observing the full production window")
	deadline := time.NewTimer(6*time.Minute + 45*time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
observe:
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			break observe
		case <-ticker.C:
			tasks, err := running()
			if err != nil {
				return err
			}
			for _, current := range tasks {
				if current.ID != originals[0].ID && current.ID != originals[1].ID {
					return errors.New("a hung data owner without a ready peer or its 503 peer was replaced")
				}
			}
			if err := request(ctx, "10.231.0.3", "/ready", http.StatusServiceUnavailable); err != nil {
				return err
			}
		}
	}
	fmt.Println("same data owners retained: frozen without a ready peer; 503 throughout the window")
	if err := request(ctx, "10.231.0.3", "/recover", http.StatusOK); err != nil {
		return err
	}
	if err := until(ctx, func() error {
		current, err := control.GetTask(ctx, &api.GetTaskRequest{TaskID: original.ID})
		if err != nil {
			return err
		}
		if current.Task.Status.State != api.TaskStateFailed {
			return errors.New("waiting for the hung source to fail")
		}
		if !strings.Contains(current.Task.Status.Err, "consecutive readiness probes") {
			return fmt.Errorf("unexpected task failure: %s", current.Task.Status.Err)
		}
		tasks, err := running()
		if err != nil {
			return err
		}
		for _, current := range tasks {
			if current.NodeID == original.NodeID && current.ID == original.ID {
				return errors.New("waiting for a distinct replacement")
			}
		}
		return request(ctx, "10.231.0.2", "/ready", http.StatusOK)
	}); err != nil {
		return err
	}
	status, err := task.Status(runtimeCtx)
	if err != nil && !errdefs.IsNotFound(err) {
		return err
	}
	if err == nil && status.Status != containerd.Stopped {
		return errors.New("replacement is ready while the hung process survives")
	}
	fmt.Println("ready peer authorized replacement; distinct replacement serves; hung process is stopped")
	return nil
}
