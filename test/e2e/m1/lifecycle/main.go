package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

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
	server := &http.Server{Addr: ":18083", ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ready":
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
	var mu sync.Mutex
	defer func() {
		stop, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		mu.Lock()
		defer mu.Unlock()
		if node != nil {
			_ = node.Stop(stop)
		}
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
	server := &http.Server{Addr: ":19090", ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/metrics":
			swarmruntime.ReadinessMetrics.WritePrometheus(w)
		case "/agent-stop":
			if err := node.Stop(r.Context()); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		case "/agent-start":
			var err error
			node, err = swarmruntime.StartSingleHost(ctx, state, executor, address, address, admission)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		default:
			http.NotFound(w, r)
		}
	})}
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(os.Stderr, err)
		}
	}()
	defer server.Close()
	if err := os.WriteFile(filepath.Join(state, "ready"), []byte(node.ID()), 0600); err != nil {
		return err
	}
	<-ctx.Done()
	return nil
}

func request(ctx context.Context, address, path string, want int) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+path, nil)
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

func agentAction(ctx context.Context, address, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+address+path, nil)
	if err != nil {
		return err
	}
	response, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", path, response.StatusCode)
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
	dataSpec, err := (swarmruntime.ServiceSpec{Name: "c18-data", Image: image, Args: []string{"/tmp/lifecycle", "serve"}, Mounts: []swarmruntime.ServiceMount{{Source: "/var/lib/ts-data/c18", Target: "/tmp"}}, Port: 18083, ReadyPath: "/ready", Replicas: 1}).SwarmSpec()
	if err != nil {
		return err
	}
	emptySpec, err := (swarmruntime.ServiceSpec{Name: "c18-empty", Image: image, Args: []string{"sh", "-c", "mkdir -p /www; echo ready > /www/ready; exec httpd -f -p 18084 -h /www"}, Port: 18084, ReadyPath: "/ready", Replicas: 1}).SwarmSpec()
	if err != nil {
		return err
	}
	var originals []*api.Task
	var processes []containerd.Task
	var runtimes []*containerd.Client
	defer func() {
		for _, runtime := range runtimes {
			_ = runtime.Close()
		}
	}()
	addresses := []string{"10.231.0.2:18083", "10.231.0.3:18084"}
	for i, spec := range []*api.ServiceSpec{dataSpec, emptySpec} {
		name := []string{"c18a", "c18b"}[i]
		nodeID, err := os.ReadFile(filepath.Join(root, name, "ready"))
		if err != nil {
			return err
		}
		if spec.Task.Placement == nil {
			spec.Task.Placement = &api.Placement{}
		}
		spec.Task.Placement.Constraints = append(spec.Task.Placement.Constraints, "node.id=="+string(nodeID))
		created, err := control.CreateService(ctx, &api.CreateServiceRequest{Spec: spec})
		if err != nil {
			return err
		}
		var original *api.Task
		if err := until(ctx, func() error {
			tasks, err := control.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{created.Service.ID}, DesiredStates: []api.TaskState{api.TaskStateRunning}}})
			if err != nil {
				return err
			}
			if len(tasks.Tasks) != 1 || tasks.Tasks[0].Status.State != api.TaskStateRunning {
				return errors.New("waiting for a running task")
			}
			original = tasks.Tasks[0]
			return request(ctx, addresses[i], "/ready", http.StatusOK)
		}); err != nil {
			return err
		}
		runtime, err := containerd.New(filepath.Join(root, name, "containerd.sock"))
		if err != nil {
			return err
		}
		runtimes = append(runtimes, runtime)
		runtimeCtx := namespaces.WithNamespace(ctx, "terrascale")
		container, err := runtime.LoadContainer(runtimeCtx, "ts-"+original.ID)
		if err != nil {
			return err
		}
		process, err := container.Task(runtimeCtx, nil)
		if err != nil {
			return err
		}
		originals = append(originals, original)
		processes = append(processes, process)
	}
	pids := []uint32{processes[0].Pid(), processes[1].Pid()}
	for _, action := range []string{"/agent-stop", "/agent-start"} {
		for _, address := range []string{"10.231.0.2:19090", "10.231.0.3:19090"} {
			if err := agentAction(ctx, address, action); err != nil {
				return err
			}
		}
		for i, address := range addresses {
			if err := request(ctx, address, "/ready", http.StatusOK); err != nil {
				return err
			}
			container, err := runtimes[i].LoadContainer(namespaces.WithNamespace(ctx, "terrascale"), "ts-"+originals[i].ID)
			if err != nil {
				return err
			}
			process, err := container.Task(namespaces.WithNamespace(ctx, "terrascale"), nil)
			if err != nil {
				return err
			}
			if process.Pid() != pids[i] {
				return errors.New("agent stop/start changed a task process id")
			}
		}
	}
	fmt.Printf("agent stop/start retained task PIDs %d and %d; both served while stopped and after start\n", pids[0], pids[1])
	runtimeCtx := namespaces.WithNamespace(ctx, "terrascale")
	for _, process := range processes {
		if err := process.Kill(runtimeCtx, syscall.SIGSTOP, containerd.WithKillAll); err != nil {
			return err
		}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = process.Kill(namespaces.WithNamespace(cleanup, "terrascale"), syscall.SIGCONT, containerd.WithKillAll)
		}()
	}
	gauge := func() (float64, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://10.231.0.2:19090/metrics", nil)
		if err != nil {
			return 0, err
		}
		response, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
		if err != nil {
			return 0, err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
		if err != nil {
			return 0, err
		}
		for _, line := range strings.Split(string(body), "\n") {
			if strings.HasPrefix(line, "ts_orch_task_unresponsive_seconds{") && strings.Contains(line, "task=\""+originals[0].ID+"\"") {
				fields := strings.Fields(line)
				return strconv.ParseFloat(fields[len(fields)-1], 64)
			}
		}
		return 0, errors.New("missing data-owner gauge")
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	lastGauge := 0.0
	replaced := false
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			data, err := control.GetTask(ctx, &api.GetTaskRequest{TaskID: originals[0].ID})
			if err != nil {
				return err
			}
			if data.Task.Status.State != api.TaskStateRunning || data.Task.DesiredState != api.TaskStateRunning {
				return errors.New("frozen data owner was failed or replaced")
			}
			value, err := gauge()
			if err != nil {
				return err
			}
			if value < lastGauge {
				return fmt.Errorf("frozen data-owner gauge regressed from %g to %g", lastGauge, value)
			}
			lastGauge = value
			empty, err := control.GetTask(ctx, &api.GetTaskRequest{TaskID: originals[1].ID})
			if err != nil {
				return err
			}
			if empty.Task.Status.State == api.TaskStateFailed {
				if !strings.Contains(empty.Task.Status.Err, "consecutive readiness probes") {
					return fmt.Errorf("unexpected task failure: %s", empty.Task.Status.Err)
				}
				tasks, err := control.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{originals[1].ServiceID}, DesiredStates: []api.TaskState{api.TaskStateRunning}}})
				if err != nil {
					return err
				}
				if len(tasks.Tasks) == 1 && tasks.Tasks[0].ID != originals[1].ID && tasks.Tasks[0].Status.State == api.TaskStateRunning {
					if err := request(ctx, addresses[1], "/ready", http.StatusOK); err != nil {
						return err
					}
					replaced = true
				}
			}
			if replaced && value >= (6*time.Minute).Seconds() {
				status, err := processes[1].Status(runtimeCtx)
				if err != nil && !errdefs.IsNotFound(err) {
					return err
				}
				if err == nil && status.Status != containerd.Stopped {
					return errors.New("replacement serves while the original process survives")
				}
				fmt.Printf("frozen task without data replaced and serving; original process stopped; frozen data owner retained, gauge %.0f seconds\n", value)
				if err := processes[0].Kill(runtimeCtx, syscall.SIGCONT, containerd.WithKillAll); err != nil {
					return err
				}
				if err := until(ctx, func() error {
					value, err := gauge()
					if err != nil {
						return err
					}
					if value != 0 {
						return errors.New("waiting for recovered data-owner gauge to clear")
					}
					return request(ctx, addresses[0], "/ready", http.StatusOK)
				}); err != nil {
					return err
				}
				fmt.Println("same data owner recovered and serving; gauge cleared")
				return nil
			}
		}
	}
}
