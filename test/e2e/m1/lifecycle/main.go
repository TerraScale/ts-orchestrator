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
	ctx, cancel := context.WithTimeout(ctx, 45*time.Minute)
	defer cancel()
	var err error
	switch os.Args[1] {
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
		case "/binary":
			http.ServeFile(w, r, os.Args[4])
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

type workload struct {
	task    *api.Task
	process containerd.Task
	runtime *containerd.Client
	address string
	host    string
}

type journey struct {
	ctx       context.Context
	root      string
	control   api.ControlClient
	workloads []*workload
	frozen    map[*workload]bool
}

func (j *journey) metric(w *workload, name string) (float64, error) {
	req, err := http.NewRequestWithContext(j.ctx, http.MethodGet, "http://"+w.host+":19090/metrics", nil)
	if err != nil {
		return 0, err
	}
	response, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "ts_orch_"+name+"{") && strings.Contains(line, "task=\""+w.task.ID+"\"") {
			fields := strings.Fields(line)
			return strconv.ParseFloat(fields[len(fields)-1], 64)
		}
	}
	return 0, fmt.Errorf("missing %s for task %s", name, w.task.ID)
}

func (j *journey) logCount(w *workload, text string) (int, error) {
	name := "c18a"
	if w.host == "10.231.0.3" {
		name = "c18b"
	}
	data, err := os.ReadFile(filepath.Join(j.root, name, "output"))
	if err != nil {
		return 0, err
	}
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, text) && strings.Contains(line, "task="+w.task.ID) {
			count++
		}
	}
	return count, nil
}

func (j *journey) retained(workloads ...*workload) error {
	for _, w := range workloads {
		result, err := j.control.GetTask(j.ctx, &api.GetTaskRequest{TaskID: w.task.ID})
		if err != nil {
			return err
		}
		if result.Task.Status.State != api.TaskStateRunning || result.Task.DesiredState != api.TaskStateRunning {
			return fmt.Errorf("task %s unexpectedly left running: %s", w.task.ID, result.Task.Status.Err)
		}
	}
	return j.processesRetained(workloads...)
}

func (j *journey) processesRetained(workloads ...*workload) error {
	runtimeCtx := namespaces.WithNamespace(j.ctx, "terrascale")
	for _, w := range workloads {
		container, err := w.runtime.LoadContainer(runtimeCtx, "ts-"+w.task.ID)
		if err != nil {
			return err
		}
		process, err := container.Task(runtimeCtx, nil)
		if err != nil {
			return err
		}
		if process.Pid() != w.process.Pid() {
			return fmt.Errorf("task %s changed PID from %d to %d", w.task.ID, w.process.Pid(), process.Pid())
		}
		status, err := process.Status(runtimeCtx)
		if err != nil {
			return err
		}
		if status.Status != containerd.Running && status.Status != containerd.Paused {
			return fmt.Errorf("task %s PID %d is %s", w.task.ID, process.Pid(), status.Status)
		}
	}
	return nil
}

func (j *journey) freeze(workloads ...*workload) error {
	for _, w := range workloads {
		if err := w.process.Kill(namespaces.WithNamespace(j.ctx, "terrascale"), syscall.SIGSTOP, containerd.WithKillAll); err != nil {
			return err
		}
		j.frozen[w] = true
	}
	return nil
}

func (j *journey) recover(workloads ...*workload) error {
	for _, w := range workloads {
		if err := w.process.Kill(namespaces.WithNamespace(j.ctx, "terrascale"), syscall.SIGCONT, containerd.WithKillAll); err != nil {
			return err
		}
		delete(j.frozen, w)
	}
	return until(j.ctx, func() error {
		if err := j.retained(workloads...); err != nil {
			return err
		}
		for _, w := range workloads {
			value, err := j.metric(w, "task_unresponsive_seconds")
			if err != nil {
				return err
			}
			if value != 0 {
				return fmt.Errorf("task %s has not cleared", w.task.ID)
			}
			if err := request(j.ctx, w.address, "/ready", http.StatusOK); err != nil {
				return err
			}
		}
		return nil
	})
}

func (j *journey) reported(reason string, counts map[*workload]int, workloads ...*workload) error {
	return until(j.ctx, func() error {
		if err := j.retained(workloads...); err != nil {
			return err
		}
		for _, w := range workloads {
			count, err := j.logCount(w, reason)
			if err != nil {
				return err
			}
			if count != counts[w]+1 {
				return fmt.Errorf("task %s report %q: %d, expected %d", w.task.ID, reason, count, counts[w]+1)
			}
			value, err := j.metric(w, "task_unresponsive_seconds")
			if err != nil {
				return err
			}
			if value < (5 * time.Minute).Seconds() {
				return fmt.Errorf("task %s gauge %g", w.task.ID, value)
			}
		}
		return nil
	})
}

func (j *journey) running(service, host string, port int, runtime *containerd.Client) ([]*workload, error) {
	tasks, err := j.control.ListTasks(j.ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{service}, DesiredStates: []api.TaskState{api.TaskStateRunning}}})
	if err != nil {
		return nil, err
	}
	var result []*workload
	for _, task := range tasks.Tasks {
		if task.Status.State != api.TaskStateRunning {
			return nil, errors.New("waiting for running process")
		}
		container, err := runtime.LoadContainer(namespaces.WithNamespace(j.ctx, "terrascale"), "ts-"+task.ID)
		if err != nil {
			return nil, err
		}
		process, err := container.Task(namespaces.WithNamespace(j.ctx, "terrascale"), nil)
		if err != nil {
			return nil, err
		}
		labels, err := container.Labels(namespaces.WithNamespace(j.ctx, "terrascale"))
		if err != nil {
			return nil, err
		}
		own, err := strconv.Atoi(labels["terrascale.ports"])
		if err != nil {
			return nil, err
		}
		w := &workload{task: task, process: process, runtime: runtime, host: host, address: host + ":" + strconv.Itoa(own)}
		if err := request(j.ctx, w.address, "/ready", http.StatusOK); err != nil {
			return nil, err
		}
		result = append(result, w)
	}
	return result, nil
}

func (j *journey) create(image, name, host string, port int, owner bool, replicas uint64) ([]*workload, error) {
	nodeName := "c18a"
	if host == "10.231.0.3" {
		nodeName = "c18b"
	}
	nodeID, err := os.ReadFile(filepath.Join(j.root, nodeName, "ready"))
	if err != nil {
		return nil, err
	}
	declaration := swarmruntime.ServiceSpec{Name: name, Image: image, Env: map[string]string{"PORT": swarmruntime.TaskPortEnv},
		Args: []string{"sh", "-c", "wget -q -O /tmp/lifecycle http://127.0.0.1:19090/binary && chmod +x /tmp/lifecycle && exec /tmp/lifecycle serve"},
		Port: uint32(port), ReadyPath: "/ready", Replicas: replicas}
	if owner {
		declaration.Env = map[string]string{"PORT": strconv.Itoa(port)}
		declaration.Mounts = []swarmruntime.ServiceMount{{Source: "/var/lib/ts-data/c18", Target: "/tmp"}}
		declaration.Args = []string{"/tmp/lifecycle", "serve"}
	}
	spec, err := declaration.SwarmSpec()
	if err != nil {
		return nil, err
	}
	spec.Task.Placement = &api.Placement{Constraints: []string{"node.id==" + string(nodeID)}}
	service, err := j.control.CreateService(j.ctx, &api.CreateServiceRequest{Spec: spec})
	if err != nil {
		return nil, err
	}
	runtime, err := containerd.New(filepath.Join(j.root, nodeName, "containerd.sock"))
	if err != nil {
		return nil, err
	}
	var result []*workload
	err = until(j.ctx, func() error {
		var err error
		result, err = j.running(service.Service.ID, host, port, runtime)
		if err != nil {
			return err
		}
		if len(result) != int(replicas) {
			return errors.New("waiting for all replicas")
		}
		return nil
	})
	if err != nil {
		runtime.Close()
		return nil, err
	}
	j.workloads = append(j.workloads, result...)
	return result, nil
}

func (j *journey) replacement(w *workload) (*workload, error) {
	var replacement *workload
	err := until(j.ctx, func() error {
		original, err := j.control.GetTask(j.ctx, &api.GetTaskRequest{TaskID: w.task.ID})
		if err != nil {
			return err
		}
		if original.Task.Status.State != api.TaskStateFailed || !strings.Contains(original.Task.Status.Err, "consecutive readiness probes") {
			return errors.New("waiting for readiness replacement")
		}
		tasks, err := j.running(w.task.ServiceID, w.host, 0, w.runtime)
		if err != nil {
			return err
		}
		if len(tasks) != 1 || tasks[0].task.ID == w.task.ID || tasks[0].process.Pid() == w.process.Pid() {
			return errors.New("expected one distinct replacement process")
		}
		status, err := w.process.Status(namespaces.WithNamespace(j.ctx, "terrascale"))
		if err != nil && !errdefs.IsNotFound(err) {
			return err
		}
		if err == nil && status.Status != containerd.Stopped {
			return errors.New("replaced original process survives")
		}
		replacement = tasks[0]
		return nil
	})
	if err == nil {
		delete(j.frozen, w)
		j.workloads = append(j.workloads, replacement)
	}
	return replacement, err
}

func run(ctx context.Context, root, image string) error {
	started := time.Now()
	defer func() { fmt.Printf("lifecycle lane runtime: %s\n", time.Since(started).Round(time.Second)) }()
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
	control, conn, err := swarmruntime.DialSingleHost(filepath.Join(root, "c18a"))
	if err != nil {
		return err
	}
	defer conn.Close()
	j := &journey{ctx: ctx, root: root, control: control, frozen: make(map[*workload]bool)}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for w := range j.frozen {
			_ = w.process.Kill(namespaces.WithNamespace(cleanup, "terrascale"), syscall.SIGCONT, containerd.WithKillAll)
		}
		for _, w := range j.workloads {
			_ = w.runtime.Close()
		}
	}()
	ownerSet, err := j.create(image, "c18-data", "10.231.0.2", 18083, true, 1)
	if err != nil {
		return err
	}
	firstSet, err := j.create(image, "c18-first", "10.231.0.2", 18084, false, 1)
	if err != nil {
		return err
	}
	secondSet, err := j.create(image, "c18-second", "10.231.0.2", 18085, false, 1)
	if err != nil {
		return err
	}
	twins, err := j.create(image, "c18-twins", "10.231.0.3", 18086, false, 2)
	if err != nil {
		return err
	}
	owner, first, second := ownerSet[0], firstSet[0], secondSet[0]
	for _, action := range []string{"/agent-stop", "/agent-start"} {
		for _, address := range []string{"10.231.0.2:19090", "10.231.0.3:19090"} {
			if err := agentAction(ctx, address, action); err != nil {
				return err
			}
		}
		if err := j.processesRetained(j.workloads...); err != nil {
			return err
		}
		for _, w := range j.workloads {
			if err := request(ctx, w.address, "/ready", http.StatusOK); err != nil {
				return err
			}
		}
	}
	fmt.Printf("agent stop/start retained PIDs %d %d %d %d %d; all served while stopped and after start\n", owner.process.Pid(), first.process.Pid(), second.process.Pid(), twins[0].process.Pid(), twins[1].process.Pid())
	if err := j.freeze(first, second); err != nil {
		return err
	}
	if err := j.reported("not replaced: correlated with 1 other tasks", map[*workload]int{}, first, second); err != nil {
		return err
	}
	if err := j.retained(owner); err != nil {
		return err
	}
	fmt.Printf("two correlated frozen tasks reported once; PIDs %d %d survived; witness PID %d survived\n", first.process.Pid(), second.process.Pid(), owner.process.Pid())
	if err := j.recover(first, second); err != nil {
		return err
	}
	for _, w := range []*workload{first, second} {
		count, err := j.logCount(w, "task readiness unresponsive window cleared")
		if err != nil || count != 1 {
			return fmt.Errorf("correlation clear count %d: %w", count, err)
		}
	}
	fmt.Printf("correlated tasks recovered and cleared once; same PIDs %d %d\n", first.process.Pid(), second.process.Pid())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://10.231.0.3:18086/ready", nil)
	if err != nil {
		return err
	}
	response, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		return err
	}
	var sibling, healthy *workload
	for _, w := range twins {
		if string(body) == strings.Split(w.address, ":")[1] {
			sibling = w
		} else {
			healthy = w
		}
	}
	if sibling == nil || healthy == nil {
		return fmt.Errorf("shared port answered unknown PID %s", body)
	}
	container, err := healthy.runtime.LoadContainer(namespaces.WithNamespace(ctx, "terrascale"), "ts-"+healthy.task.ID)
	if err != nil {
		return err
	}
	labels, err := container.Labels(namespaces.WithNamespace(ctx, "terrascale"))
	if err != nil {
		return err
	}
	ownPort := labels["terrascale.ports"]
	if _, err := container.SetLabels(namespaces.WithNamespace(ctx, "terrascale"), map[string]string{"terrascale.ports": "unreadable"}); err != nil {
		return err
	}
	if err := j.freeze(sibling, owner, first, second); err != nil {
		return err
	}
	if err := j.reported("not replaced: no witness answered", map[*workload]int{}, first, second, sibling); err != nil {
		return err
	}
	if err := j.reported("not replaced: data owner", map[*workload]int{}, owner); err != nil {
		return err
	}
	lastGauge := 0.0
	if err := until(ctx, func() error {
		if err := j.retained(owner, first, second, healthy, sibling); err != nil {
			return err
		}
		value, err := j.metric(owner, "task_unresponsive_seconds")
		if err != nil {
			return err
		}
		if value < lastGauge {
			return fmt.Errorf("data-owner gauge regressed from %g to %g", lastGauge, value)
		}
		lastGauge = value
		if value < (6 * time.Minute).Seconds() {
			return errors.New("waiting for six minutes of retained data-owner telemetry")
		}
		return nil
	}); err != nil {
		return err
	}
	missing, err := j.metric(healthy, "task_readiness_unobserved_total")
	if err != nil || missing < 2 {
		return fmt.Errorf("unobserved counter %g: %w", missing, err)
	}
	count, err := j.logCount(healthy, "task readiness not observed: exact task endpoint unavailable")
	if err != nil || count != 1 {
		return fmt.Errorf("unobserved log count %d: %w", count, err)
	}
	if err := request(ctx, healthy.address, "/ready", http.StatusOK); err != nil {
		return err
	}
	fmt.Printf("no witness: all frozen tasks reported, PIDs %d %d %d retained; data owner reported, PID %d retained, rising gauge %.0f seconds\n", first.process.Pid(), second.process.Pid(), sibling.process.Pid(), owner.process.Pid(), lastGauge)
	fmt.Printf("unreadable task port: healthy PID %d survived beside frozen shared-port sibling PID %d; %.0f unobserved rounds, one log\n", healthy.process.Pid(), sibling.process.Pid(), missing)
	if _, err := container.SetLabels(namespaces.WithNamespace(ctx, "terrascale"), map[string]string{"terrascale.ports": ownPort}); err != nil {
		return err
	}
	if err := j.recover(owner, first, second, sibling); err != nil {
		return err
	}
	if err := j.retained(healthy); err != nil {
		return err
	}
	fmt.Printf("all recovered and gauges cleared; same PIDs %d %d %d %d %d\n", owner.process.Pid(), first.process.Pid(), second.process.Pid(), sibling.process.Pid(), healthy.process.Pid())
	if err := j.freeze(first); err != nil {
		return err
	}
	replacement, err := j.replacement(first)
	if err != nil {
		return err
	}
	if err := j.retained(owner, second, healthy, sibling); err != nil {
		return err
	}
	fmt.Printf("one frozen task with witnesses replaced once: PID %d stopped, new PID %d; witness PIDs %d %d retained\n", first.process.Pid(), replacement.process.Pid(), owner.process.Pid(), second.process.Pid())
	budgetData, err := os.ReadFile(filepath.Join(root, "c18a", "containerd.sock.readiness-replacement"))
	if err != nil {
		return err
	}
	budgetStart, err := time.Parse(time.RFC3339Nano, string(budgetData))
	if err != nil {
		return err
	}
	if err := j.freeze(second); err != nil {
		return err
	}
	if err := j.reported("not replaced: host replacement budget unavailable", map[*workload]int{}, second); err != nil {
		return err
	}
	if err := j.retained(owner, replacement, healthy, sibling); err != nil {
		return err
	}
	fmt.Printf("second sequential failure held by real 15-minute host budget: PID %d survived past five minutes; first replacement PID %d survived\n", second.process.Pid(), replacement.process.Pid())
	next, err := j.replacement(second)
	if err != nil {
		return err
	}
	nextBudgetData, err := os.ReadFile(filepath.Join(root, "c18a", "containerd.sock.readiness-replacement"))
	if err != nil {
		return err
	}
	nextBudgetStart, err := time.Parse(time.RFC3339Nano, string(nextBudgetData))
	if err != nil {
		return err
	}
	if nextBudgetStart.Sub(budgetStart) < 15*time.Minute {
		return errors.New("host replaced twice inside real 15-minute budget")
	}
	if err := j.retained(owner, replacement, healthy, sibling); err != nil {
		return err
	}
	all, err := control.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{first.task.ServiceID, second.task.ServiceID}}})
	if err != nil {
		return err
	}
	if len(all.Tasks) != 4 {
		return fmt.Errorf("expected exactly two original tasks and two replacements, got %d", len(all.Tasks))
	}
	fmt.Printf("budget released after %s: second PID %d stopped, new PID %d; first replacement PID %d and data owner PID %d survived\n", nextBudgetStart.Sub(budgetStart).Round(time.Second), second.process.Pid(), next.process.Pid(), replacement.process.Pid(), owner.process.Pid())
	return nil
}
