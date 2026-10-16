package swarmruntime

import (
	"context"
	"fmt"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/containerd/errdefs"
	"github.com/moby/swarmkit/v2/api"
)

// This scenario crosses the embedded manager, agent, containerd, runc and
// application HTTP boundaries; no test executor substitutes for the runtime.
func TestRuntimeServiceSurvivesNodeRestart(t *testing.T) {
	if *integrationSocket == "" {
		t.Fatal("provide -containerd-socket for a disposable real runtime")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	state := t.TempDir()
	cfg := nodeFixtureConfig(t, "founder", "manager")
	cfg.Admission.Region = "gru"
	e, err := NewExecutor(*integrationSocket, state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	node, err := StartNode(ctx, cfg, e)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nodeFixtureStop(t, node) })
	client, err := node.ControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AdmitNode(ctx, client, node.ID(), cfg.Admission); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint32(listener.Addr().(*net.TCPAddr).Port)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	command := fmt.Sprintf("exec nc -lk -p %d -e /bin/sh -c \"printf 'HTTP/1.1 200 OK\\r\\nContent-Length: 5\\r\\nConnection: close\\r\\n\\r\\nready'\"", port)
	service, err := applyService(ctx, client, ServiceIntent{
		ID: entityid.Derive("integration", "runtime-restart"), Role: "smoke", Region: "gru", Environment: "integration", Architecture: runtime.GOARCH, Replicas: 1,
		Container: &api.ContainerSpec{Image: integrationImage, User: "65532:65532", Command: []string{"/bin/sh", "-c", command}},
		Resources: &api.ResourceRequirements{Limits: &api.Resources{NanoCPUs: 250_000_000, MemoryBytes: 64 << 20}},
		Ports:     []*api.PortConfig{{Name: "ready", Protocol: api.ProtocolTCP, PublishMode: api.PublishModeHost, TargetPort: port, PublishedPort: port}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		_, _ = client.RemoveService(cleanup, &api.RemoveServiceRequest{ServiceID: service.ID})
	})
	url := "http://127.0.0.1:" + strconv.Itoa(int(port)) + "/readyz"
	httpClient := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	defer httpClient.CloseIdleConnections()
	probe := func(ctx context.Context, _ *api.Task) error {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		response, err := httpClient.Do(request)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 32))
		if err != nil || response.StatusCode != http.StatusOK || string(body) != "ready" {
			return fmt.Errorf("application readiness: status=%d body=%q err=%v", response.StatusCode, body, err)
		}
		return nil
	}
	var taskID string
	waitRuntime(t, ctx, func() (bool, error) {
		view, err := ObserveService(ctx, client, service.ID, probe)
		if err != nil || view.ReadyReplicas != 1 {
			return false, err
		}
		for _, task := range view.Tasks {
			if task.Ready {
				taskID = task.TaskID
			}
		}
		return taskID != "", nil
	})
	scheduled, err := client.GetTask(ctx, &api.GetTaskRequest{TaskID: taskID})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		runtime, err := NewExecutor(*integrationSocket, state)
		if err != nil {
			t.Error(err)
			return
		}
		defer runtime.Close()
		controller, err := runtime.Controller(scheduled.Task)
		if err == nil {
			err = controller.Remove(cleanup)
		}
		if err != nil {
			t.Error(err)
		}
	})
	container, err := e.client.LoadContainer(runtimeContext(ctx), "ts-"+taskID)
	if err != nil {
		t.Fatal(err)
	}
	task, err := container.Task(runtimeContext(ctx), nil)
	if err != nil {
		t.Fatal(err)
	}
	pid := task.Pid()
	nodeID := node.ID()
	nodeFixtureStop(t, node)
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if err := probe(ctx, nil); err != nil {
		t.Fatalf("application stopped with embedded manager/agent: %v", err)
	}
	e, err = NewExecutor(*integrationSocket, state)
	if err != nil {
		t.Fatal(err)
	}
	node, err = StartNode(ctx, cfg, e)
	if err != nil {
		t.Fatal(err)
	}
	if node.ID() != nodeID {
		t.Fatalf("node identity changed: %s -> %s", nodeID, node.ID())
	}
	client, err = node.ControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	waitRuntime(t, ctx, func() (bool, error) {
		view, err := ObserveService(ctx, client, service.ID, probe)
		if err != nil || view.ReadyReplicas != 1 {
			return false, err
		}
		for _, observed := range view.Tasks {
			if observed.Ready && observed.TaskID != taskID {
				return false, fmt.Errorf("restart replaced task %s with %s", taskID, observed.TaskID)
			}
		}
		return true, nil
	})
	container, err = e.client.LoadContainer(runtimeContext(ctx), "ts-"+taskID)
	if err != nil {
		t.Fatal(err)
	}
	task, err = container.Task(runtimeContext(ctx), nil)
	if err != nil || task.Pid() != pid {
		t.Fatalf("restart duplicated container process: pid=%v err=%v", task, err)
	}
	if _, err := client.RemoveService(ctx, &api.RemoveServiceRequest{ServiceID: service.ID}); err != nil {
		t.Fatal(err)
	}
	waitRuntime(t, ctx, func() (bool, error) {
		_, err := e.client.LoadContainer(runtimeContext(ctx), "ts-"+taskID)
		return errdefs.IsNotFound(err), nil
	})
	t.Logf("real service %s retained task %s pid %d across node restart; state=%s", service.ID, taskID, pid, filepath.Base(cfg.StateDir))
}

func waitRuntime(t *testing.T, ctx context.Context, condition func() (bool, error)) {
	t.Helper()
	var last error
	for {
		ready, err := condition()
		if ready {
			return
		}
		last = err
		select {
		case <-ctx.Done():
			t.Fatalf("runtime convergence: %v (last error: %s)", ctx.Err(), strings.TrimSpace(fmt.Sprint(last)))
		case <-time.After(100 * time.Millisecond):
		}
	}
}
