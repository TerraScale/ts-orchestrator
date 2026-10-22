package swarmruntime

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/moby/swarmkit/v2/api"
)

// A replacement task must read what its predecessor wrote under DataRoot as the same non-root user.
// The target is absent from the image: runc creates it in the read-only root.
func TestContainerdBindMountSurvivesTaskRestart(t *testing.T) {
	if *integrationSocket == "" {
		t.Skip("runs in the containerd workflow, which passes -containerd-socket")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	e, err := newIntegrationExecutor(*integrationSocket, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	source := filepath.Join(DataRoot, fmt.Sprintf("integration-%d", time.Now().UnixNano()))
	t.Cleanup(func() { _ = os.RemoveAll(source) })
	run := func(name, script string) {
		t.Helper()
		runtime, err := ContainerRuntime(&api.ContainerSpec{Image: integrationImage, User: "65532:65532", Command: []string{"/bin/sh", "-c", script},
			Mounts: []api.Mount{{Type: api.MountTypeBind, Source: source, Target: "/data"}}})
		if err != nil {
			t.Fatal(err)
		}
		task := &api.Task{ID: fmt.Sprintf("%s%d", name, time.Now().UnixNano()), ServiceID: "mountintegration", Spec: api.TaskSpec{Runtime: runtime, Resources: containerTestResources(250_000_000, 64<<20)}}
		c, err := integrationContainerController(e, task)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
			defer stop()
			if err := c.Remove(cleanup); err != nil {
				t.Error(err)
			}
		}()
		if err := c.Prepare(ctx); err != nil {
			t.Fatal(err)
		}
		if err := c.Start(ctx); err != nil {
			t.Fatal(err)
		}
		if err := c.Wait(ctx); err != nil {
			t.Fatalf("%s task: %v", name, err)
		}
	}
	run("writer", `set -eu; test "$(id -u)" = 65532; printf persisted > /data/value`)
	run("reader", `set -eu; test "$(cat /data/value)" = persisted; printf again >> /data/value; touch /tmp/scratch`)
	// Without the host resolv.conf the image's empty /etc falls back to [::1]:53 and fails.
	run("resolver", `set -eu; test -s /etc/resolv.conf; grep -q localhost /etc/hosts; nslookup github.com`)
	data, err := os.ReadFile(filepath.Join(source, "value"))
	if err != nil || string(data) != "persistedagain" {
		t.Fatalf("host data = %q, %v", data, err)
	}
	info, err := os.Stat(source)
	if err != nil {
		t.Fatal(err)
	}
	if st := info.Sys().(*syscall.Stat_t); st.Uid != 65532 || st.Gid != 65532 {
		t.Fatalf("bind source owned by %d:%d, want container user", st.Uid, st.Gid)
	}
}

// An image that serves only /healthz becomes ready once its service names that path.
func TestContainerdReadinessUsesServicePath(t *testing.T) {
	if *integrationSocket == "" {
		t.Skip("runs in the containerd workflow, which passes -containerd-socket")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	cfg := nodeFixtureConfig(t, "founder", "manager")
	cfg.Admission.Region = "sa-saopaulo-1"
	e, err := newIntegrationExecutor(*integrationSocket, t.TempDir())
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
	handler := `read -r method target version; if [ "$target" = /healthz ]; then printf 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok'; else printf 'HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'; fi`
	container := &api.ContainerSpec{Image: integrationImage, User: "65532:65532", Labels: map[string]string{LabelReadyPath: "/healthz"},
		Command: []string{"nc", "-lk", "-p", fmt.Sprint(port), "-e", "/bin/sh", "-c", handler}}
	service, err := applyService(ctx, client, ServiceIntent{
		ID: entityid.Derive("integration", "readiness-path"), Role: "smoke", Region: "sa-saopaulo-1", Environment: "integration", Architecture: runtime.GOARCH, Replicas: 1,
		Container: container,
		Resources: containerTestResources(250_000_000, 64<<20),
		Ports:     []*api.PortConfig{{Name: "http", Protocol: api.ProtocolTCP, PublishMode: api.PublishModeHost, TargetPort: port, PublishedPort: port}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var ready *api.Task
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		_, _ = client.RemoveService(cleanup, &api.RemoveServiceRequest{ServiceID: service.ID})
		// Remove the container before the node stops, or its shim outlives the test.
		if ready != nil {
			if c, err := e.Controller(ready); err != nil {
				t.Error(err)
			} else if err := c.Remove(cleanup); err != nil {
				t.Error(err)
			}
		}
	})
	waitRuntime(t, ctx, func() (bool, error) {
		view, err := ObserveService(ctx, client, service.ID, ProbeLocalTask)
		if err != nil || view.ReadyReplicas != 1 {
			return false, err
		}
		for _, observed := range view.Tasks {
			if observed.Ready {
				response, err := client.GetTask(ctx, &api.GetTaskRequest{TaskID: observed.TaskID})
				if err != nil {
					return false, err
				}
				ready = response.Task
			}
		}
		return ready != nil, nil
	})
	// The same running task probed at the default path is refused by this image.
	container.Labels = nil
	defaultPath, err := ContainerRuntime(container)
	if err != nil {
		t.Fatal(err)
	}
	probed := ready.Copy()
	probed.Spec.Runtime = defaultPath
	if err := ProbeLocalTask(ctx, probed); err == nil {
		t.Fatal("image without /readyz was ready at the default path")
	}
}
