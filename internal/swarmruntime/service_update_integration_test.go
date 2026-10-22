package swarmruntime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/moby/swarmkit/v2/api"
)

// `service apply` of a new spec on a live host port must replace the task,
// not reject the replacement on its predecessor's retained reservation.
// It logs each phase and the longest window in which the port refused HTTP.
func TestContainerdServiceUpdateOnLivePort(t *testing.T) {
	if *integrationSocket == "" {
		t.Skip("runs in the containerd workflow, which passes -containerd-socket")
	}
	// Not t.Context(): the node must outlive the test body so cleanup can remove its containers.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)
	state := t.TempDir()
	// The fixture binds container material; a bare single host has none yet.
	e, err := newIntegrationExecutor(*integrationSocket, state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	node, err := StartSingleHost(ctx, state, e)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nodeFixtureStop(t, node) })
	client, conn, err := DialSingleHost(state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint32(listener.Addr().(*net.TCPAddr).Port)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	// v1's sh (PID 1) ignores SIGTERM and runs until the grace SIGKILL; later
	// versions trap it and exit at once, like a well-behaved service.
	spec := func(version string) ServiceSpec {
		trap := `trap 'kill $! 2>/dev/null; exit 0' TERM; `
		if version == "v1" {
			trap = ""
		}
		return ServiceSpec{Name: "update-live-port", Image: integrationImage, Port: port, Replicas: 1,
			Env:  map[string]string{"HANDLER": `read -r line; printf 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n` + version + `'`},
			Args: []string{"/bin/sh", "-c", trap + fmt.Sprintf(`nc -lk -p %d -e /bin/sh -c "$HANDLER" & wait`, port)}}
	}
	apply := func(version string) (*api.Service, time.Duration, ServiceRollout) {
		t.Helper()
		start := time.Now()
		if err := e.PrePull(ctx, integrationImage); err != nil {
			t.Fatal(err)
		}
		pulled := time.Since(start)
		service, err := ApplyServiceSpec(ctx, client, spec(version))
		if err != nil {
			t.Fatal(err)
		}
		rollout, err := WaitServiceSpec(ctx, client, service, ProbeLocalTask)
		if err != nil {
			t.Fatal(err)
		}
		return service, pulled, rollout
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Minute)
		defer stop()
		if err := RemoveServiceSpec(cleanup, client, "update-live-port"); err != nil {
			t.Error(err)
		}
		// Remove every container before the node stops, or a shim outlives the test.
		waitRuntime(t, cleanup, func() (bool, error) {
			containers, err := e.client.Containers(runtimeContext(cleanup), fmt.Sprintf(`labels."terrascale.ports"=="%d"`, port))
			return len(containers) == 0, err
		})
	})

	service, pulled, created := apply("v1")
	t.Logf("create (cold): pulled %s, running %s, ready %s", pulled, created.Running, created.Ready)
	if body := getBody(port); body != "v1" {
		t.Fatalf("first task serves %q", body)
	}

	var mu sync.Mutex
	var down, longest time.Duration
	var downSince time.Time
	first, last := map[string]time.Time{}, map[string]time.Time{}
	probing, stopProbing := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for probing.Err() == nil {
			body := getBody(port)
			now := time.Now()
			mu.Lock()
			if body == "" && downSince.IsZero() {
				downSince = now
			}
			if body != "" {
				if first[body].IsZero() {
					first[body] = now
				}
				last[body] = now
				if !downSince.IsZero() {
					gap := now.Sub(downSince)
					down += gap
					longest = max(longest, gap)
					downSince = time.Time{}
				}
			}
			mu.Unlock()
			time.Sleep(20 * time.Millisecond)
		}
	}()
	previous := "v1"
	for _, version := range []string{"v2", "v3"} {
		start := time.Now()
		_, pulled, updated := apply(version)
		if body := getBody(port); body != version {
			t.Fatalf("updated task serves %q, want %s", body, version)
		}
		mu.Lock()
		t.Logf("update %s->%s (warm): pulled %s, running %s, ready %s; old served until %s, new served from %s",
			previous, version, pulled, updated.Running, updated.Ready, last[previous].Sub(start), first[version].Sub(start))
		mu.Unlock()
		previous = version
	}
	stopProbing()
	<-done
	t.Logf("port refused HTTP for %s in total, longest window %s", down, longest)

	listed, err := client.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{service.ID}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, task := range listed.Tasks {
		if task.Status.State == api.TaskStateRejected || task.Status.State == api.TaskStateFailed {
			t.Fatalf("task %s %s: %s", task.ID, task.Status.State, task.Status.Err)
		}
	}
	// Retained, exited predecessors keep their containers but no longer the port.
	containers, err := e.client.Containers(runtimeContext(ctx), fmt.Sprintf(`labels."terrascale.ports"=="%d"`, port))
	if err != nil {
		t.Fatal(err)
	}
	live := 0
	for _, container := range containers {
		if holder, err := portHolderState(runtimeContext(ctx), container); err != nil {
			t.Fatal(err)
		} else if holder != holderExited {
			live++
		}
	}
	if len(containers) < 2 || live != 1 {
		t.Fatalf("want retained exited predecessors and one live holder, got %d containers, %d live", len(containers), live)
	}

	// A spec whose task never answers its readyPath rolls back; the previous spec serves again.
	t.Run("never ready rolls back", func(t *testing.T) {
		bad := spec("v4")
		bad.ReadyPath, bad.ReadyTimeoutSeconds = "/readyz", 3
		bad.Env["HANDLER"] = `read -r line; printf 'HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'`
		start := time.Now()
		updated, err := ApplyServiceSpec(ctx, client, bad)
		if err != nil {
			t.Fatal(err)
		}
		_, err = WaitServiceSpec(ctx, client, updated, nil)
		var rollback *RollbackError
		if !errors.As(err, &rollback) {
			t.Fatalf("want a rollback, got %v", err)
		}
		t.Logf("rolled back in %s: %v", time.Since(start), err)
		if !strings.Contains(rollback.Reason, "not ready within 3s") {
			t.Errorf("rollback reason %q does not name the readiness timeout", rollback.Reason)
		}
		if body := getBody(port); body != "v3" {
			t.Fatalf("after rollback the port serves %q, want v3", body)
		}
	})

	containerdCrashLoops(t, ctx, e, client)
}

func getBody(port uint32) string {
	client := http.Client{Timeout: time.Second}
	response, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
	if err != nil {
		return ""
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	return string(body)
}
