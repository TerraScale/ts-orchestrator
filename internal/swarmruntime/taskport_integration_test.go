package swarmruntime

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/moby/swarmkit/v2/api"
)

// A slow-starting service (ts-auth binds ~3 s after start) moves from binding
// its port itself to ${PORT}, then updates twice; a 1 s-timeout probe of the
// service port every 20 ms must never fail across the ${PORT} updates.
func containerdTaskPortUpdateServesThroughout(t *testing.T, ctx context.Context, e *Executor, client api.ControlClient) {
	t.Run("task port update serves throughout", func(t *testing.T) {
		listener, err := net.Listen("tcp", ":0")
		if err != nil {
			t.Fatal(err)
		}
		port := uint32(listener.Addr().(*net.TCPAddr).Port)
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
		const name = "task-port-update"
		spec := func(version string, taskPort bool) ServiceSpec {
			listen := fmt.Sprint(port)
			if taskPort {
				listen = TaskPortEnv
			}
			return ServiceSpec{Name: name, Image: integrationImage, Port: port, Replicas: 1, ReadyPath: "/readyz",
				Env: map[string]string{"LISTEN": listen,
					"HANDLER": `read -r line; printf 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n` + version + `'`},
				Args: []string{"/bin/sh", "-c", `trap 'kill $! 2>/dev/null; exit 0' TERM; sleep 3; nc -lk -p "$LISTEN" -e /bin/sh -c "$HANDLER" & wait`}}
		}
		var serviceID string
		t.Cleanup(func() {
			cleanup, stop := context.WithTimeout(context.Background(), time.Minute)
			defer stop()
			if err := RemoveServiceSpec(cleanup, client, name); err != nil {
				t.Error(err)
			}
			waitRuntime(t, cleanup, func() (bool, error) {
				containers, err := e.client.Containers(runtimeContext(cleanup), fmt.Sprintf(`labels."terrascale.service"==%q`, serviceID))
				return len(containers) == 0, err
			})
		})
		apply := func(version string, taskPort bool) {
			t.Helper()
			service, err := ApplyServiceSpec(ctx, client, spec(version, taskPort))
			if err != nil {
				t.Fatal(err)
			}
			serviceID = service.ID
			if _, err := WaitServiceSpec(ctx, client, service, ProbeLocalTask); err != nil {
				t.Fatal(err)
			}
		}
		apply("v1", false)

		var mu sync.Mutex
		failures := 0
		probing, stopProbing := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() {
			defer close(done)
			for probing.Err() == nil {
				if getBody(port) == "" {
					mu.Lock()
					failures++
					mu.Unlock()
				}
				time.Sleep(20 * time.Millisecond)
			}
		}()
		count := func() int {
			mu.Lock()
			defer mu.Unlock()
			n := failures
			failures = 0
			return n
		}
		apply("v2", true)
		// The self-bound v1 frees the port at SIGTERM; the forwarder takes it within bindRetry.
		t.Logf("v1 (self-bound) -> v2 (${PORT}): %d failed probes", count())
		for _, version := range []string{"v3", "v4"} {
			apply(version, true)
			if body := getBody(port); body != version {
				t.Fatalf("updated task serves %q, want %s", body, version)
			}
			if n := count(); n != 0 {
				t.Fatalf("update to %s: %d probes failed, want 0", version, n)
			}
		}
		stopProbing()
		<-done
	})
}
