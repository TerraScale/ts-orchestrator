package swarmruntime

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
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
				// Like Kestrel, it drains for a second after SIGTERM before it exits. The
				// executor signals every process, so nc and its handlers ignore TERM.
				Args: []string{"/bin/sh", "-c", `sleep 3; (trap '' TERM; exec nc -lk -p "$LISTEN" -e /bin/sh -c "$HANDLER") & trap 'sleep 1; kill -KILL $! 2>/dev/null; exit 0' TERM; wait`}}
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
		// The node offers the scheduler its free disk plus the running task's
		// 10 GiB budget, which the scheduler subtracts again.
		free, freeErr := e.diskCapacity(ctx)
		offer, offerErr := e.schedulableDisk(ctx)
		if freeErr != nil || offerErr != nil || offer < free+(10<<30)-(1<<30) {
			t.Fatalf("disk offer %d with %d free: %v %v", offer, free, freeErr, offerErr)
		}

		var mu sync.Mutex
		var failures []string
		start := time.Now()
		probing, stopProbing := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() {
			defer close(done)
			for probing.Err() == nil {
				client := http.Client{Timeout: time.Second}
				sent := time.Since(start)
				response, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
				var body []byte
				if err == nil {
					body, err = io.ReadAll(response.Body)
					response.Body.Close()
				}
				if err != nil || len(body) == 0 {
					mu.Lock()
					failures = append(failures, fmt.Sprintf("at %s (%s): %v", sent.Round(time.Millisecond), start.Add(sent).Format("15:04:05.000"), err))
					mu.Unlock()
				}
				time.Sleep(20 * time.Millisecond)
			}
		}()
		count := func() []string {
			mu.Lock()
			defer mu.Unlock()
			n := failures
			failures = nil
			return n
		}
		apply("v2", true)
		// The self-bound v1 drains for a second after SIGTERM, then frees the port;
		// the forwarder takes it within bindRetry (the edge holds dials meanwhile).
		time.Sleep(3 * time.Second)
		t.Logf("v1 (self-bound) -> v2 (${PORT}): failed probes %v", count())
		for _, version := range []string{"v3", "v4"} {
			t.Logf("update to %s from %s", version, time.Since(start).Round(time.Millisecond))
			apply(version, true)
			if body := getBody(port); body != version {
				t.Fatalf("updated task serves %q, want %s", body, version)
			}
			if n := count(); !servedThroughout(n) {
				t.Fatalf("update to %s: probes failed %v", version, n)
			}
		}
		// A concurrent re-apply of the same workload (the mesh stamps a new
		// generation) mid-update must not fail the first apply's wait.
		first, err := ApplyServiceSpec(ctx, client, spec("v5", true))
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Second)
		again := spec("v5", true)
		again.Generation = time.Now().UnixNano()
		if _, err := ApplyServiceSpec(ctx, client, again); err != nil {
			t.Fatal(err)
		}
		if _, err := WaitServiceSpec(ctx, client, first, ProbeLocalTask); err != nil {
			t.Fatalf("wait across a same-workload re-apply: %v", err)
		}
		if n := count(); !servedThroughout(n) {
			t.Fatalf("update to v5: probes failed %v", n)
		}
		stopProbing()
		<-done
	})
}

// servedThroughout allows no refused dial (the service port closed or had no
// ready task) and one other failure: busybox nc, serving one connection at a
// time, rarely drops one with no forwarder change around it (measured locally).
func servedThroughout(failures []string) bool {
	return len(failures) <= 1 && !slices.ContainsFunc(failures, func(f string) bool { return strings.Contains(f, "connection refused") })
}

// Adding regions or a ready timeout to a spec changes only labels: SwarmKit
// keeps the running task, and the exact readiness wait must accept it as the
// new generation instead of failing the rollout (gru's ts-auth, 2026-10-24).
func containerdLabelOnlyChangeKeepsTask(t *testing.T, ctx context.Context, e *Executor, client api.ControlClient) {
	t.Run("label-only change keeps its task", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := uint32(listener.Addr().(*net.TCPAddr).Port)
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
		spec := ServiceSpec{Name: "label-only", Image: integrationImage, Port: port, Replicas: 1, ReadyPath: "/readyz", Generation: 1,
			Env:  map[string]string{"HANDLER": `read -r line; printf 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok'`},
			Args: []string{"/bin/sh", "-c", fmt.Sprintf(`trap 'kill $! 2>/dev/null; exit 0' TERM; nc -lk -p %d -e /bin/sh -c "$HANDLER" & wait`, port)}}
		t.Cleanup(func() {
			cleanup, stop := context.WithTimeout(context.Background(), time.Minute)
			defer stop()
			if err := RemoveServiceSpec(cleanup, client, spec.Name); err != nil {
				t.Error(err)
			}
			waitRuntime(t, cleanup, func() (bool, error) {
				containers, err := e.client.Containers(runtimeContext(cleanup), fmt.Sprintf(`labels."terrascale.ports"=="%d"`, port))
				return len(containers) == 0, err
			})
		})
		if _, err := ApplyServiceSpec(ctx, client, spec); err != nil {
			t.Fatal(err)
		}
		first, err := WaitServiceSpecExact(ctx, client, spec)
		if err != nil || len(first.Tasks) != 1 {
			t.Fatalf("first rollout: %+v, %v", first, err)
		}
		spec.Generation, spec.ReadyTimeoutSeconds = 2, 300
		if _, err := ApplyServiceSpec(ctx, client, spec); err != nil {
			t.Fatal(err)
		}
		second, err := WaitServiceSpecExact(ctx, client, spec)
		if err != nil || len(second.Tasks) != 1 || second.Tasks[0].TaskID != first.Tasks[0].TaskID {
			t.Fatalf("label-only rollout: %+v, %v (first task %s)", second, err, first.Tasks[0].TaskID)
		}
	})
}
