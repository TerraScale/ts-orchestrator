package swarmruntime

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/moby/swarmkit/v2/api"
)

// containerdDataTaskStopsGracefully runs inside TestContainerdServiceUpdateOnLivePort
// (the containerd workflow's allowlist): a task with a bind mount that needs 30s
// to flush after SIGTERM exits by itself, and its replacement waits for it.
func containerdDataTaskStopsGracefully(t *testing.T, ctx context.Context, e *Executor, client api.ControlClient) {
	t.Run("data task gets its SIGTERM grace", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := uint32(listener.Addr().(*net.TCPAddr).Port)
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
		source := filepath.Join(DataRoot, fmt.Sprintf("integration-stop-%d", time.Now().UnixNano()))
		spec := func(version string) ServiceSpec {
			// On SIGTERM: 30s of "flushing", then a clean exit 0; SIGKILL would show 137.
			script := fmt.Sprintf(`trap 'kill $! 2>/dev/null; sleep 30; echo %s > /data/flushed; exit 0' TERM; nc -lk -p %d -e /bin/sh -c "$HANDLER" & wait; wait`, version, port)
			return ServiceSpec{Name: "data-stop", Image: integrationImage, Port: port, Replicas: 1,
				Mounts: []ServiceMount{{Source: source, Target: "/data"}},
				Env:    map[string]string{"HANDLER": `read -r line; printf 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n` + version + `'`},
				Args:   []string{"/bin/sh", "-c", script}}
		}
		t.Cleanup(func() {
			cleanup, stop := context.WithTimeout(context.Background(), 3*time.Minute)
			defer stop()
			if err := RemoveServiceSpec(cleanup, client, "data-stop"); err != nil {
				t.Error(err)
			}
			waitRuntime(t, cleanup, func() (bool, error) {
				containers, err := e.client.Containers(runtimeContext(cleanup), fmt.Sprintf(`labels."terrascale.ports"=="%d"`, port))
				return len(containers) == 0, err
			})
		})
		first, err := ApplyServiceSpec(ctx, client, spec("v1"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := WaitServiceSpec(ctx, client, first, ProbeLocalTask); err != nil {
			t.Fatal(err)
		}
		listed, err := client.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{first.ID}}})
		if err != nil || len(listed.Tasks) != 1 {
			t.Fatalf("tasks %v, %v", listed, err)
		}
		old := listed.Tasks[0].ID
		start := time.Now()
		second, err := ApplyServiceSpec(ctx, client, spec("v2"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := WaitServiceSpec(ctx, client, second, ProbeLocalTask); err != nil {
			t.Fatal(err)
		}
		swapped := time.Since(start)
		ctr, err := e.client.LoadContainer(runtimeContext(ctx), "ts-"+old)
		if err != nil {
			t.Fatal(err)
		}
		task, err := ctr.Task(runtimeContext(ctx), nil)
		if err != nil {
			t.Fatal(err)
		}
		status, err := task.Status(runtimeContext(ctx))
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("v1 exited with status %d; v2 served after %s", status.ExitStatus, swapped)
		if status.ExitStatus != 0 || swapped < 30*time.Second {
			t.Fatalf("v1 must flush for 30s and exit 0 before v2 starts: status %d after %s", status.ExitStatus, swapped)
		}
		if body := getBody(port); body != "v2" {
			t.Fatalf("port serves %q, want v2", body)
		}
	})
}
