package swarmruntime

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/moby/swarmkit/v2/api"
)

func taskExitCode(task *api.Task) int32 {
	if container := task.Status.GetContainer(); container != nil {
		return container.ExitCode
	}
	return -1
}

// containerdCrashLoops runs inside TestContainerdServiceUpdateOnLivePort (the
// containerd workflow's allowlist): a crashing container restarts with growing
// gaps and shows as a crash loop; one over its memory limit reports OOM.
func containerdCrashLoops(t *testing.T, ctx context.Context, e *Executor, client api.ControlClient) {
	failures := func(t *testing.T, spec ServiceSpec, want int, done func(*api.Task) bool) (*api.Service, map[string]*api.Task) {
		t.Helper()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		spec.Port = uint32(listener.Addr().(*net.TCPAddr).Port)
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
		spec.Image, spec.Replicas = integrationImage, 1
		t.Cleanup(func() {
			cleanup, stop := context.WithTimeout(context.Background(), time.Minute)
			defer stop()
			if err := RemoveServiceSpec(cleanup, client, spec.Name); err != nil {
				t.Error(err)
			}
			waitRuntime(t, cleanup, func() (bool, error) {
				containers, err := e.client.Containers(runtimeContext(cleanup), fmt.Sprintf(`labels."terrascale.ports"=="%d"`, spec.Port))
				return len(containers) == 0, err
			})
		})
		service, err := ApplyServiceSpec(ctx, client, spec)
		if err != nil {
			t.Fatal(err)
		}
		failed := map[string]*api.Task{}
		wait, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		waitRuntime(t, wait, func() (bool, error) {
			listed, err := client.ListTasks(wait, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{service.ID}}})
			if err != nil {
				return false, err
			}
			for _, task := range listed.Tasks {
				if task.Status.State == api.TaskStateFailed && done(task) {
					failed[task.ID] = task
				}
			}
			return len(failed) >= want, fmt.Errorf("%d of %d failures", len(failed), want)
		})
		return service, failed
	}

	t.Run("exit 3 restarts with growing backoff", func(t *testing.T) {
		service, failed := failures(t, ServiceSpec{Name: "crash-exit", Args: []string{"/bin/sh", "-c", "exit 3"}}, 4, func(task *api.Task) bool {
			if taskExitCode(task) != 3 || !strings.Contains(task.Status.Err, "status 3") {
				t.Fatalf("task %s: exit %d, error %q", task.ID, taskExitCode(task), task.Status.Err)
			}
			return true
		})
		var times []time.Time
		for _, task := range failed {
			times = append(times, TaskTime(task))
		}
		slices.SortFunc(times, time.Time.Compare)
		var gaps []time.Duration
		for i := 1; i < len(times); i++ {
			gaps = append(gaps, times[i].Sub(times[i-1]).Round(10*time.Millisecond))
		}
		t.Logf("gaps between FAILED exit-3 tasks: %v", gaps)
		if gaps[2] < 3*time.Second || gaps[2] <= gaps[0] {
			t.Fatalf("restart gaps do not grow: %v", gaps)
		}
		rows, err := ServiceTasks(ctx, client, service)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			t.Logf("ps: %s state=%s restarts=%d exit=%d error=%q", row.ID, row.State, row.Restarts, row.Exit, row.Error)
		}
		if rows[0].State != "CRASH-LOOP" || rows[0].Restarts < 3 {
			t.Fatalf("newest row %+v is not a crash loop", rows[0])
		}
	})

	t.Run("memory over memoryMiB is OOM-killed", func(t *testing.T) {
		_, failed := failures(t, ServiceSpec{Name: "crash-oom", MemoryMiB: 16,
			Args: []string{"/bin/sh", "-c", `x=$(head -c 67108864 /dev/zero | tr '\000' a); echo ${#x}`}}, 1, func(*api.Task) bool { return true })
		for _, task := range failed {
			t.Logf("OOM task %s: exit %d, error %q", task.ID, taskExitCode(task), task.Status.Err)
			if task.Status.Err != "container OOM-killed (memory limit 16 MiB)" || taskExitCode(task) != 137 {
				t.Fatalf("task %s: exit %d, error %q", task.ID, taskExitCode(task), task.Status.Err)
			}
		}
	})
}
