package swarmruntime

import (
	"context"
	"fmt"

	"os"
	"path/filepath"

	"syscall"
	"testing"
	"time"

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
