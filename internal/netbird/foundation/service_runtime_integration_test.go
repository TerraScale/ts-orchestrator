package foundation

import (
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/errdefs"
	spec "github.com/opencontainers/runtime-spec/specs-go"
)

var runtimeSocket = flag.String("foundation-containerd-socket", "", "disposable qualified containerd fixture socket")
var runtimeLogger = flag.String("foundation-runtime-logger", "", "compiled ts-orch binary supporting the runtime logger dispatcher")

// Exercise the production SDK lifecycle, native snapshots, shim logger and persistent mounts.
func TestFoundationContainerdLifecycle(t *testing.T) {
	if *runtimeSocket == "" || *runtimeLogger == "" {
		t.Fatal("provide the disposable containerd socket and runtime logger executable")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	client, err := containerd.New(*runtimeSocket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	r := &foundationRuntime{client: client, executable: *runtimeLogger, logRoot: filepath.Join(t.TempDir(), "logs")}
	check := func() error { return nil }
	if containers, err := client.Containers(foundationContext(ctx)); err != nil || len(containers) != 0 {
		t.Fatalf("fixture namespace must be empty: count=%d err=%v", len(containers), err)
	}
	component := foundationComponent{ID: "netbird-server", Image: "docker.io/library/alpine@sha256:3e9b4b680bfc9fb5269227cffbd6d42be39fbf7c0b908123913864aa4447e764", Memory: 64 << 20, Args: []string{"/bin/sh", "-c", "echo start >> /state/runs; echo foundation-ready; trap 'exit 0' TERM; while :; do sleep 1; done"}, Mounts: []spec.Mount{{Source: t.TempDir(), Destination: "/state", Type: "bind", Options: []string{"rbind", "nosuid", "nodev"}}}}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 40*time.Second)
		defer stop()
		if err := r.stop(cleanup, component.ID, check); err != nil {
			t.Error(err)
		}
		container, err := client.LoadContainer(foundationContext(cleanup), component.ID)
		if err == nil {
			err = container.Delete(foundationContext(cleanup), containerd.WithSnapshotCleanup)
		}
		if err != nil && !errdefs.IsNotFound(err) {
			t.Error(err)
		}
	})
	if err := r.ensure(ctx, component, check); err != nil {
		t.Fatal(err)
	}
	container, err := client.LoadContainer(foundationContext(ctx), component.ID)
	if err != nil {
		t.Fatal(err)
	}
	first, err := container.Task(foundationContext(ctx), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.ensure(ctx, component, check); err != nil {
		t.Fatal(err)
	}
	again, err := container.Task(foundationContext(ctx), nil)
	if err != nil || again.Pid() != first.Pid() {
		t.Fatalf("reconcile duplicated process: %v", err)
	}
	waitFile := func(path, contains string) {
		t.Helper()
		for deadline := time.Now().Add(10 * time.Second); ; {
			wire, err := os.ReadFile(path)
			if err == nil && strings.Contains(string(wire), contains) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("expected persisted marker in %s: %v", filepath.Base(path), err)
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
	waitFile(filepath.Join(r.logRoot, component.ID, "stdout"), "foundation-ready")
	waitFile(filepath.Join(component.Mounts[0].Source, "runs"), "start\n")
	lost := errors.New("fixture authority lost")
	if err := r.stop(ctx, component.ID, func() error { return lost }); !errors.Is(err, lost) {
		t.Fatalf("stop bypassed authority: %v", err)
	}
	if err := r.stop(ctx, component.ID, check); err != nil {
		t.Fatal(err)
	}
	if _, err := container.Task(foundationContext(ctx), nil); !errdefs.IsNotFound(err) {
		t.Fatalf("stopped task was retained: %v", err)
	}
	if err := r.ensure(ctx, component, check); err != nil {
		t.Fatal(err)
	}
	waitFile(filepath.Join(component.Mounts[0].Source, "runs"), "start\nstart\n")
	component.Configuration = "next-config"
	if err := r.ensure(ctx, component, check); err != nil {
		t.Fatal(err)
	}
	waitFile(filepath.Join(component.Mounts[0].Source, "runs"), "start\nstart\nstart\n")
	container, err = client.LoadContainer(foundationContext(ctx), component.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Emulate a crash after snapshot preparation but before the container metadata update.
	if err := r.stop(ctx, component.ID, check); err != nil {
		t.Fatal(err)
	}
	if err := container.Update(foundationContext(ctx), func(_ context.Context, _ *containerd.Client, metadata *containers.Container) error {
		metadata.SnapshotKey = ""
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := r.ensure(ctx, component, check); err != nil {
		t.Fatal(err)
	}
	waitFile(filepath.Join(component.Mounts[0].Source, "runs"), "start\nstart\nstart\nstart\n")
	if _, err := container.SetLabels(foundationContext(ctx), map[string]string{"terrascale.foundation": "foreign"}); err != nil {
		t.Fatal(err)
	}
	if err := r.ensure(ctx, component, check); err == nil {
		t.Fatal("adopted foreign ownership")
	}
	if _, err := container.SetLabels(foundationContext(ctx), map[string]string{"terrascale.foundation": "netbird-v1"}); err != nil {
		t.Fatal(err)
	}
}
