//go:build linux

package execution

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/storage/hostvolume"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/errdefs"
	"github.com/gogo/protobuf/types"
	"github.com/moby/swarmkit/v2/api"
	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
)

func TestContainerdRuntimeSpecMetadataIntegration(t *testing.T) {
	client := runtimeMetadataClient(t)
	ctx := namespaces.WithNamespace(t.Context(), "terrascale")
	task := &api.Task{ID: "metadata", ServiceID: "metadata-service", NodeID: "metadata-node",
		ServiceAnnotations: api.Annotations{Labels: map[string]string{"terrascale.role": "terrabase"}},
		Spec: api.TaskSpec{Runtime: &api.TaskSpec_Generic{Generic: &api.GenericRuntimeSpec{
			Kind: "terrascale.stateful-container.v1", Payload: &types.Any{TypeUrl: "terrascale.tech/runtime/stateful-container/v1"},
		}}}}
	binding, err := TaskSHA256(task)
	if err != nil {
		t.Fatal(err)
	}
	pins := RuntimePins{Task: task, ContainerSpecSHA256: binding, Image: "fixture.invalid/terrabase@sha256:" + binding,
		Process: runtimespec.Process{User: runtimespec.User{UID: 65534, GID: 65534}, Args: []string{"/terrabase"},
			Cwd: "/", NoNewPrivileges: true, Capabilities: &runtimespec.LinuxCapabilities{}},
		Resources: runtimespec.LinuxResources{Memory: &runtimespec.LinuxMemory{Limit: new(int64(64 << 20))}},
		Mounts: []runtimespec.Mount{{Source: "/run/retained/volume", Destination: "/retained", Type: "bind",
			Options: []string{"rbind", "nosuid", "nodev", "noexec", "noatime"}}},
		Volume: hostvolume.MountPins{MountPath: "/run/retained/volume", UID: 65534, GID: 65534}, VolumeDestination: "/retained",
		Namespaces: []runtimespec.LinuxNamespace{{Type: runtimespec.PIDNamespace}, {Type: runtimespec.MountNamespace}}}
	const id = "ts-metadata"
	makeSpec := func() *runtimespec.Spec {
		process, resources := pins.Process, pins.Resources
		return &runtimespec.Spec{Version: runtimespec.Version, Root: &runtimespec.Root{Readonly: true},
			Process: &process, Mounts: slices.Clone(pins.Mounts), Linux: &runtimespec.Linux{
				CgroupsPath: "/terrascale/" + id, Resources: &resources, Namespaces: slices.Clone(pins.Namespaces)}}
	}
	container, err := client.NewContainer(ctx, id, containerd.WithImageName(pins.Image), containerd.WithRuntime("io.containerd.runc.v2", nil),
		containerd.WithContainerLabels(map[string]string{"terrascale.task": task.ID, "terrascale.service": task.ServiceID,
			"terrascale.spec": binding, "terrascale.task-binding": binding}), containerd.WithSpec(makeSpec()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(namespaces.WithNamespace(context.Background(), "terrascale"), time.Second)
		defer cancel()
		if err := container.Delete(cleanup); err != nil {
			t.Error(err)
		}
	})
	actual, err := container.Spec(ctx)
	if err != nil || !reflect.DeepEqual(actual, makeSpec()) {
		t.Fatalf("actual containerd spec round trip: %+v %v", actual, err)
	}
	observer := RuntimeObserver{Client: client}
	// A genuine metadata-only container passes spec admission but cannot serve.
	if _, err := observer.Observe(ctx, pins); !errdefs.IsNotFound(err) || errors.Is(err, ErrUnsafe) {
		t.Fatalf("admitted metadata must reach the absent-task boundary: %v", err)
	}
	for _, missing := range []context.Context{nil, ctx} {
		if _, err := (RuntimeObserver{}).Observe(missing, pins); !errors.Is(err, ErrUnsafe) {
			t.Fatalf("absent concrete runtime client: %v", err)
		}
	}
	for name, mutate := range map[string]func(*runtimespec.Spec){
		"writable root":     func(spec *runtimespec.Spec) { spec.Root.Readonly = false },
		"different process": func(spec *runtimespec.Spec) { spec.Process.Args = []string{"/different-member"} },
		"different limits": func(spec *runtimespec.Spec) {
			spec.Linux.Resources = &runtimespec.LinuxResources{Memory: &runtimespec.LinuxMemory{Limit: new(int64(128 << 20))}}
		},
		"different mount": func(spec *runtimespec.Spec) {
			spec.Mounts = []runtimespec.Mount{{Source: "/run/another-volume", Destination: "/retained", Type: "bind"}}
		},
		"different cgroup":     func(spec *runtimespec.Spec) { spec.Linux.CgroupsPath = "/other" },
		"host PID namespace":   func(spec *runtimespec.Spec) { spec.Linux.Namespaces[0].Path = "/proc/1/ns/pid" },
		"host mount namespace": func(spec *runtimespec.Spec) { spec.Linux.Namespaces[1].Path = "/proc/1/ns/mnt" },
		"user namespace": func(spec *runtimespec.Spec) {
			spec.Linux.Namespaces = append(spec.Linux.Namespaces, runtimespec.LinuxNamespace{Type: runtimespec.UserNamespace})
		},
		"private network namespace": func(spec *runtimespec.Spec) {
			spec.Linux.Namespaces = append(spec.Linux.Namespaces, runtimespec.LinuxNamespace{Type: runtimespec.NetworkNamespace})
		},
	} {
		t.Run(name, func(t *testing.T) {
			spec := makeSpec()
			mutate(spec)
			if err := container.Update(ctx, containerd.UpdateContainerOpts(containerd.WithSpec(spec))); err != nil {
				t.Fatal(err)
			}
			if _, err := observer.Observe(ctx, pins); !errors.Is(err, ErrUnsafe) {
				t.Fatalf("actual containerd spec drift reached the task boundary: %v", err)
			}
		})
	}
	if err := container.Update(ctx, containerd.UpdateContainerOpts(containerd.WithSpec(makeSpec()))); err != nil {
		t.Fatal(err)
	}
	if _, err := observer.Observe(ctx, pins); !errdefs.IsNotFound(err) || errors.Is(err, ErrUnsafe) {
		t.Fatalf("restored actual metadata or admitted pins changed: %v", err)
	}
}

func runtimeMetadataClient(t *testing.T) *containerd.Client {
	t.Helper()
	binary, err := exec.LookPath("containerd")
	if err != nil {
		t.Fatal("containerd executable is required on PATH for the disposable metadata integration fixture")
	}
	directory := t.TempDir()
	logPath := filepath.Join(directory, "daemon.log")
	log, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	socket := filepath.Join(directory, "daemon.sock")
	command := exec.Command("nice", "-n", "19", binary, "--config", "/dev/null", "--root", filepath.Join(directory, "root"),
		"--state", filepath.Join(directory, "state"), "--address", socket, "--log-level", "error")
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var exit error
	go func() { exit = command.Wait(); close(done) }()
	t.Cleanup(func() {
		select {
		case <-done:
			return
		default:
			_ = command.Process.Signal(syscall.SIGTERM)
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = command.Process.Kill()
			<-done
		}
	})
	client, err := containerd.New(socket, containerd.WithTimeout(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	for {
		if _, err := client.Version(ctx); err == nil {
			return client
		}
		select {
		case <-done:
			output, _ := os.ReadFile(logPath)
			t.Fatalf("owned metadata daemon exited: %v\n%s", exit, output)
		case <-ctx.Done():
			output, _ := os.ReadFile(logPath)
			t.Fatalf("owned metadata daemon unavailable: %v\n%s", ctx.Err(), output)
		case <-time.After(25 * time.Millisecond):
		}
	}
}
