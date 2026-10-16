//go:build linux

package execution

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/memberstatus"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/moby/swarmkit/v2/api"
	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

var stopIntegrationSocket = flag.String("containerd-socket", "", "disposable containerd fixture socket")

func TestContainerdEmergencyStopRetainsExactIdentity(t *testing.T) {
	if *stopIntegrationSocket == "" || os.Geteuid() != 0 {
		t.Fatal("provide -containerd-socket and root for the disposable real runtime")
	}
	ctx, cancel := context.WithTimeout(namespaces.WithNamespace(t.Context(), "terrascale"), 30*time.Second)
	defer cancel()
	client, err := containerd.New(*stopIntegrationSocket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	const imageName = "docker.io/library/alpine@sha256:3e9b4b680bfc9fb5269227cffbd6d42be39fbf7c0b908123913864aa4447e764"
	image, err := client.GetImage(ctx, imageName)
	if err != nil {
		t.Fatal(err)
	}
	task := &api.Task{ID: fmt.Sprintf("emergencystop%d", time.Now().UnixNano()), ServiceID: "emergencystop", NodeID: "stopnode",
		ServiceAnnotations: api.Annotations{Labels: map[string]string{"terrascale.role": "terrabase"}}}
	hash, err := TaskSHA256(task)
	if err != nil {
		t.Fatal(err)
	}
	id := "ts-" + task.ID
	container, err := client.NewContainer(ctx, id, containerd.WithImage(image), containerd.WithSnapshotter("native"),
		containerd.WithNewSnapshot(id, image), containerd.WithRuntime("io.containerd.runc.v2", nil),
		containerd.WithContainerLabels(map[string]string{"terrascale.task": task.ID, "terrascale.service": task.ServiceID,
			"terrascale.spec": hash, "terrascale.task-binding": hash}),
		containerd.WithNewSpec(oci.WithImageConfig(image), oci.WithProcessArgs("/bin/sh", "-c", "sleep 60 & wait"),
			oci.WithUIDGID(65532, 65532), oci.WithCgroup("/terrascale/"+id), oci.WithHostNamespace(runtimespec.NetworkNamespace),
			oci.WithRootFSReadonly(), oci.WithNoNewPrivileges, oci.WithCapabilities(nil),
			oci.WithMemoryLimit(64<<20), oci.WithMemorySwap(64<<20), oci.WithCPUCFS(25000, 100000), oci.WithPidsLimit(32)))
	if err != nil {
		t.Fatal(err)
	}
	var process containerd.Task
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(namespaces.WithNamespace(context.Background(), "terrascale"), 10*time.Second)
		defer stop()
		if process != nil {
			if _, err := process.Delete(cleanup, containerd.WithProcessKill); err != nil {
				t.Error(err)
			}
		}
		if err := container.Delete(cleanup, containerd.WithSnapshotCleanup); err != nil {
			t.Error(err)
		}
	})
	start := func() {
		t.Helper()
		var err error
		process, err = container.NewTask(ctx, cio.NullIO)
		if err != nil {
			t.Fatal(err)
		}
		if err := process.Start(ctx); err != nil {
			t.Fatal(err)
		}
	}
	start()
	observed, err := memberstatus.ObserveContainerProcess(int(process.Pid()), int(process.Pid()))
	if err != nil {
		t.Fatal(err)
	}
	var pidNS, mountNS unix.Stat_t
	if err := unix.Stat(fmt.Sprintf("/proc/%d/ns/pid", process.Pid()), &pidNS); err != nil {
		t.Fatal(err)
	}
	if err := unix.Stat(fmt.Sprintf("/proc/%d/ns/mnt", process.Pid()), &mountNS); err != nil {
		t.Fatal(err)
	}
	spec, err := container.Spec(ctx)
	if err != nil {
		t.Fatal(err)
	}
	held := &workerTaskSession{task: task, pins: &RuntimePins{Task: task, Resources: *spec.Linux.Resources},
		observation: RuntimeObservation{Process: observed, ContainerID: id, PIDNamespace: pidNS.Ino, MountNamespace: mountNS.Ino, State: containerd.Running}}
	session := &WorkerSession{client: client, tasks: map[string]*workerTaskSession{hash: held}}
	witness := held.observation
	// The real kernel witness is retained directly; this does not qualify Source admission.
	for _, name := range []string{"unknown PID", "reused PID start", "other cgroup", "other PID namespace", "other mount namespace", "other binding"} {
		t.Run(name, func(t *testing.T) {
			held.observation = witness
			switch name {
			case "unknown PID":
				held.observation.Process.PID = os.Getpid()
			case "reused PID start":
				held.observation.Process.KernelStart += "0"
			case "other cgroup":
				held.observation.Process.Cgroup = "0::/unknown\n"
			case "other PID namespace":
				held.observation.PIDNamespace++
			case "other mount namespace":
				held.observation.MountNamespace++
			case "other binding":
				if _, err := container.SetLabels(ctx, map[string]string{"terrascale.task-binding": "substituted"}); err != nil {
					t.Fatal(err)
				}
			}
			if err := session.stopRuntime(ctx, task, hash); !errors.Is(err, ErrUnsafe) {
				t.Fatalf("substituted identity stop = %v", err)
			}
			status, err := process.Status(ctx)
			if err != nil || status.Status != containerd.Running {
				t.Fatalf("identity rejection killed retained writer: %v %v", status, err)
			}
		})
	}
	if _, err := container.SetLabels(ctx, map[string]string{"terrascale.task-binding": hash}); err != nil {
		t.Fatal(err)
	}
	held.observation = witness
	if err := verifyRuntimeLimits(observed.Cgroup, id, held.pins.Resources); err != nil {
		t.Fatalf("initial actual resource policy: %v", err)
	}
	cgroup := filepath.Join("/sys/fs/cgroup/terrascale", id)
	if err := os.WriteFile(filepath.Join(cgroup, "memory.max"), []byte("100663296"), 0); err != nil {
		t.Fatal(err)
	}
	if err := verifyRuntimeLimits(observed.Cgroup, id, held.pins.Resources); err == nil {
		t.Fatal("actual memory drift passed runtime health observation")
	}
	if err := session.stopRuntime(ctx, task, hash); err != nil {
		t.Fatalf("emergency stop after actual resource drift: %v", err)
	}
	if err := originalProcessStopped(observed.PID, observed.KernelStart); err != nil {
		t.Fatalf("retained writer still live: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(cgroup, "cgroup.events"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if err == nil && !bytes.Contains(data, []byte("populated 0\n")) {
		t.Fatalf("private PID namespace descendants survived stop: %s", data)
	}
	if _, err := process.Delete(ctx); err != nil {
		t.Fatal(err)
	}
	process = nil
	start()
	if err := session.stopRuntime(ctx, task, hash); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("replacement task inherited old stop authorization: %v", err)
	}
	if err := syscall.Kill(int(process.Pid()), 0); err != nil {
		t.Fatalf("replacement task was killed: %v", err)
	}
}
