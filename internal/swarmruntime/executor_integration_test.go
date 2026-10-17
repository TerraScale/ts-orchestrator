package swarmruntime

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	tasksapi "github.com/containerd/containerd/api/services/tasks/v1"
	"github.com/containerd/errdefs"
	swarmexec "github.com/moby/swarmkit/v2/agent/exec"
	"github.com/moby/swarmkit/v2/api"
)

var integrationSocket = flag.String("containerd-socket", "", "disposable containerd fixture socket")

var integrationImage = func() string {
	switch runtime.GOARCH {
	case "amd64":
		return "docker.io/library/alpine@sha256:3e9b4b680bfc9fb5269227cffbd6d42be39fbf7c0b908123913864aa4447e764"
	case "arm64":
		return "docker.io/library/alpine@sha256:2e1a7aa4cbc4e9e5222bb4c24a839aa1a6170ea5492d644777ce7b178824e44f"
	default:
		panic("no pinned containerd integration image for " + runtime.GOARCH)
	}
}()

func TestMain(m *testing.M) {
	if len(os.Args) == 3 && os.Args[1] == "--runtime-logger" {
		RunRuntimeLogger(os.Args[2])
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "stateful-guard-agent-fixture" {
		if err := statefulGuardAgentFixture(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if len(os.Args) == 6 && os.Args[1] == "runtime-expiring-agent-fixture" {
		if err := integrationExpiringAgent(os.Args[2], os.Args[3], os.Args[4], os.Args[5]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if len(os.Args) == 5 && os.Args[1] == "runtime-agent-fixture" {
		if err := integrationAgent(os.Args[2], os.Args[3], os.Args[4]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func integrationAgent(socket, state, taskPath string) error {
	data, err := os.ReadFile(taskPath)
	if err != nil {
		return err
	}
	task := new(api.Task)
	if err := task.Unmarshal(data); err != nil {
		return err
	}
	e, err := newIntegrationExecutor(socket, state)
	if err != nil {
		return err
	}
	defer e.Close()
	c, err := integrationContainerController(e, task)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := c.Prepare(ctx); err != nil {
		return err
	}
	if err := c.Start(ctx); err != nil && !errors.Is(err, swarmexec.ErrTaskStarted) {
		return err
	}
	status, err := c.(swarmexec.ContainerStatuser).ContainerStatus(ctx)
	if err != nil {
		return err
	}
	fmt.Println(status.PID)
	return nil
}

func TestContainerdLifecycleAgentRecovery(t *testing.T) {
	testContainerdLifecycleAgentRecovery(t, integrationImage)
}

func testContainerdLifecycleAgentRecovery(t *testing.T, imageRef string) {
	t.Helper()
	if *integrationSocket == "" {
		t.Fatal("provide -containerd-socket for a disposable real runtime")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	state := t.TempDir()
	e, err := newIntegrationExecutor(*integrationSocket, state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	description, err := e.Describe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if description.Resources.NanoCPUs < 250_000_000 || description.Resources.NanoCPUs >= int64(runtime.NumCPU())*1_000_000_000 {
		t.Fatalf("runtime cannot schedule its bounded smoke task with reserved host CPU: %d", description.Resources.NanoCPUs)
	}
	if runtime.NumCPU() == 1 && description.Resources.NanoCPUs != 750_000_000 {
		t.Fatalf("single-CPU runtime must reserve 250m and advertise 750m, got %d", description.Resources.NanoCPUs)
	}
	t.Logf("runtime reports %d CPU(s), %dm allocatable", runtime.NumCPU(), description.Resources.NanoCPUs/1_000_000)
	runtime, err := ContainerRuntime(&api.ContainerSpec{Image: imageRef, User: "65532:65532", Command: []string{"/bin/sh", "-c", "test \"$(id -u)\" = 65532 || exit 11; if touch /must-not-write 2>/dev/null; then exit 12; fi; head -c 2097152 /dev/zero; trap 'exit 0' TERM; while :; do echo runtime-ready; sleep 1; done"}})
	if err != nil {
		t.Fatal(err)
	}
	task := &api.Task{ID: fmt.Sprintf("executor%d", time.Now().UnixNano()), ServiceID: "executorintegration", Spec: api.TaskSpec{Runtime: runtime, Resources: containerTestResources(250_000_000, 64<<20)}}
	c, err := integrationContainerController(e, task)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		if err := c.Remove(cleanup); err != nil {
			t.Error(err)
		}
	})
	data, err := task.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	taskPath := filepath.Join(state, "task.pb")
	if err := os.WriteFile(taskPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Prepare(ctx); err != nil {
		t.Fatal(err)
	}
	failingLogger, err := exec.LookPath("false")
	if err != nil {
		t.Fatal(err)
	}
	e.executable = failingLogger
	if err := c.Start(ctx); err == nil {
		t.Fatal("workload started without a ready log collector")
	}
	e.executable = executable
	agent := func() string {
		t.Helper()
		command := exec.CommandContext(ctx, executable, "runtime-agent-fixture", *integrationSocket, state, taskPath)
		var stderr bytes.Buffer
		command.Stderr = &stderr
		output, err := command.Output()
		t.Logf("actual runtime agent argv=%q output=%q stderr=%q err=%v", command.Args, output, stderr.String(), err)
		if err != nil {
			t.Fatalf("agent: %v\n%s", err, stderr.String())
		}
		return strings.TrimSpace(string(output))
	}
	firstPID := agent()
	if firstPID == "" || firstPID == "0" {
		t.Fatalf("invalid PID %q", firstPID)
	}
	nativeTask, err := c.(*controller).runtimeTask(ctx)
	if err != nil {
		t.Fatal(err)
	}
	originalProcess, err := c.(*controller).observeGenericProcess(ctx, nativeTask)
	if err != nil || fmt.Sprint(originalProcess.HostPID) != firstPID {
		t.Fatal("actual original runtime process identity unavailable", err)
	}
	if secondPID := agent(); secondPID != firstPID {
		t.Fatalf("restart duplicated task: %s -> %s", firstPID, secondPID)
	}
	adopted, err := c.(*controller).observeGenericProcess(ctx, nativeTask)
	if err != nil || adopted != originalProcess {
		t.Fatal("agent recovery changed original PID/kernel-start/cgroup/namespaces/spec", err)
	}
	t.Logf("actual original/adopted runtime process: %+v", originalProcess)
	containers, err := e.client.Containers(runtimeContext(ctx), "id==ts-"+task.ID)
	if err != nil || len(containers) != 1 {
		t.Fatalf("container identity: count=%d err=%v", len(containers), err)
	}
	info, err := containers[0].Info(runtimeContext(ctx))
	if err != nil || info.SnapshotKey == "" {
		t.Fatal("actual writable task snapshot unavailable", err)
	}
	processes, err := e.client.TaskService().List(runtimeContext(ctx), &tasksapi.ListTasksRequest{})
	if err != nil {
		t.Fatal(err)
	}
	matching := 0
	for _, process := range processes.Tasks {
		if process.ID == "ts-"+task.ID {
			matching++
			if int(process.Pid) != originalProcess.HostPID {
				t.Fatal("actual runtime task changed original PID")
			}
		}
	}
	if matching != 1 {
		t.Fatal("agent recovery did not retain exactly one actual runtime task", err)
	}
	short, stop := context.WithTimeout(ctx, 30*time.Millisecond)
	if err := c.Wait(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wait cancellation: %v", err)
	}
	stop()
	mutated := task.Copy()
	mutated.Spec.Resources.Limits.MemoryBytes *= 2
	if err := c.Update(ctx, mutated); !errors.Is(err, swarmexec.ErrTaskUpdateRejected) {
		t.Fatalf("immutable task update: %v", err)
	}
	conflict, err := integrationContainerController(e, mutated)
	if err != nil {
		t.Fatal(err)
	}
	if err := conflict.Prepare(ctx); err == nil {
		t.Fatal("conflicting durable identity adopted")
	}
	if _, err := c.(*controller).Metrics(ctx); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	for deadline := time.Now().Add(10 * time.Second); ; {
		logs.Reset()
		err = c.(swarmexec.ControllerLogs).Logs(ctx, swarmexec.LogPublisherFunc(func(_ context.Context, m api.LogMessage) error { _, err := logs.Write(m.Data); return err }), api.LogSubscriptionOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(logs.String(), "runtime-ready") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no readiness marker after agent process exit")
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	if logs.Len() > 2*logSegmentBytes {
		t.Fatalf("log snapshot exceeds bound: %d", logs.Len())
	}
	for _, stream := range []string{"stdout", "stderr"} {
		info, err := os.Stat(filepath.Join(state, "runtime-logs", "ts-"+task.ID, stream))
		if err != nil || info.Size() > logSegmentBytes {
			t.Fatalf("log storage exceeds bound for %s: %v", stream, err)
		}
	}
	if err := c.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Wait(ctx); err != nil {
		t.Fatalf("graceful exit: %v", err)
	}
	if err := c.Start(ctx); err == nil {
		t.Fatal("exited task identity restarted")
	}
	if err := c.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := e.client.LoadContainer(runtimeContext(ctx), "ts-"+task.ID); !errdefs.IsNotFound(err) {
		t.Fatalf("container survived removal: %v", err)
	}
	processes, err = e.client.TaskService().List(runtimeContext(ctx), &tasksapi.ListTasksRequest{})
	if err != nil {
		t.Fatal("runtime task survived removal", err)
	}
	for _, process := range processes.Tasks {
		if process.ID == "ts-"+task.ID {
			t.Fatal("runtime task survived removal")
		}
	}
	if _, err := e.client.SnapshotService(info.Snapshotter).Stat(runtimeContext(ctx), info.SnapshotKey); !errdefs.IsNotFound(err) {
		t.Fatal("task writable snapshot survived removal", err)
	}
	if err := genericOriginalProcessStopped(originalProcess.HostPID, originalProcess.KernelStart); err != nil {
		t.Fatal("original native process survived stop/remove", err)
	}
	cgroup, err := os.ReadFile(filepath.Join("/sys/fs/cgroup/terrascale", "ts-"+task.ID, "cgroup.events"))
	if err != nil && !errors.Is(err, os.ErrNotExist) || err == nil && !strings.Contains("\n"+string(cgroup), "\npopulated 0\n") {
		t.Fatal("original task cgroup still populated after remove", err)
	}
	if _, err := os.Stat(filepath.Join(state, "runtime-logs", "ts-"+task.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("removed task retained runtime logs", err)
	}
	loggerCtx, stopLogger := context.WithTimeout(ctx, 5*time.Second)
	defer stopLogger()
	waitRuntime(t, loggerCtx, func() (bool, error) {
		entries, err := os.ReadDir("/proc")
		if err != nil {
			return false, err
		}
		for _, entry := range entries {
			command, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
			if err != nil {
				if errors.Is(err, os.ErrNotExist) || !entry.IsDir() {
					continue
				}
				return false, err
			}
			args := bytes.Split(bytes.TrimSuffix(command, []byte{0}), []byte{0})
			if len(args) != 3 || string(args[1]) != "--runtime-logger" {
				continue
			}
			var invocation runtimeLoggerInvocation
			if string(args[2]) == e.logRoot || json.Unmarshal(args[2], &invocation) == nil && invocation.Root == e.logRoot {
				return false, fmt.Errorf("exact fixture runtime logger %s remains", entry.Name())
			}
		}
		return true, nil
	})
}
