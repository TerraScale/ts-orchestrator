package swarmruntime

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/containerd/errdefs"
	swarmexec "github.com/moby/swarmkit/v2/agent/exec"
	"github.com/moby/swarmkit/v2/api"
)

var integrationSocket = flag.String("containerd-socket", "", "disposable containerd fixture socket")

const integrationImage = "docker.io/library/alpine@sha256:3e9b4b680bfc9fb5269227cffbd6d42be39fbf7c0b908123913864aa4447e764"

func TestMain(m *testing.M) {
	if len(os.Args) == 3 && os.Args[1] == "--runtime-logger" {
		RunRuntimeLogger(os.Args[2])
		return
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
	e, err := NewExecutor(socket, state)
	if err != nil {
		return err
	}
	defer e.Close()
	c, err := e.Controller(task)
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
	if *integrationSocket == "" {
		t.Fatal("provide -containerd-socket for a disposable real runtime")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	state := t.TempDir()
	e, err := NewExecutor(*integrationSocket, state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	runtime, err := ContainerRuntime(&api.ContainerSpec{Image: integrationImage, User: "65532:65532", Command: []string{"/bin/sh", "-c", "test \"$(id -u)\" = 65532 || exit 11; if touch /must-not-write 2>/dev/null; then exit 12; fi; head -c 2097152 /dev/zero; trap 'exit 0' TERM; while :; do echo runtime-ready; sleep 1; done"}})
	if err != nil {
		t.Fatal(err)
	}
	task := &api.Task{ID: fmt.Sprintf("executor%d", time.Now().UnixNano()), ServiceID: "executorintegration", Spec: api.TaskSpec{Runtime: runtime, Resources: &api.ResourceRequirements{Limits: &api.Resources{NanoCPUs: 250_000_000, MemoryBytes: 64 << 20}}}}
	c, err := e.Controller(task)
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
	agent := func() string {
		t.Helper()
		command := exec.CommandContext(ctx, executable, "runtime-agent-fixture", *integrationSocket, state, taskPath)
		var stderr bytes.Buffer
		command.Stderr = &stderr
		output, err := command.Output()
		if err != nil {
			t.Fatalf("agent: %v\n%s", err, stderr.String())
		}
		return strings.TrimSpace(string(output))
	}
	firstPID := agent()
	if firstPID == "" || firstPID == "0" {
		t.Fatalf("invalid PID %q", firstPID)
	}
	if secondPID := agent(); secondPID != firstPID {
		t.Fatalf("restart duplicated task: %s -> %s", firstPID, secondPID)
	}
	containers, err := e.client.Containers(runtimeContext(ctx), "id==ts-"+task.ID)
	if err != nil || len(containers) != 1 {
		t.Fatalf("container identity: count=%d err=%v", len(containers), err)
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
	conflict, err := e.Controller(mutated)
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
}
