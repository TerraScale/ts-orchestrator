package swarmruntime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	swarmexec "github.com/moby/swarmkit/v2/agent/exec"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/api/genericresource"
)

type containerMaterialFixture func(context.Context, ContainerTaskBinding) (ContainerMaterial, error)

func (f containerMaterialFixture) CurrentContainerMaterial(ctx context.Context, binding ContainerTaskBinding) (ContainerMaterial, error) {
	return f(ctx, binding)
}

// Runtime-only fixtures explicitly supply test authority for their no-secret tasks.
func newIntegrationExecutor(socket, state string) (*Executor, error) {
	e, err := NewExecutor(socket, state)
	if err != nil {
		return nil, err
	}
	err = e.BindContainerMaterial(Admission{Role: "container", Region: "sa-saopaulo-1", HostID: "integrationhost", InstanceID: "ocid1.instance.fixture"}, containerMaterialFixture(func(_ context.Context, binding ContainerTaskBinding) (ContainerMaterial, error) {
		return ContainerMaterial{Binding: binding, ExpiresAt: time.Now().Add(time.Hour), User: "65532:65532"}, nil
	}))
	if err != nil {
		_ = e.Close()
		return nil, err
	}
	return e, nil
}

func integrationContainerController(e *Executor, task *api.Task) (swarmexec.Controller, error) {
	if task.NodeID == "" {
		task.NodeID = "integrationnode"
	}
	if err := e.Configure(context.Background(), &api.Node{ID: task.NodeID}); err != nil {
		return nil, err
	}
	return e.Controller(task)
}

func TestContainerdContainerMaterialBoundary(t *testing.T) {
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
	runtime, err := ContainerRuntime(&api.ContainerSpec{Image: integrationImage, User: "10001:10002", Command: []string{"/bin/sh", "-c", `
set -eu
test "$(id -u)" = 10001
test "$(id -g)" = 10002
test "$DATABASE_PASSWORD_FILE" = /run/ts-orch/secrets/database_password_file
test "$(cat "$DATABASE_PASSWORD_FILE")" = fixture-database-password
test "$(stat -c %a "$DATABASE_PASSWORD_FILE")" = 600
test "$(ls -1 /run/ts-orch/secrets | wc -l)" = 1
if echo overwrite > "$DATABASE_PASSWORD_FILE" 2>/dev/null; then exit 21; fi
if touch /run/ts-orch/secrets/added 2>/dev/null; then exit 22; fi
if /run/ts-orch/secrets/database_password_file 2>/dev/null; then exit 23; fi
echo container-material-ready
trap 'exit 0' TERM
while :; do sleep 1; done
`}})
	if err != nil {
		t.Fatal(err)
	}
	task := &api.Task{ID: fmt.Sprintf("secrets%d", time.Now().UnixNano()), ServiceID: "containersecretsintegration", NodeID: "secretsnode",
		ServiceAnnotations: api.Annotations{Labels: map[string]string{LabelRole: "ts-auth"}},
		Spec:               api.TaskSpec{Runtime: runtime, Resources: containerTestResources(250_000_000, 64<<20)}}
	controllerFor := func(executor *Executor, task *api.Task) *controller {
		t.Helper()
		c, err := executor.Controller(task)
		if err != nil {
			t.Fatal(err)
		}
		return c.(*controller)
	}
	c := controllerFor(e, task)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		if err := c.Remove(cleanup); err != nil {
			t.Error(err)
		}
	})
	if err := c.Prepare(ctx); !errors.Is(err, ErrContainerMaterialPending) {
		t.Fatalf("missing material authority must stay pending: %v", err)
	}
	admitted := Admission{Role: "container", Region: "sa-saopaulo-1", HostID: "secretshost", InstanceID: "ocid1.instance.secretsfixture"}
	binding := ContainerTaskBinding{TaskID: task.ID, ServiceID: task.ServiceID, NodeID: task.NodeID, InstanceID: admitted.InstanceID, Region: admitted.Region, HostID: admitted.HostID, Fingerprint: c.fingerprint}
	material := ContainerMaterial{Binding: binding, ExpiresAt: time.Now().Add(time.Hour), User: "10001:10002", Files: map[string][]byte{"database_password_file": []byte("fixture-database-password")}, FileEnvironment: map[string]string{"DATABASE_PASSWORD_FILE": "database_password_file"}}
	provider := containerMaterialFixture(func(_ context.Context, requested ContainerTaskBinding) (ContainerMaterial, error) {
		if requested != binding {
			return ContainerMaterial{}, errors.New("fixture rejected unassigned recipient")
		}
		return material, nil
	})
	bind := func(executor *Executor) {
		t.Helper()
		if err := executor.BindContainerMaterial(admitted, provider); err != nil {
			t.Fatal(err)
		}
		if err := executor.Configure(ctx, &api.Node{ID: task.NodeID}); err != nil {
			t.Fatal(err)
		}
	}
	bind(e)
	if err := e.BindContainerMaterial(admitted, provider); err == nil {
		t.Fatal("material authority replaced")
	}
	material.Binding.HostID = "anotherhost"
	if err := c.Prepare(ctx); err == nil {
		t.Fatal("wrong recipient material accepted")
	}
	material.Binding = binding
	material.User = "65532:65532"
	if err := c.Prepare(ctx); err == nil {
		t.Fatal("material for a different user accepted")
	}
	material.User = "10001:10002"
	material.ExpiresAt = time.Now().Add(-time.Second)
	if err := c.Prepare(ctx); !errors.Is(err, ErrContainerMaterialPending) {
		t.Fatalf("expired material must stay pending: %v", err)
	}
	material.ExpiresAt = time.Now().Add(time.Hour)
	material.FileEnvironment["DATABASE_PASSWORD_FILE"] = "../outside"
	if err := c.Prepare(ctx); err == nil {
		t.Fatal("caller selected native file path")
	}
	material.FileEnvironment["DATABASE_PASSWORD_FILE"] = "database_password_file"
	material.FileEnvironment["TOKEN"] = "token"
	material.Files["token"] = []byte("plaintext-only-secret")
	if err := c.Prepare(ctx); err == nil {
		t.Fatal("plaintext-only environment key accepted")
	}
	delete(material.FileEnvironment, "TOKEN")
	delete(material.Files, "token")
	wrongNode := task.Copy()
	wrongNode.NodeID = "anothernode"
	if err := controllerFor(e, wrongNode).Prepare(ctx); !errors.Is(err, ErrContainerMaterialPending) {
		t.Fatalf("task assigned to another node received material: %v", err)
	}
	if err := c.Prepare(ctx); err != nil {
		t.Fatal(err)
	}
	material.Files["database_password_file"] = []byte("renewed-database-password")
	if err := c.Prepare(ctx); err == nil {
		t.Fatal("credential renewal mutated existing task files")
	}
	material.Files["database_password_file"] = []byte("fixture-database-password")
	changed := task.Copy()
	changed.Spec.ForceUpdate++
	if err := c.Update(ctx, changed); !errors.Is(err, swarmexec.ErrTaskUpdateRejected) {
		t.Fatalf("renewal reused old task: %v", err)
	}
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	first, err := c.ContainerStatus(ctx)
	if err != nil || first.PID == 0 {
		t.Fatalf("secret consumer did not start: %v", err)
	}
	checkExecutorTaskLoad(t, ctx, e, c)
	for deadline := time.Now().Add(10 * time.Second); ; {
		var logs bytes.Buffer
		err := c.Logs(ctx, swarmexec.LogPublisherFunc(func(_ context.Context, message api.LogMessage) error { _, err := logs.Write(message.Data); return err }), api.LogSubscriptionOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(logs.String(), "container-material-ready") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("consumer did not prove nonroot read and readonly file mapping")
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(25 * time.Millisecond):
		}
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	e, err = NewExecutor(*integrationSocket, state)
	if err != nil {
		t.Fatal(err)
	}
	bind(e)
	c = controllerFor(e, task)
	if err := c.Prepare(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Start(ctx); !errors.Is(err, swarmexec.ErrTaskStarted) {
		t.Fatalf("reattach existing secret consumer: %v", err)
	}
	second, err := c.ContainerStatus(ctx)
	if err != nil || first.PID != second.PID {
		t.Fatalf("recovery duplicated process: %v", err)
	}
	checkExecutorTaskLoad(t, ctx, e, c)
	file := filepath.Join(c.containerMaterialPath(), "database_password_file")
	if err := os.Chmod(file, 0640); err != nil {
		t.Fatal(err)
	}
	if err := c.Prepare(ctx); err == nil {
		t.Fatal("recovery adopted nonprivate material permissions")
	}
	if err := os.Chmod(file, 0600); err != nil {
		t.Fatal(err)
	}
	material.ExpiresAt = time.Now().Add(-time.Second)
	if err := c.Start(ctx); !errors.Is(err, ErrContainerMaterialPending) {
		t.Fatalf("reattach bypassed current grant expiry: %v", err)
	}
	live, err := c.runtimeTask(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if status, err := live.Status(runtimeContext(ctx)); err != nil || status.Status != containerd.Running {
		t.Fatalf("transport grant expiry stopped a running consumer: %v, %v", status, err)
	}
	material.ExpiresAt = time.Now().Add(time.Hour)
	if err := c.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(c.containerMaterialPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("secret files survived task removal: %v", err)
	}
}

func TestContainerdContainerCredentialExpirySurvivesAgentExit(t *testing.T) {
	testContainerCredentialExpiry(t, "container")
}

func TestContainerdFunctionCredentialExpirySurvivesAgentExit(t *testing.T) {
	testContainerCredentialExpiry(t, "function-worker")
}

func testContainerCredentialExpiry(t *testing.T, role string) {
	t.Helper()
	if *integrationSocket == "" {
		t.Fatal("provide -containerd-socket for a disposable real runtime")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	state := t.TempDir()
	e, err := NewExecutor(*integrationSocket, state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	commandText := "test -r \"$TOKEN_FILE\"; echo credential-consumer-ready; exec sleep 120"
	if role == "function-worker" {
		commandText = "test -r /run/ts-orch/function/broker.creds; echo credential-consumer-ready; exec sleep 120"
	}
	runtime, err := ContainerRuntime(&api.ContainerSpec{Image: integrationImage, User: "65532:65532", Command: []string{"/bin/sh", "-ec", commandText}})
	if err != nil {
		t.Fatal(err)
	}
	task := &api.Task{ID: fmt.Sprintf("expiry%d", time.Now().UnixNano()), ServiceID: "credentialexpiryintegration", NodeID: "expirynode", Spec: api.TaskSpec{Runtime: runtime, Resources: containerTestResources(250_000_000, 64<<20)}}
	if role == "function-worker" {
		task.ServiceAnnotations.Labels = map[string]string{LabelRole: role, "terrascale.function-proof": "expiry-fixture"}
		task.Spec.Resources.Limits.Generic = []*api.GenericResource{genericresource.NewDiscrete(FunctionWorkerSlot, 1)}
		task.Spec.Resources.Reservations = task.Spec.Resources.Limits.Copy()
	}
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
	expires := time.Now().Add(15 * time.Second)
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
	command := exec.CommandContext(ctx, executable, "runtime-expiring-agent-fixture", *integrationSocket, state, taskPath, expires.UTC().Format(time.RFC3339Nano))
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if output, err := command.Output(); err != nil {
		t.Fatalf("expiring agent process: %v, %s, %s", err, output, stderr.String())
	}
	first, err := c.(*controller).ContainerStatus(ctx)
	if err != nil || first.PID == 0 {
		t.Fatalf("credential consumer did not survive agent process exit: %v", err)
	}
	// This executor never had a provider or watchdog; only the shim can enforce expiry.
	wait, stop := context.WithDeadline(ctx, expires.Add(4*time.Second))
	defer stop()
	if err := c.Wait(wait); err == nil {
		t.Fatal("expired credential consumer exited successfully")
	} else if errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("shim-owned guardian did not stop consumer after actual credential expiry")
	}
	if time.Now().Before(expires) {
		t.Fatal("credential consumer stopped before actual expiry")
	}
	t.Logf("exact PID %d stopped at actual credential expiry after agent process exit", first.PID)
}

func integrationExpiringAgent(socket, state, taskPath, deadline string) error {
	data, err := os.ReadFile(taskPath)
	if err != nil {
		return err
	}
	task := new(api.Task)
	if err := task.Unmarshal(data); err != nil {
		return err
	}
	expires, err := time.Parse(time.RFC3339Nano, deadline)
	if err != nil {
		return err
	}
	e, err := NewExecutor(socket, state)
	if err != nil {
		return err
	}
	defer e.Close()
	admission := Admission{Role: "container", Region: "sa-saopaulo-1", InstanceID: "ocid1.instance.expiryfixture", HostID: "expiryhost"}
	if task.ServiceAnnotations.Labels[LabelRole] == "function-worker" {
		admission.Role = "wasm"
		files := make(map[string][]byte, len(functionMaterialLimits))
		for name := range functionMaterialLimits {
			files[name] = []byte("fixture-" + name)
		}
		files["root.pub"] = bytes.Repeat([]byte{1}, 32)
		if err := e.BindFunctionMaterial(admission, functionMaterialFixture(func(_ context.Context, binding FunctionTaskBinding) (FunctionMaterial, error) {
			return FunctionMaterial{Binding: binding, ExpiresAt: time.Now().Add(time.Hour), CredentialExpiresAt: expires, Files: files}, nil
		})); err != nil {
			return err
		}
	} else if err := e.BindContainerMaterial(admission, containerMaterialFixture(func(_ context.Context, binding ContainerTaskBinding) (ContainerMaterial, error) {
		return ContainerMaterial{Binding: binding, User: "65532:65532", ExpiresAt: time.Now().Add(time.Hour), CredentialExpiresAt: expires, Files: map[string][]byte{"token_file": []byte("fixture-expiring-credential")}, FileEnvironment: map[string]string{"TOKEN_FILE": "token_file"}}, nil
	})); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := e.Configure(ctx, &api.Node{ID: task.NodeID}); err != nil {
		return err
	}
	c, err := e.Controller(task)
	if err != nil {
		return err
	}
	if err := c.Prepare(ctx); err != nil {
		return err
	}
	return c.Start(ctx)
}
