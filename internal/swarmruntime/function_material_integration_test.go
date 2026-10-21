package swarmruntime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	swarmexec "github.com/moby/swarmkit/v2/agent/exec"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/api/genericresource"
)

type functionMaterialFixture func(context.Context, FunctionTaskBinding) (FunctionMaterial, error)

func (f functionMaterialFixture) CurrentFunctionMaterial(ctx context.Context, binding FunctionTaskBinding) (FunctionMaterial, error) {
	return f(ctx, binding)
}

func TestContainerdFunctionMaterialBoundary(t *testing.T) {
	if *integrationSocket == "" {
		t.Skip("runs in the containerd workflow, which passes -containerd-socket")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	state := t.TempDir()
	e, err := NewExecutor(*integrationSocket, state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	runtime, err := ContainerRuntime(&api.ContainerSpec{Image: integrationImage, User: "65532:65532", Command: []string{"/bin/sh", "-c", `
set -eu
cd /run/ts-orch/function
test "$(id -u)" = 65532
test "$(ls -1 | wc -l)" = 10
test "$(cat broker.creds)" = fixture-broker-credential
test "$(stat -c %a ingress-key.pem)" = 600
for file in *; do test -r "$file"; done
if echo overwrite > broker.creds 2>/dev/null; then exit 21; fi
if touch added-file 2>/dev/null; then exit 22; fi
echo function-material-ready
trap 'exit 0' TERM
while :; do sleep 1; done
`}})
	if err != nil {
		t.Fatal(err)
	}
	task := &api.Task{ID: fmt.Sprintf("material%d", time.Now().UnixNano()), ServiceID: "materialintegration", NodeID: "materialnode", ServiceAnnotations: api.Annotations{Labels: map[string]string{LabelRole: "function-worker", "terrascale.function-proof": "fixture-proof"}}, Spec: api.TaskSpec{Runtime: runtime, Resources: &api.ResourceRequirements{Limits: &api.Resources{NanoCPUs: 250_000_000, MemoryBytes: 64 << 20}}}}
	task.Spec.Resources.Limits.Generic = []*api.GenericResource{genericresource.NewDiscrete(FunctionWorkerSlot, 1)}
	task.Spec.Resources.Reservations = task.Spec.Resources.Limits.Copy()
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
	if err := c.Prepare(ctx); err == nil {
		t.Fatal("function task prepared without trusted material authority")
	}
	admission := Admission{Role: "wasm", Region: "gru", HostID: "materialhost", InstanceID: "ocid1.instance.fixture"}
	files := make(map[string][]byte, len(functionMaterialLimits))
	for name := range functionMaterialLimits {
		files[name] = []byte("fixture-" + name)
	}
	files["root.pub"] = bytes.Repeat([]byte{1}, 32)
	files["broker.creds"] = []byte("fixture-broker-credential")
	fingerprint, err := ContainerTaskFingerprint(task)
	if err != nil {
		t.Fatal(err)
	}
	binding := FunctionTaskBinding{TaskID: task.ID, ServiceID: task.ServiceID, NodeID: task.NodeID, InstanceID: admission.InstanceID, Region: admission.Region, HostID: admission.HostID, Fingerprint: fingerprint}
	material := FunctionMaterial{Binding: binding, ExpiresAt: time.Now().Add(time.Hour), CredentialExpiresAt: time.Now().Add(time.Hour), Files: files}
	provider := functionMaterialFixture(func(_ context.Context, requested FunctionTaskBinding) (FunctionMaterial, error) {
		if requested != binding {
			return FunctionMaterial{}, errors.New("fixture rejected unassigned recipient")
		}
		return material, nil
	})
	bind := func(executor *Executor) {
		t.Helper()
		if err := executor.BindFunctionMaterial(admission, provider); err != nil {
			t.Fatal(err)
		}
		if err := executor.Configure(ctx, &api.Node{ID: task.NodeID}); err != nil {
			t.Fatal(err)
		}
	}
	bind(e)
	description, err := e.Describe(ctx)
	if err != nil || !hasFunctionWorkerSlot(description.Resources.Generic) {
		t.Fatalf("admitted function host lacks scheduler slot: %v", err)
	}
	if err := e.BindFunctionMaterial(admission, provider); err == nil {
		t.Fatal("function authority replaced after admission")
	}
	if err := e.Configure(ctx, &api.Node{ID: "anothernode"}); err == nil {
		t.Fatal("authenticated local node identity changed")
	}
	material.Binding.HostID = "anotherhost"
	if err := c.Prepare(ctx); err == nil {
		t.Fatal("material for another recipient was accepted")
	}
	material.Binding = binding
	material.ExpiresAt = time.Now().Add(-time.Second)
	if err := c.Prepare(ctx); err == nil {
		t.Fatal("expired material was accepted")
	}
	material.ExpiresAt = time.Now().Add(time.Hour)
	credentialExpiry := material.CredentialExpiresAt
	for _, invalid := range []time.Time{{}, time.Now().Add(-time.Second)} {
		material.CredentialExpiresAt = invalid
		if err := c.Prepare(ctx); err == nil {
			t.Fatal("function material accepted absent or expired actual credentials")
		}
	}
	material.CredentialExpiresAt = credentialExpiry
	files["../outside"] = []byte("unsafe")
	if err := c.Prepare(ctx); err == nil {
		t.Fatal("caller-selected material path was accepted")
	}
	delete(files, "../outside")
	wrongNode := task.Copy()
	wrongNode.NodeID = "anothernode"
	if err := controllerFor(e, wrongNode).Prepare(ctx); err == nil {
		t.Fatal("task assigned to another node received material")
	}
	if err := c.Prepare(ctx); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*api.Task){
		func(task *api.Task) {
			task.ServiceAnnotations.Labels["terrascale.function-proof"] = "replacement-proof"
		},
		func(task *api.Task) { task.Spec.ForceUpdate++ },
	} {
		changed := task.Copy()
		mutate(changed)
		if err := c.Update(ctx, changed); !errors.Is(err, swarmexec.ErrTaskUpdateRejected) {
			t.Fatalf("function proof update reused task identity: %v", err)
		}
	}
	files["broker.creds"] = []byte("renewed-credential")
	if err := c.Prepare(ctx); err == nil {
		t.Fatal("new credentials overwrote immutable task material")
	}
	files["broker.creds"] = []byte("fixture-broker-credential")
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	first, err := c.ContainerStatus(ctx)
	if err != nil || first.PID == 0 {
		t.Fatalf("function process did not start: %v", err)
	}
	for deadline := time.Now().Add(10 * time.Second); ; {
		var logs bytes.Buffer
		err := c.Logs(ctx, swarmexec.LogPublisherFunc(func(_ context.Context, message api.LogMessage) error { _, err := logs.Write(message.Data); return err }), api.LogSubscriptionOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(logs.String(), "function-material-ready") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("worker did not prove nonroot read and read-only material mount")
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
	material.CredentialExpiresAt = credentialExpiry.Add(time.Minute)
	if err := c.Prepare(ctx); err == nil {
		t.Fatal("recovery replaced the immutable actual credential deadline")
	}
	material.CredentialExpiresAt = credentialExpiry
	if err := c.Prepare(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Start(ctx); !errors.Is(err, swarmexec.ErrTaskStarted) {
		t.Fatalf("reattach running function task: %v", err)
	}
	second, err := c.ContainerStatus(ctx)
	if err != nil || second.PID != first.PID {
		t.Fatalf("material recovery duplicated worker: %v", err)
	}
	material.ExpiresAt = time.Now().Add(-time.Second)
	if err := c.Start(ctx); err == nil {
		t.Fatal("reattach bypassed current grant expiry")
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
	if _, err := os.Lstat(filepath.Join(state, "function-material", "ts-"+task.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recipient files survived task removal: %v", err)
	}
}
