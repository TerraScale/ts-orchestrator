package swarmruntime

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/storage/execution"
	"github.com/moby/swarmkit/v2/api"
)

func TestContainerdStatefulMissingAdmissionDeniesAllClaims(t *testing.T) {
	if *integrationSocket == "" {
		t.Fatal("provide -containerd-socket for a disposable real runtime")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	executor, err := NewExecutor(*integrationSocket, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = executor.Close() })
	runtime, err := ContainerRuntime(&api.ContainerSpec{Image: integrationImage, User: "65532:65532", Command: []string{"/bin/sleep", "60"}})
	if err != nil {
		t.Fatal(err)
	}
	task := &api.Task{
		ID: fmt.Sprintf("statefuldeny%d", time.Now().UnixNano()), ServiceID: "statefuldenial", NodeID: "statefulnode",
		ServiceAnnotations: api.Annotations{Labels: map[string]string{LabelRole: "terrabase", "terrascale.stateful": "true"}},
		Spec:               api.TaskSpec{Runtime: runtime, Resources: &api.ResourceRequirements{Limits: &api.Resources{NanoCPUs: 250_000_000, MemoryBytes: 64 << 20}}},
	}
	// Ordinary task metadata cannot turn the stateless route into a writer.
	if _, err := executor.Controller(task); err == nil {
		t.Fatal("stateless route accepted a stateful label")
	}
	task.Spec.GetGeneric().Kind = execution.StatefulContainerKind
	task.Spec.GetGeneric().Payload.TypeUrl = execution.StatefulContainerTypeURL
	// A well-formed typed request still lacks independently verified admission.
	if _, err := executor.Controller(task); !errors.Is(err, execution.ErrUnsafe) {
		t.Fatalf("missing source: %v", err)
	}
	if err := executor.BindStateful(nil); !errors.Is(err, execution.ErrUnsafe) {
		t.Fatalf("nil source: %v", err)
	}
	if err := executor.Configure(ctx, &api.Node{ID: task.NodeID}); err != nil {
		t.Fatal(err)
	}
	if err := executor.BindStateful(new(execution.Source)); err != nil {
		t.Fatal(err)
	}
	denied, err := executor.Controller(task)
	if err != nil {
		t.Fatal(err)
	}
	for name, effect := range map[string]func(context.Context) error{
		"prepare": denied.Prepare, "start": denied.Start, "shutdown": denied.Shutdown,
		"terminate": denied.Terminate, "remove": denied.Remove,
	} {
		if err := effect(ctx); !errors.Is(err, execution.ErrUnsafe) {
			t.Fatalf("uninitialized source %s: %v", name, err)
		}
	}
	containers, err := executor.client.Containers(runtimeContext(ctx), "id==ts-"+task.ID)
	if err != nil || len(containers) != 0 {
		t.Fatalf("denied task mutated actual runtime: containers=%d err=%v", len(containers), err)
	}
}
