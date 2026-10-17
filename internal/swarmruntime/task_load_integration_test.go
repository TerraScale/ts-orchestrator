package swarmruntime

import (
	"context"
	"errors"
	"testing"
	"time"

	swarmexec "github.com/moby/swarmkit/v2/agent/exec"
	"github.com/moby/swarmkit/v2/api"
)

// The existing material fixture owns runtime-only test admission. These reads
// qualify actual task/cgroup telemetry, not its enrollment or OCI provenance.
func checkExecutorTaskLoad(t *testing.T, ctx context.Context, executor *Executor, running *controller, failMaterial func(error)) {
	t.Helper()
	first, err := executor.ReadTaskLoad(ctx)
	if err != nil || len(first) != 1 || first[0].Role != "ts-auth" || first[0].CPUCores != nil ||
		first[0].MemoryBytes == nil || *first[0].MemoryBytes == 0 || !first[0].LimitsRead ||
		first[0].CPULimit == nil || *first[0].CPULimit != 0.25 || first[0].MemoryLimit == nil || *first[0].MemoryLimit > 64<<20 {
		t.Fatalf("actual task cgroup did not produce bounded initial telemetry: %+v %v", first, err)
	}
	if len(first[0].Tasks) != 1 || first[0].Tasks[0].TaskID != running.task.ID || first[0].Tasks[0].ServiceID != running.task.ServiceID ||
		first[0].Tasks[0].NodeID != running.task.NodeID || first[0].Tasks[0].Fingerprint != running.fingerprint {
		t.Fatalf("actual task measurement lost its exact assignment identity: %+v", first[0].Tasks)
	}
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-time.After(25 * time.Millisecond):
	}
	second, err := executor.ReadTaskLoad(ctx)
	if err != nil || len(second) != 1 || second[0].CPUCores == nil || *second[0].CPUCores < 0 || second[0].MemoryBytes == nil {
		t.Fatalf("actual task cumulative CPU counter did not produce interval usage: %+v %v", second, err)
	}
	missing := running.task.Copy()
	missing.ID += "missing"
	allocated, err := executor.Controller(missing)
	if err != nil {
		t.Fatal(err)
	}
	defer allocated.Close()
	missing.DesiredState = api.TaskStateShutdown
	missing.Status.State = api.TaskStatePreparing
	if err := allocated.Update(ctx, missing); err != nil {
		t.Fatal(err)
	}
	partial, err := executor.ReadTaskLoad(ctx)
	if err != nil || len(partial) != 1 || partial[0].Role != "ts-auth" || partial[0].CPUCores != nil || partial[0].MemoryBytes != nil || partial[0].LimitsRead {
		t.Fatalf("one missing allocated task became a partial role measurement: %+v %v", partial, err)
	}
	if len(partial[0].Tasks) != 2 || partial[0].Tasks[0].TaskID != running.task.ID || partial[0].Tasks[1].TaskID != missing.ID {
		t.Fatalf("unknown usage lost the complete allocated task set: %+v", partial[0].Tasks)
	}
	missing.DesiredState = api.TaskStateRunning
	failMaterial(swarmexec.MakeTemporary(errors.New("material read temporarily unavailable")))
	defer failMaterial(nil)
	status, err := swarmexec.Do(ctx, missing, allocated)
	if !errors.Is(err, swarmexec.ErrTaskRetry) || status.State != api.TaskStatePreparing {
		t.Fatalf("upstream did not preserve the transient preparation reservation: %+v %v", status, err)
	}
	retained, err := executor.ReadTaskLoad(ctx)
	if err != nil || len(retained) != 1 || len(retained[0].Tasks) != 2 || retained[0].MemoryBytes != nil {
		t.Fatalf("transient preparation dropped an unknown live reservation: %+v %v", retained, err)
	}
	failMaterial(errors.New("material authority rejected this task"))
	status, err = swarmexec.Do(ctx, missing, allocated)
	if err != nil || status.State != api.TaskStateRejected {
		t.Fatalf("upstream did not reject the unexecutable task: %+v %v", status, err)
	}
	terminal, err := executor.ReadTaskLoad(ctx)
	if err != nil || len(terminal) != 1 || len(terminal[0].Tasks) != 1 || terminal[0].Tasks[0].TaskID != running.task.ID || terminal[0].MemoryBytes == nil {
		t.Fatalf("retained rejected controller prevented current task measurement: %+v %v", terminal, err)
	}
}

func checkExecutorTerminalTaskLoad(t *testing.T, ctx context.Context, executor *Executor, running *controller) {
	t.Helper()
	shutdown := running.task.Copy()
	shutdown.Status.State, shutdown.DesiredState = api.TaskStateRunning, api.TaskStateShutdown
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	status, err := swarmexec.Do(canceled, shutdown, running)
	if !errors.Is(err, swarmexec.ErrTaskRetry) || status.State != api.TaskStateRunning {
		t.Fatalf("canceled shutdown became terminal: %+v %v", status, err)
	}
	retained, err := executor.ReadTaskLoad(ctx)
	if err != nil || len(retained) != 1 || len(retained[0].Tasks) != 1 || retained[0].Tasks[0].TaskID != running.task.ID {
		t.Fatalf("canceled shutdown lost its live reservation: %+v %v", retained, err)
	}
	status, err = swarmexec.Do(ctx, shutdown, running)
	if err != nil || status.State != api.TaskStateShutdown {
		t.Fatalf("actual running task did not reach terminal shutdown: %+v %v", status, err)
	}
	terminal, err := executor.ReadTaskLoad(ctx)
	if err != nil || len(terminal) != 0 {
		t.Fatalf("terminal historical controller remained in reported task pins before Close: %+v %v", terminal, err)
	}
	if _, err := running.container(ctx); err != nil {
		t.Fatalf("telemetry cleanup deleted the retained runtime container: %v", err)
	}
	shutdown.Status = *status
	historical, err := executor.Controller(shutdown)
	if err != nil {
		t.Fatal(err)
	}
	defer historical.Close()
	recovered, err := executor.ReadTaskLoad(ctx)
	if err != nil || len(recovered) != 0 {
		t.Fatalf("recovered terminal history regained a reservation: %+v %v", recovered, err)
	}
}
