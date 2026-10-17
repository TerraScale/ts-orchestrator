package swarmruntime

import (
	"context"
	"testing"
	"time"
)

// The existing material fixture owns runtime-only test admission. These reads
// qualify actual task/cgroup telemetry, not its enrollment or OCI provenance.
func checkExecutorTaskLoad(t *testing.T, ctx context.Context, executor *Executor, running *controller) {
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
	partial, err := executor.ReadTaskLoad(ctx)
	if err != nil || len(partial) != 1 || partial[0].Role != "ts-auth" || partial[0].CPUCores != nil || partial[0].MemoryBytes != nil || partial[0].LimitsRead {
		t.Fatalf("one missing allocated task became a partial role measurement: %+v %v", partial, err)
	}
	if len(partial[0].Tasks) != 2 || partial[0].Tasks[0].TaskID != running.task.ID || partial[0].Tasks[1].TaskID != missing.ID {
		t.Fatalf("unknown usage lost the complete allocated task set: %+v", partial[0].Tasks)
	}
}
