// This file tests the workload executor: driver dispatch of serialized plans,
// fail-closed cordon behavior, registry tracking, and drain observations.
package hostagent

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/runtime"
)

// marshalHostAgentPlan serializes one canonical plan through the runtime
// package's MarshalJSON, the exact bytes the control plane would send.
func marshalHostAgentPlan(plan runtime.HostRuntimePlan) ([]byte, error) {
	return json.Marshal(plan)
}

const executorTestDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func executorTestNodeId(t *testing.T) NodeId {
	t.Helper()
	id, err := NewNodeId("gru-node-1")
	if err != nil {
		t.Fatalf("node id: %v", err)
	}
	return id
}

func executorTestPlan(
	t *testing.T,
	role runtime.AdmittedRole,
	driver runtime.RuntimeDriver,
	allocationId string,
) runtime.HostRuntimePlan {
	t.Helper()
	plan, err := runtime.NewHostRuntimePlan(
		role,
		driver,
		mustExecutorAllocationId(t, allocationId),
		mustExecutorDigest(t),
		runtime.HostArchitectureArm64,
		nil)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return plan
}

func mustExecutorAllocationId(t *testing.T, value string) runtime.RuntimeAllocationId {
	t.Helper()
	id, err := runtime.NewRuntimeAllocationId(value)
	if err != nil {
		t.Fatalf("allocation id: %v", err)
	}
	return id
}

func mustExecutorDigest(t *testing.T) runtime.ArtifactDigest {
	t.Helper()
	digest, err := runtime.NewArtifactDigest(executorTestDigest)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	return digest
}

func executorTestCommand(t *testing.T, plan runtime.HostRuntimePlan, commandId string) WorkloadCommandRequest {
	t.Helper()
	payload, err := marshalHostAgentPlan(plan)
	if err != nil {
		t.Fatalf("marshal plan: %v", err)
	}
	command, err := NewWorkloadCommandRequest(payload, commandId)
	if err != nil {
		t.Fatalf("command: %v", err)
	}
	return command
}

// fakeNativeAdapter records calls and answers with fixed results.
type fakeNativeAdapter struct {
	convergeCalls int
	observeCalls  int
	stopCalls     int
	convergeErr   error
	observeErr    error
	stopErr       error
	observation   runtime.SystemdAllocationObservation
	seenPlans     []runtime.HostRuntimePlan
}

func (f *fakeNativeAdapter) Converge(ctx context.Context, plan runtime.HostRuntimePlan) error {
	f.convergeCalls++
	f.seenPlans = append(f.seenPlans, plan)
	return f.convergeErr
}

func (f *fakeNativeAdapter) Observe(ctx context.Context, plan runtime.HostRuntimePlan) (runtime.SystemdAllocationObservation, error) {
	f.observeCalls++
	f.seenPlans = append(f.seenPlans, plan)
	return f.observation, f.observeErr
}

func (f *fakeNativeAdapter) Stop(ctx context.Context, plan runtime.HostRuntimePlan) error {
	f.stopCalls++
	f.seenPlans = append(f.seenPlans, plan)
	return f.stopErr
}

// fakeContainerAdapter records calls and answers with fixed results.
type fakeContainerAdapter struct {
	convergeCalls int
	observeCalls  int
	stopCalls     int
	deleteCalls   int
	convergeErr   error
	observeErr    error
	stopErr       error
	deleteErr     error
	observation   runtime.PodmanAllocationObservation
	seenPlans     []runtime.HostRuntimePlan
}

func (f *fakeContainerAdapter) Converge(ctx context.Context, plan runtime.HostRuntimePlan) error {
	f.convergeCalls++
	f.seenPlans = append(f.seenPlans, plan)
	return f.convergeErr
}

func (f *fakeContainerAdapter) Observe(ctx context.Context, plan runtime.HostRuntimePlan) (runtime.PodmanAllocationObservation, error) {
	f.observeCalls++
	f.seenPlans = append(f.seenPlans, plan)
	return f.observation, f.observeErr
}

func (f *fakeContainerAdapter) Stop(ctx context.Context, plan runtime.HostRuntimePlan) error {
	f.stopCalls++
	f.seenPlans = append(f.seenPlans, plan)
	return f.stopErr
}

func (f *fakeContainerAdapter) Delete(ctx context.Context, plan runtime.HostRuntimePlan) error {
	f.deleteCalls++
	f.seenPlans = append(f.seenPlans, plan)
	return f.deleteErr
}

// runningSystemdObservation builds one running systemd observation of a unit.
func runningSystemdObservation() runtime.SystemdAllocationObservation {
	return runtime.SystemdAllocationObservation{
		UnitName: "terrascale-unit.service",
		State:    runtime.SystemdAllocationStateRunning,
		Result:   "success",
	}
}

// runningPodmanObservation builds one running podman observation.
func runningPodmanObservation(t *testing.T) runtime.PodmanAllocationObservation {
	t.Helper()
	observation, err := runtime.NewPodmanAllocationObservation(
		runtime.PodmanAllocationStateRunning,
		"registry.terrascale.internal/terrascale/x@sha256:"+executorTestDigest,
		map[string]string{runtime.PodmanLabelAllocation: "terrascale-unit"},
		true)
	if err != nil {
		t.Fatalf("podman observation: %v", err)
	}
	return observation
}

func TestNewWorkloadExecutorValidatesConfiguration(t *testing.T) {
	node := executorTestNodeId(t)
	tests := []struct {
		name      string
		config    WorkloadExecutorConfig
		wantParam string
	}{
		{
			name:      "missing node id",
			config:    WorkloadExecutorConfig{Systemd: &fakeNativeAdapter{}, Container: &fakeContainerAdapter{}},
			wantParam: "value",
		},
		{
			name:      "missing systemd adapter",
			config:    WorkloadExecutorConfig{NodeId: node, Container: &fakeContainerAdapter{}},
			wantParam: "Systemd",
		},
		{
			name:      "missing container adapter",
			config:    WorkloadExecutorConfig{NodeId: node, Systemd: &fakeNativeAdapter{}},
			wantParam: "Container",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewWorkloadExecutor(test.config); err == nil {
				t.Fatal("expected a configuration error")
			} else if !errorsAsParam(err, test.wantParam) {
				t.Fatalf("error %v does not reference param %s", err, test.wantParam)
			}
		})
	}
}

func TestConvergeDispatchesSerializedPlansByDriver(t *testing.T) {
	tests := []struct {
		name       string
		plan       runtime.HostRuntimePlan
		wantDetail string
	}{
		{
			name:       "native systemd plan reaches the systemd adapter",
			plan:       executorTestPlan(t, runtime.AdmittedRoleOrchestrator, runtime.RuntimeDriverNativeSystemd, "gru-orchestrator-1"),
			wantDetail: "converged through the NativeSystemd driver",
		},
		{
			name:       "oci plan reaches the container adapter",
			plan:       executorTestPlan(t, runtime.AdmittedRoleGrafana, runtime.RuntimeDriverOciContainer, "grafana-1"),
			wantDetail: "converged through the OciContainer driver",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			systemd := &fakeNativeAdapter{}
			container := &fakeContainerAdapter{}
			executor := newExecutorForTest(t, systemd, container)

			receipt, err := executor.Converge(context.Background(),
				executorTestCommand(t, test.plan, "cmd-converge-1"))

			if err != nil {
				t.Fatalf("converge: %v", err)
			}
			if !receipt.Accepted {
				t.Fatalf("receipt not accepted: %+v", receipt)
			}
			if receipt.CommandId != "cmd-converge-1" {
				t.Fatalf("command id = %q", receipt.CommandId)
			}
			if !strings.Contains(receipt.Detail, test.wantDetail) {
				t.Fatalf("detail = %q", receipt.Detail)
			}
			expectedFingerprint, err := runtime.CanonicalPlanFingerprint.Compute(test.plan)
			if err != nil {
				t.Fatalf("fingerprint: %v", err)
			}
			if receipt.PlanFingerprint != expectedFingerprint {
				t.Fatalf("fingerprint = %q, want %q", receipt.PlanFingerprint, expectedFingerprint)
			}
			if test.plan.Driver == runtime.RuntimeDriverNativeSystemd {
				if systemd.convergeCalls != 1 || container.convergeCalls != 0 {
					t.Fatalf("systemd calls = %d, container calls = %d",
						systemd.convergeCalls, container.convergeCalls)
				}
				if len(systemd.seenPlans) != 1 || !reflect.DeepEqual(systemd.seenPlans[0], test.plan) {
					t.Fatal("the dispatched plan must round trip byte-equal through JSON")
				}
				return
			}
			if container.convergeCalls != 1 || systemd.convergeCalls != 0 {
				t.Fatalf("systemd calls = %d, container calls = %d",
					systemd.convergeCalls, container.convergeCalls)
			}
			if len(container.seenPlans) != 1 || !reflect.DeepEqual(container.seenPlans[0], test.plan) {
				t.Fatal("the dispatched plan must round trip byte-equal through JSON")
			}
		})
	}
}

func TestConvergeRejectsNonCanonicalPlanPayload(t *testing.T) {
	executor := newExecutorForTest(t, &fakeNativeAdapter{}, &fakeContainerAdapter{})
	command, err := NewWorkloadCommandRequest([]byte(`{"schemaVersion":9}`), "cmd-bad-1")
	if err != nil {
		t.Fatalf("command: %v", err)
	}

	receipt, err := executor.Converge(context.Background(), command)

	if err == nil {
		t.Fatal("expected a decode error")
	}
	if receipt.Accepted {
		t.Fatalf("rejected payload must not be accepted: %+v", receipt)
	}
	if receipt.PlanFingerprint != "" {
		t.Fatalf("fingerprint = %q, want empty", receipt.PlanFingerprint)
	}
	if !strings.Contains(receipt.Detail, "canonical runtime plan") {
		t.Fatalf("detail = %q", receipt.Detail)
	}
}

func TestCordonedExecutorRefusesNewConvergeWorkFailClosed(t *testing.T) {
	systemd := &fakeNativeAdapter{}
	executor := newExecutorForTest(t, systemd, &fakeContainerAdapter{})
	plan := executorTestPlan(t, runtime.AdmittedRoleOrchestrator, runtime.RuntimeDriverNativeSystemd, "gru-orchestrator-1")
	executor.SetCordoned(true)

	receipt, err := executor.Converge(context.Background(), executorTestCommand(t, plan, "cmd-cordoned"))

	if err != nil {
		t.Fatalf("a cordon rejection is a processed answer, not a failure: %v", err)
	}
	if receipt.Accepted {
		t.Fatalf("cordoned node must refuse work: %+v", receipt)
	}
	if systemd.convergeCalls != 0 {
		t.Fatal("a cordoned node must not touch the adapter")
	}
	if !strings.Contains(receipt.Detail, "cordoned") {
		t.Fatalf("detail = %q", receipt.Detail)
	}
	expectedFingerprint, _ := runtime.CanonicalPlanFingerprint.Compute(plan)
	if receipt.PlanFingerprint != expectedFingerprint {
		t.Fatal("the rejected plan's fingerprint must still be reported")
	}

	observeReceipt, err := executor.Observe(context.Background(), executorTestCommand(t, plan, "cmd-observe-1"))
	if err != nil {
		t.Fatalf("observe must keep answering while cordoned: %v", err)
	}
	if !observeReceipt.Accepted {
		t.Fatalf("observe receipt: %+v", observeReceipt)
	}
	if systemd.observeCalls != 1 {
		t.Fatal("observe must reach the adapter while cordoned")
	}
}

func TestObserveTracksPendingAllocations(t *testing.T) {
	systemd := &fakeNativeAdapter{observation: runningSystemdObservation()}
	executor := newExecutorForTest(t, systemd, &fakeContainerAdapter{})
	plan := executorTestPlan(t, runtime.AdmittedRoleOrchestrator, runtime.RuntimeDriverNativeSystemd, "gru-orchestrator-1")

	if _, err := executor.Converge(context.Background(), executorTestCommand(t, plan, "cmd-1")); err != nil {
		t.Fatalf("converge: %v", err)
	}
	if pending := executor.PendingAllocations(); pending != 1 {
		t.Fatalf("pending after converge = %d, want 1", pending)
	}

	receipt, err := executor.Observe(context.Background(), executorTestCommand(t, plan, "cmd-2"))
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if !receipt.Accepted || !strings.Contains(receipt.Detail, "Running") {
		t.Fatalf("observe receipt: %+v", receipt)
	}
	if pending := executor.PendingAllocations(); pending != 0 {
		t.Fatalf("pending after running observation = %d, want 0", pending)
	}
}

func TestStopAnswersWhileCordonedAndDeleteRemovesRecords(t *testing.T) {
	systemd := &fakeNativeAdapter{
		observation: runtime.SystemdAllocationObservation{
			UnitName: "terrascale-unit.service",
			State:    runtime.SystemdAllocationStateAbsent,
			Result:   "not-found",
		},
	}
	container := &fakeContainerAdapter{observation: runningPodmanObservation(t)}
	executor := newExecutorForTest(t, systemd, container)
	nativePlan := executorTestPlan(t, runtime.AdmittedRoleOrchestrator, runtime.RuntimeDriverNativeSystemd, "gru-orchestrator-1")
	ociPlan := executorTestPlan(t, runtime.AdmittedRoleGrafana, runtime.RuntimeDriverOciContainer, "grafana-1")
	executor.SetCordoned(true)

	stopReceipt, err := executor.Stop(context.Background(), executorTestCommand(t, ociPlan, "cmd-stop-1"))
	if err != nil {
		t.Fatalf("stop must answer while cordoned: %v", err)
	}
	if !stopReceipt.Accepted || container.stopCalls != 1 {
		t.Fatalf("stop receipt: %+v, container stops = %d", stopReceipt, container.stopCalls)
	}

	deleteReceipt, err := executor.Delete(context.Background(), executorTestCommand(t, ociPlan, "cmd-delete-1"))
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if !deleteReceipt.Accepted || container.deleteCalls != 1 {
		t.Fatalf("delete receipt: %+v, deletes = %d", deleteReceipt, container.deleteCalls)
	}

	nativeDelete, err := executor.Delete(context.Background(), executorTestCommand(t, nativePlan, "cmd-delete-2"))
	if err != nil {
		t.Fatalf("native delete: %v", err)
	}
	if !nativeDelete.Accepted || systemd.stopCalls != 1 {
		t.Fatalf("native delete receipt: %+v, systemd stops = %d", nativeDelete, systemd.stopCalls)
	}

	observations, err := executor.ObserveAllocations(context.Background())
	if err != nil {
		t.Fatalf("observe allocations: %v", err)
	}
	if len(observations) != 0 {
		t.Fatalf("deleted allocations must be forgotten, got %+v", observations)
	}
}

func TestNativeDeleteRejectsStillRunningAllocation(t *testing.T) {
	systemd := &fakeNativeAdapter{observation: runningSystemdObservation()}
	executor := newExecutorForTest(t, systemd, &fakeContainerAdapter{})
	plan := executorTestPlan(t, runtime.AdmittedRoleOrchestrator, runtime.RuntimeDriverNativeSystemd, "gru-orchestrator-1")

	receipt, err := executor.Delete(context.Background(), executorTestCommand(t, plan, "cmd-delete-1"))

	if err == nil {
		t.Fatal("a still-running unit after deletion is a failure")
	}
	if receipt.Accepted {
		t.Fatalf("receipt must not be accepted: %+v", receipt)
	}
	if !strings.Contains(receipt.Detail, "still Running") {
		t.Fatalf("detail = %q", receipt.Detail)
	}
}

func TestObserveAllocationsReportsSortedStatesAndFailsClosed(t *testing.T) {
	systemd := &fakeNativeAdapter{observation: runningSystemdObservation()}
	container := &fakeContainerAdapter{observation: runningPodmanObservation(t), observeErr: errors.New("podman refused")}
	executor := newExecutorForTest(t, systemd, container)
	nativePlan := executorTestPlan(t, runtime.AdmittedRoleOrchestrator, runtime.RuntimeDriverNativeSystemd, "z-late-allocation")
	ociPlan := executorTestPlan(t, runtime.AdmittedRoleGrafana, runtime.RuntimeDriverOciContainer, "a-first-allocation")
	for _, plan := range []runtime.HostRuntimePlan{nativePlan, ociPlan} {
		if _, err := executor.Converge(context.Background(), executorTestCommand(t, plan, "cmd-1")); err != nil {
			t.Fatalf("converge: %v", err)
		}
	}

	observations, err := executor.ObserveAllocations(context.Background())

	if err == nil {
		t.Fatal("the podman observation failure must surface")
	}
	if len(observations) != 2 {
		t.Fatalf("observations = %+v", observations)
	}
	if observations[0].AllocationId != "a-first-allocation" || observations[1].AllocationId != "z-late-allocation" {
		t.Fatalf("observations must be ordered by allocation id: %+v", observations)
	}
	if observations[0].State != allocationStateUnknown || observations[0].Running {
		t.Fatalf("a failed observation must be Unknown, got %+v", observations[0])
	}
	if observations[1].State != "Running" || !observations[1].Running {
		t.Fatalf("native observation = %+v", observations[1])
	}
	if executor.Drained(observations) {
		t.Fatal("a node with running or unknown allocations is not drained")
	}
	if executor.Cordoned() {
		t.Fatal("a node reports drained only after cordon")
	}
	executor.SetCordoned(true)
	if executor.Drained(observations) {
		t.Fatal("unknown observations never count as drained")
	}

	systemd.observation = runtime.SystemdAllocationObservation{
		UnitName: "terrascale-unit.service",
		State:    runtime.SystemdAllocationStateStopped,
		Result:   "success",
	}
	container.observeErr = nil
	container.observation = mustStoppedPodmanObservation(t)
	stopped, err := executor.ObserveAllocations(context.Background())
	if err != nil {
		t.Fatalf("observe allocations: %v", err)
	}
	if !executor.Drained(stopped) {
		t.Fatalf("a cordoned node with stopped allocations is drained: %+v", stopped)
	}
}

func mustStoppedPodmanObservation(t *testing.T) runtime.PodmanAllocationObservation {
	t.Helper()
	observation, err := runtime.NewPodmanAllocationObservation(
		runtime.PodmanAllocationStateStopped,
		"registry.terrascale.internal/terrascale/x@sha256:"+executorTestDigest,
		map[string]string{runtime.PodmanLabelAllocation: "terrascale-unit"},
		false)
	if err != nil {
		t.Fatalf("podman observation: %v", err)
	}
	return observation
}

func newExecutorForTest(t *testing.T, systemd NativePlanAdapter, container ContainerPlanAdapter) *WorkloadExecutor {
	t.Helper()
	executor, err := NewWorkloadExecutor(WorkloadExecutorConfig{
		NodeId:    executorTestNodeId(t),
		Systemd:   systemd,
		Container: container,
	})
	if err != nil {
		t.Fatalf("executor: %v", err)
	}
	return executor
}
