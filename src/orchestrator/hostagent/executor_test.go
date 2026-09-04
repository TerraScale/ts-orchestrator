// This file tests the workload executor: driver dispatch of serialized plans,
// fail-closed cordon behavior, allocation tracking, and drain observations.
package hostagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

type concurrentNativeAdapter struct {
	convergeCalls atomic.Int32
	entered       chan struct{}
	release       chan struct{}
}

func (a *concurrentNativeAdapter) Converge(ctx context.Context, plan runtime.HostRuntimePlan) error {
	a.convergeCalls.Add(1)
	a.entered <- struct{}{}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-a.release:
		return nil
	}
}

func (a *concurrentNativeAdapter) Observe(context.Context, runtime.HostRuntimePlan) (runtime.SystemdAllocationObservation, error) {
	return runtime.SystemdAllocationObservation{State: runtime.SystemdAllocationStateAbsent}, nil
}

func (a *concurrentNativeAdapter) Stop(context.Context, runtime.HostRuntimePlan) error { return nil }

// runningSystemdObservation builds one running systemd observation of a unit.
func runningSystemdObservation() runtime.SystemdAllocationObservation {
	return runtime.SystemdAllocationObservation{
		UnitName: "terrascale-unit.service",
		State:    runtime.SystemdAllocationStateRunning,
		Result:   "success",
	}
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
			config:    WorkloadExecutorConfig{Systemd: &fakeNativeAdapter{}},
			wantParam: "value",
		},
		{
			name:      "missing systemd adapter",
			config:    WorkloadExecutorConfig{NodeId: node},
			wantParam: "Systemd",
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
	plan := executorTestPlan(t, runtime.AdmittedRoleAutoscaler, runtime.RuntimeDriverNativeSystemd, "gru-orchestrator-1")
	systemd := &fakeNativeAdapter{}
	executor := newExecutorForTest(t, systemd)

	receipt, err := executor.Converge(context.Background(),
		executorTestCommand(t, plan, "cmd-converge-1"))

	if err != nil {
		t.Fatalf("converge: %v", err)
	}
	if !receipt.Accepted {
		t.Fatalf("receipt not accepted: %+v", receipt)
	}
	if receipt.CommandId != "cmd-converge-1" {
		t.Fatalf("command id = %q", receipt.CommandId)
	}
	if !strings.Contains(receipt.Detail, "converged through the NativeSystemd driver") {
		t.Fatalf("detail = %q", receipt.Detail)
	}
	expectedFingerprint, err := runtime.CanonicalPlanFingerprint.Compute(plan)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	if receipt.PlanFingerprint != expectedFingerprint {
		t.Fatalf("fingerprint = %q, want %q", receipt.PlanFingerprint, expectedFingerprint)
	}
	if systemd.convergeCalls != 1 {
		t.Fatalf("systemd calls = %d, want 1", systemd.convergeCalls)
	}
	if len(systemd.seenPlans) != 1 || !reflect.DeepEqual(systemd.seenPlans[0], plan) {
		t.Fatal("the dispatched plan must round trip byte-equal through JSON")
	}
}

func TestConvergeRejectsRetiredOciDriver(t *testing.T) {
	executor := newExecutorForTest(t, &fakeNativeAdapter{})
	plan := executorTestPlan(t, runtime.AdmittedRoleAutoscaler, runtime.RuntimeDriverNativeSystemd, "gru-orchestrator-1")
	payload, err := marshalHostAgentPlan(plan)
	if err != nil {
		t.Fatalf("marshal plan: %v", err)
	}
	retired := strings.Replace(string(payload), `"driver":"nativeSystemd"`, `"driver":"ociContainer"`, 1)
	command, err := NewWorkloadCommandRequest([]byte(retired), "cmd-retired-1")
	if err != nil {
		t.Fatalf("command: %v", err)
	}
	receipt, err := executor.Converge(context.Background(), command)
	if err == nil {
		t.Fatal("expected a rejection for the retired OCI driver")
	}
	if receipt.Accepted {
		t.Fatalf("retired driver payload must not be accepted: %+v", receipt)
	}
}

func TestConvergeRejectsNonCanonicalPlanPayload(t *testing.T) {
	executor := newExecutorForTest(t, &fakeNativeAdapter{})
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
	executor := newExecutorForTest(t, systemd)
	plan := executorTestPlan(t, runtime.AdmittedRoleAutoscaler, runtime.RuntimeDriverNativeSystemd, "gru-orchestrator-1")
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
	executor := newExecutorForTest(t, systemd)
	plan := executorTestPlan(t, runtime.AdmittedRoleAutoscaler, runtime.RuntimeDriverNativeSystemd, "gru-orchestrator-1")

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
	executor := newExecutorForTest(t, systemd)
	nativePlan := executorTestPlan(t, runtime.AdmittedRoleAutoscaler, runtime.RuntimeDriverNativeSystemd, "gru-orchestrator-1")
	secondPlan := executorTestPlan(t, runtime.AdmittedRoleNats, runtime.RuntimeDriverNativeSystemd, "gru-nats-1")
	executor.SetCordoned(true)

	stopReceipt, err := executor.Stop(context.Background(), executorTestCommand(t, secondPlan, "cmd-stop-1"))
	if err != nil {
		t.Fatalf("stop must answer while cordoned: %v", err)
	}
	if !stopReceipt.Accepted || systemd.stopCalls != 1 {
		t.Fatalf("stop receipt: %+v, systemd stops = %d", stopReceipt, systemd.stopCalls)
	}

	deleteReceipt, err := executor.Delete(context.Background(), executorTestCommand(t, secondPlan, "cmd-delete-1"))
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if !deleteReceipt.Accepted || systemd.stopCalls != 2 {
		t.Fatalf("delete receipt: %+v, systemd stops = %d", deleteReceipt, systemd.stopCalls)
	}

	nativeDelete, err := executor.Delete(context.Background(), executorTestCommand(t, nativePlan, "cmd-delete-2"))
	if err != nil {
		t.Fatalf("native delete: %v", err)
	}
	if !nativeDelete.Accepted || systemd.stopCalls != 3 {
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
	executor := newExecutorForTest(t, systemd)
	plan := executorTestPlan(t, runtime.AdmittedRoleAutoscaler, runtime.RuntimeDriverNativeSystemd, "gru-orchestrator-1")

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
	systemd := &fakeNativeAdapter{observation: runningSystemdObservation(), observeErr: errors.New("systemd refused")}
	executor := newExecutorForTest(t, systemd)
	nativePlan := executorTestPlan(t, runtime.AdmittedRoleAutoscaler, runtime.RuntimeDriverNativeSystemd, "z-late-allocation")
	secondPlan := executorTestPlan(t, runtime.AdmittedRoleNats, runtime.RuntimeDriverNativeSystemd, "a-first-allocation")
	for _, plan := range []runtime.HostRuntimePlan{nativePlan, secondPlan} {
		if _, err := executor.Converge(context.Background(), executorTestCommand(t, plan, "cmd-1")); err != nil {
			t.Fatalf("converge: %v", err)
		}
	}

	observations, err := executor.ObserveAllocations(context.Background())

	if err == nil {
		t.Fatal("the systemd observation failure must surface")
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
	if observations[1].State != allocationStateUnknown || observations[1].Running {
		t.Fatalf("a failed observation must be Unknown, got %+v", observations[1])
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

	systemd.observeErr = nil
	systemd.observation = runtime.SystemdAllocationObservation{
		UnitName: "terrascale-unit.service",
		State:    runtime.SystemdAllocationStateStopped,
		Result:   "success",
	}
	stopped, err := executor.ObserveAllocations(context.Background())
	if err != nil {
		t.Fatalf("observe allocations: %v", err)
	}
	if !executor.Drained(stopped) {
		t.Fatalf("a cordoned node with stopped allocations is drained: %+v", stopped)
	}
}

func newExecutorForTest(t *testing.T, systemd NativePlanAdapter) *WorkloadExecutor {
	t.Helper()
	executor, err := NewWorkloadExecutor(WorkloadExecutorConfig{
		NodeId:  executorTestNodeId(t),
		Systemd: systemd,
	})
	if err != nil {
		t.Fatalf("executor: %v", err)
	}
	return executor
}

func TestConvergeReservesCapacityBeforeConcurrentAdapterCalls(t *testing.T) {
	adapter := &concurrentNativeAdapter{
		entered: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	executor := newExecutorForTest(t, adapter)
	executor.maximumTrackedAllocations = 1

	const callers = 32
	type result struct {
		receipt ConvergeReceipt
		err     error
	}
	results := make(chan result, callers)
	var group sync.WaitGroup
	for index := 0; index < callers; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			plan := executorTestPlan(t, runtime.AdmittedRoleAutoscaler,
				runtime.RuntimeDriverNativeSystemd, fmt.Sprintf("concurrent-%d", index))
			receipt, err := executor.Converge(context.Background(),
				executorTestCommand(t, plan, fmt.Sprintf("cmd-concurrent-%d", index)))
			results <- result{receipt: receipt, err: err}
		}(index)
	}

	select {
	case <-adapter.entered:
	case <-time.After(time.Second):
		t.Fatal("the admitted adapter call did not start")
	}
	close(adapter.release)
	group.Wait()
	close(results)

	accepted := 0
	for outcome := range results {
		if outcome.err == nil && outcome.receipt.Accepted {
			accepted++
		} else if outcome.err == nil {
			// Capacity rejection is a processed receipt with its cause returned.
			continue
		}
	}
	if accepted != 1 {
		t.Fatalf("accepted converges = %d, want 1", accepted)
	}
	if got := adapter.convergeCalls.Load(); got != 1 {
		t.Fatalf("adapter converge calls = %d, want 1", got)
	}
	if got := len(executor.records); got != 1 {
		t.Fatalf("tracked records = %d, want 1", got)
	}
}

func TestConvergeRejectsOverlappingOperationForSameAllocation(t *testing.T) {
	adapter := &concurrentNativeAdapter{
		entered: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	executor := newExecutorForTest(t, adapter)
	plan := executorTestPlan(t, runtime.AdmittedRoleAutoscaler,
		runtime.RuntimeDriverNativeSystemd, "same-allocation")
	firstCommand := executorTestCommand(t, plan, "cmd-overlap-first")
	secondCommand := executorTestCommand(t, plan, "cmd-overlap-second")

	type result struct {
		receipt ConvergeReceipt
		err     error
	}
	firstResult := make(chan result, 1)
	go func() {
		receipt, err := executor.Converge(context.Background(), firstCommand)
		firstResult <- result{receipt: receipt, err: err}
	}()
	select {
	case <-adapter.entered:
	case <-time.After(time.Second):
		t.Fatal("the first adapter call did not start")
	}

	secondReceipt, secondErr := executor.Converge(context.Background(), secondCommand)
	if secondErr == nil || secondReceipt.Accepted {
		t.Fatalf("overlapping converge was accepted: receipt=%+v err=%v", secondReceipt, secondErr)
	}
	if got := adapter.convergeCalls.Load(); got != 1 {
		t.Fatalf("adapter converge calls while first is active = %d, want 1", got)
	}

	close(adapter.release)
	first := <-firstResult
	if first.err != nil || !first.receipt.Accepted {
		t.Fatalf("first converge failed: receipt=%+v err=%v", first.receipt, first.err)
	}
}

func TestExistingAllocationOperatesAtCapacityAndDeleteReleasesSlot(t *testing.T) {
	systemd := &fakeNativeAdapter{}
	executor := newExecutorForTest(t, systemd)
	executor.maximumTrackedAllocations = 1
	first := executorTestPlan(t, runtime.AdmittedRoleAutoscaler,
		runtime.RuntimeDriverNativeSystemd, "capacity-first")
	second := executorTestPlan(t, runtime.AdmittedRoleNats,
		runtime.RuntimeDriverNativeSystemd, "capacity-second")

	if receipt, err := executor.Converge(context.Background(), executorTestCommand(t, first, "cmd-capacity-first")); err != nil || !receipt.Accepted {
		t.Fatalf("first converge: receipt=%+v err=%v", receipt, err)
	}
	if receipt, err := executor.Converge(context.Background(), executorTestCommand(t, second, "cmd-capacity-full")); err == nil || receipt.Accepted {
		t.Fatalf("full capacity converge: receipt=%+v err=%v", receipt, err)
	}
	if receipt, err := executor.Stop(context.Background(), executorTestCommand(t, second, "cmd-capacity-stop-full")); err == nil || receipt.Accepted {
		t.Fatalf("full capacity stop: receipt=%+v err=%v", receipt, err)
	}
	if receipt, err := executor.Delete(context.Background(), executorTestCommand(t, second, "cmd-capacity-delete-full")); err == nil || receipt.Accepted {
		t.Fatalf("full capacity delete: receipt=%+v err=%v", receipt, err)
	}
	if receipt, err := executor.Stop(context.Background(), executorTestCommand(t, first, "cmd-capacity-stop")); err != nil || !receipt.Accepted {
		t.Fatalf("existing stop at capacity: receipt=%+v err=%v", receipt, err)
	}
	if receipt, err := executor.Delete(context.Background(), executorTestCommand(t, first, "cmd-capacity-delete")); err != nil || !receipt.Accepted {
		t.Fatalf("delete at capacity: receipt=%+v err=%v", receipt, err)
	}
	if got := len(executor.records); got != 0 {
		t.Fatalf("records after successful delete = %d, want 0", got)
	}
	if receipt, err := executor.Converge(context.Background(), executorTestCommand(t, second, "cmd-capacity-retry")); err != nil || !receipt.Accepted {
		t.Fatalf("converge after delete release: receipt=%+v err=%v", receipt, err)
	}
	if systemd.convergeCalls != 2 || systemd.stopCalls != 2 {
		t.Fatalf("adapter calls = converge %d stop %d, want 2/2",
			systemd.convergeCalls, systemd.stopCalls)
	}
}

func TestUnknownObservationsDoNotConsumeCapacity(t *testing.T) {
	systemd := &fakeNativeAdapter{observation: runtime.SystemdAllocationObservation{
		State: runtime.SystemdAllocationStateAbsent,
	}}
	executor := newExecutorForTest(t, systemd)
	executor.maximumTrackedAllocations = 1

	nativePlan := executorTestPlan(t, runtime.AdmittedRoleAutoscaler,
		runtime.RuntimeDriverNativeSystemd, "unknown-absent")
	failingPlan := executorTestPlan(t, runtime.AdmittedRoleNats,
		runtime.RuntimeDriverNativeSystemd, "unknown-error")
	if receipt, err := executor.Observe(context.Background(), executorTestCommand(t, nativePlan, "cmd-unknown-absent")); err != nil || !receipt.Accepted {
		t.Fatalf("absent observation: receipt=%+v err=%v", receipt, err)
	}
	if got := len(executor.records); got != 0 {
		t.Fatalf("records after absent observation = %d, want 0", got)
	}
	systemd.observeErr = errors.New("observation unavailable")
	if receipt, err := executor.Observe(context.Background(), executorTestCommand(t, failingPlan, "cmd-unknown-error")); err == nil || receipt.Accepted {
		t.Fatalf("failed observation: receipt=%+v err=%v", receipt, err)
	}
	if got := len(executor.records); got != 0 {
		t.Fatalf("records after failed unknown observation = %d, want 0", got)
	}
	systemd.observeErr = nil

	trackedPlan := executorTestPlan(t, runtime.AdmittedRoleAutoscaler,
		runtime.RuntimeDriverNativeSystemd, "after-unknown")
	if receipt, err := executor.Converge(context.Background(), executorTestCommand(t, trackedPlan, "cmd-after-unknown")); err != nil || !receipt.Accepted {
		t.Fatalf("converge after unknown observations: receipt=%+v err=%v", receipt, err)
	}
}
