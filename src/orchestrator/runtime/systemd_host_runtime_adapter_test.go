// This file ports tests/TerraScale.Orchestrator.Tests/
// SystemdHostRuntimeAdapterTests.cs.
package runtime

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"
)

type recordingHostRunner struct {
	pending  []HostCommandResult
	commands []hostCommandCall
}

type hostCommandCall struct {
	Executable string
	Arguments  []string
}

func newRecordingHostRunner(results ...HostCommandResult) *recordingHostRunner {
	return &recordingHostRunner{pending: append([]HostCommandResult{}, results...)}
}

func (r *recordingHostRunner) Run(ctx context.Context, executable string, arguments []string) (HostCommandResult, error) {
	r.commands = append(r.commands, hostCommandCall{Executable: executable, Arguments: append([]string{}, arguments...)})
	if len(r.pending) == 0 {
		return HostCommandResult{ExitCode: 0}, nil
	}
	result := r.pending[0]
	r.pending = r.pending[1:]
	return result, nil
}

func systemdTestNativePlan(t *testing.T) HostRuntimePlan {
	t.Helper()
	plan, err := NewHostRuntimePlan(
		AdmittedRoleOrchestrator,
		RuntimeDriverNativeSystemd,
		mustRuntimeAllocationId(t, "gru-orchestrator-1"),
		mustArtifactDigest(t, hostRuntimePlanDigest),
		HostArchitectureArm64,
		nil)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return plan
}

func runnerArgumentsContain(runner *recordingHostRunner, commandIndex int, expected string) bool {
	for _, argument := range runner.commands[commandIndex].Arguments {
		if argument == expected {
			return true
		}
	}
	return false
}

func TestConvergeUsesArgumentListsAndEveryCatalogSecurityProperty(t *testing.T) {
	runner := newRecordingHostRunner(
		HostCommandResult{ExitCode: 1, StandardOutput: "LoadState=not-found\n", StandardError: "Unit not found"},
		HostCommandResult{ExitCode: 0})
	adapter := NewSystemdHostRuntimeAdapter(runner, false)
	plan := systemdTestNativePlan(t)

	if err := adapter.Converge(context.Background(), plan); err != nil {
		t.Fatalf("converge: %v", err)
	}

	command := runner.commands[len(runner.commands)-1]
	if command.Executable != "/usr/bin/systemd-run" {
		t.Fatalf("unexpected executable %q", command.Executable)
	}
	if !runnerArgumentsContain(runner, len(runner.commands)-1, plan.Systemd.UnitName) {
		t.Fatal("the unit name must be passed")
	}
	fingerprint, err := CanonicalPlanFingerprint.Compute(plan)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	if !runnerArgumentsContain(runner, len(runner.commands)-1,
		"Description=TerraScale allocation "+plan.AllocationId.Value+" plan "+fingerprint) {
		t.Fatal("the canonical plan description must be passed")
	}
	for _, expected := range []string{
		"NoNewPrivileges=yes", "ProtectSystem=strict", "RestrictSUIDSGID=yes",
		"MemoryMax=" + strconv.FormatInt(plan.Resources.MemoryMaxBytes, 10),
		"CPUWeight=" + strconv.Itoa(plan.Resources.CpuWeight),
		"IOWeight=" + strconv.Itoa(plan.Resources.IoWeight),
		"Nice=" + strconv.Itoa(plan.Resources.Nice),
		plan.Systemd.Executable,
	} {
		if !runnerArgumentsContain(runner, len(runner.commands)-1, expected) {
			t.Fatalf("expected argument %q", expected)
		}
	}
	if runnerArgumentsContain(runner, len(runner.commands)-1, "--setenv") {
		t.Fatal("no environment may be injected")
	}
}

func TestObserveMapsSystemdStateWithoutTrustingFreeFormOutput(t *testing.T) {
	plan := systemdTestNativePlan(t)
	fingerprint, err := CanonicalPlanFingerprint.Compute(plan)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	runner := newRecordingHostRunner(HostCommandResult{ExitCode: 0, StandardOutput: "LoadState=loaded\n" +
		"ActiveState=active\nSubState=running\nMainPID=481\nResult=success\n" +
		"Description=TerraScale allocation " + plan.AllocationId.Value + " plan " + fingerprint + "\n"})
	adapter := NewSystemdHostRuntimeAdapter(runner, true)

	observation, err := adapter.Observe(context.Background(), plan)
	if err != nil {
		t.Fatalf("observe: %v", err)
	}

	if observation.State != SystemdAllocationStateRunning {
		t.Fatalf("unexpected state %v", observation.State)
	}
	if observation.MainProcessId == nil || *observation.MainProcessId != 481 {
		t.Fatalf("unexpected main pid %v", observation.MainProcessId)
	}
	if len(runner.commands) != 1 || runner.commands[0].Arguments[0] != "--user" {
		t.Fatal("the user manager must be selected with --user first")
	}
}

func TestConvergenceIsIdempotentAndInspectionFailuresStayFailClosed(t *testing.T) {
	plan := systemdTestNativePlan(t)
	fingerprint, err := CanonicalPlanFingerprint.Compute(plan)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	description := "Description=TerraScale allocation " + plan.AllocationId.Value + " plan " + fingerprint
	running := newRecordingHostRunner(HostCommandResult{ExitCode: 0, StandardOutput: "LoadState=loaded\n" +
		"ActiveState=active\nMainPID=481\nResult=success\n" + description + "\n"})

	if err := NewSystemdHostRuntimeAdapter(running, false).Converge(context.Background(), plan); err != nil {
		t.Fatalf("converge: %v", err)
	}
	if len(running.commands) != 1 || running.commands[0].Executable != "/usr/bin/systemctl" {
		t.Fatal("a running allocation must only be inspected")
	}

	var operationError *InvalidOperationError
	unavailable := newRecordingHostRunner(HostCommandResult{ExitCode: 1, StandardError: "D-Bus unavailable"})
	err = NewSystemdHostRuntimeAdapter(unavailable, false).Converge(context.Background(), plan)
	if !errors.As(err, &operationError) {
		t.Fatalf("expected InvalidOperationError, got %v", err)
	}
	if len(unavailable.commands) != 1 {
		t.Fatalf("inspection failure must stop after one command: %d", len(unavailable.commands))
	}

	foreign := newRecordingHostRunner(HostCommandResult{ExitCode: 0, StandardOutput: "LoadState=loaded\n" +
		"ActiveState=active\nMainPID=481\nResult=success\nDescription=foreign\n"})
	err = NewSystemdHostRuntimeAdapter(foreign, false).Converge(context.Background(), plan)
	if !errors.As(err, &operationError) {
		t.Fatalf("expected InvalidOperationError, got %v", err)
	}
	if len(foreign.commands) != 1 {
		t.Fatalf("a foreign allocation must be fenced after inspection: %d", len(foreign.commands))
	}
}

func TestAdapterRejectsAPlanWithInjectedExecutableOrProperty(t *testing.T) {
	original := systemdTestNativePlan(t)
	injectedSystemd := *original.Systemd
	injectedSystemd.Executable = "/bin/sh"
	injectedSystemd.Arguments = []string{"-c", "arbitrary"}
	injectedSystemd.Properties = append(append([]string{}, original.Systemd.Properties...), "Environment=SECRET=value")
	injected := original
	injected.Systemd = &injectedSystemd
	adapter := NewSystemdHostRuntimeAdapter(newRecordingHostRunner(), false)

	var operationError *InvalidOperationError
	err := adapter.Converge(context.Background(), injected)
	if !errors.As(err, &operationError) {
		t.Fatalf("expected InvalidOperationError, got %v", err)
	}
}

func TestProcessHostCommandRunnerHandlesStartFailureAndBoundsOutput(t *testing.T) {
	runner := ProcessHostCommandRunner{}
	if _, err := runner.Run(context.Background(), "/definitely/not-an-executable", nil); err == nil {
		t.Fatal("a command start failure must be returned as an error")
	}

	result, err := runner.Run(context.Background(), "/bin/sh", []string{"-c", "head -c 1048576 /dev/zero"})
	if err != nil {
		t.Fatalf("bounded command: %v", err)
	}
	if len([]rune(result.StandardOutput)) > hostCommandMaximumCapturedCharacters {
		t.Fatalf("captured output exceeded bound: %d", len([]rune(result.StandardOutput)))
	}
}

func TestProcessHostCommandRunnerCancellationKillsProcessGroup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	started := time.Now()
	_, err := (ProcessHostCommandRunner{}).Run(ctx, "/bin/sh", []string{"-c", "sleep 30"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancellation error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("canceled command took too long: %s", elapsed)
	}
}

func TestBoundedOutputWriterDropsExcessWithoutReturningAnIoError(t *testing.T) {
	var writer boundedOutputWriter
	writer.limit = 4
	if written, err := writer.Write([]byte("abcdef")); err != nil || written != 6 {
		t.Fatalf("Write = (%d, %v), want (6, nil)", written, err)
	}
	if got := writer.String(); got != "abcd" {
		t.Fatalf("captured output = %q", got)
	}
}
