package runtime

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type recordingProbe struct {
	result SystemdHostProbeResult
}

func (p recordingProbe) Probe() SystemdHostProbeResult { return p.result }

func admittedHostProbe() SystemdHostProbe {
	return recordingProbe{result: SystemdHostProbeResult{
		IsLinux: true, IsSystemdPid1: true, HasCgroupV2: true,
		HasSystemctl: true, HasSystemdRun: true,
	}}
}

func nativeTestPlan(t *testing.T, role AdmittedRole, allocation string) HostRuntimePlan {
	t.Helper()
	plan, err := NewHostRuntimePlan(
		role,
		RuntimeDriverNativeSystemd,
		mustRuntimeAllocationId(t, allocation),
		mustArtifactDigest(t, hostRuntimePlanDigest),
		HostArchitectureArm64,
		nil)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return plan
}

func TestAdmitsCanonicalNativeTerraBaseOrchestratorAndNatsPlans(t *testing.T) {
	cases := []struct {
		role       AdmittedRole
		allocation string
	}{
		{AdmittedRoleTerraBaseMember, "gru-terrabase-1"},
		{AdmittedRoleAutoscaler, "gru-orchestrator-1"},
		{AdmittedRoleNats, "gru-nats-1"},
		{AdmittedRoleNats, "gru-nats-2"},
	}
	for _, testCase := range cases {
		runner := newRecordingHostRunner(
			HostCommandResult{ExitCode: 1, StandardOutput: "LoadState=not-found\n", StandardError: "Unit not found"},
			HostCommandResult{ExitCode: 0})
		admission, err := NewNativeSystemdRuntimeAdmissionWithRunner(
			nativeTestPlan(t, testCase.role, testCase.allocation),
			admittedHostProbe(), runner)
		if err != nil {
			t.Fatalf("admission for %v: %v", testCase.role, err)
		}

		if err := admission.Converge(context.Background()); err != nil {
			t.Fatalf("converge for %v: %v", testCase.role, err)
		}

		if len(runner.commands) != 2 {
			t.Fatalf("role %v: expected 2 commands, got %d", testCase.role, len(runner.commands))
		}
		if runner.commands[0].Executable != "/usr/bin/systemctl" {
			t.Fatalf("role %v: first command must be systemctl", testCase.role)
		}
		if runner.commands[1].Executable != "/usr/bin/systemd-run" {
			t.Fatalf("role %v: second command must be systemd-run", testCase.role)
		}
	}
}

func TestEveryFailedHostAdmissionIsRejectedBeforeAnyRunnerCall(t *testing.T) {
	failures := []SystemdHostProbeResult{
		{IsLinux: false, IsSystemdPid1: true, HasCgroupV2: true, HasSystemctl: true, HasSystemdRun: true},
		{IsLinux: true, IsSystemdPid1: false, HasCgroupV2: true, HasSystemctl: true, HasSystemdRun: true},
		{IsLinux: true, IsSystemdPid1: true, HasCgroupV2: false, HasSystemctl: true, HasSystemdRun: true},
		{IsLinux: true, IsSystemdPid1: true, HasCgroupV2: true, HasSystemctl: false, HasSystemdRun: true},
		{IsLinux: true, IsSystemdPid1: true, HasCgroupV2: true, HasSystemctl: true, HasSystemdRun: false},
	}
	for _, failedProbe := range failures {
		runner := newRecordingHostRunner()
		var operationError *InvalidOperationError
		_, err := NewNativeSystemdRuntimeAdmissionWithRunner(
			nativeTestPlan(t, AdmittedRoleAutoscaler, "gru-orchestrator-1"),
			recordingProbe{result: failedProbe}, runner)
		if !errors.As(err, &operationError) {
			t.Fatalf("expected InvalidOperationError, got %v", err)
		}
		if len(runner.commands) != 0 {
			t.Fatalf("failed admission must not run commands: %d", len(runner.commands))
		}
	}
}

func TestProductionProbeIsReadOnlyAndUsesTheFixedAdmissionPaths(t *testing.T) {
	probe := LinuxSystemdHostProbe{}
	evidence := probe.Probe()

	if evidence.IsLinux != isLinuxHost() {
		t.Fatal("IsLinux must mirror the host platform")
	}
	if LinuxSystemdHostProbeSystemctlPath != "/usr/bin/systemctl" {
		t.Fatal("unexpected systemctl path")
	}
	if LinuxSystemdHostProbeSystemdRunPath != "/usr/bin/systemd-run" {
		t.Fatal("unexpected systemd-run path")
	}
	if LinuxSystemdHostProbeSystemdPid1CommPath != "/proc/1/comm" {
		t.Fatal("unexpected pid1 comm path")
	}
	if LinuxSystemdHostProbeCgroupV2ControllersPath != "/sys/fs/cgroup/cgroup.controllers" {
		t.Fatal("unexpected cgroup controllers path")
	}
}

func TestEveryCanonicalPlanTamperClassIsRejectedBeforeRunnerCall(t *testing.T) {
	original := nativeTestPlan(t, AdmittedRoleAutoscaler, "gru-orchestrator-1")

	executableTampered := original
	tamperedSystemd := *original.Systemd
	tamperedSystemd.Executable = "/bin/sh"
	executableTampered.Systemd = &tamperedSystemd

	argumentsTampered := original
	argumentsSystemd := *original.Systemd
	argumentsSystemd.Arguments = []string{"-c", "injected"}
	argumentsTampered.Systemd = &argumentsSystemd

	propertiesTampered := original
	propertiesSystemd := *original.Systemd
	propertiesSystemd.Properties = append(append([]string{}, original.Systemd.Properties...), "Environment=SECRET=value")
	propertiesTampered.Systemd = &propertiesSystemd

	resourcesTampered := original
	resourcesTampered.Resources = original.Resources
	resourcesTampered.Resources.MemoryMaxBytes = 512 * 1024 * 1024

	allocationTampered := original
	allocationTampered.AllocationId = mustRuntimeAllocationId(t, "gru-orchestrator-tampered")

	digestTampered := original
	digestTampered.ArtifactDigest = mustArtifactDigest(t,
		"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")

	for name, tampered := range map[string]HostRuntimePlan{
		"executable": executableTampered,
		"arguments":  argumentsTampered,
		"properties": propertiesTampered,
		"resources":  resourcesTampered,
		"allocation": allocationTampered,
		"digest":     digestTampered,
	} {
		runner := newRecordingHostRunner()
		var operationError *InvalidOperationError
		_, err := NewNativeSystemdRuntimeAdmissionWithRunner(tampered, admittedHostProbe(), runner)
		if !errors.As(err, &operationError) {
			t.Fatalf("%s: expected InvalidOperationError, got %v", name, err)
		}
		if len(runner.commands) != 0 {
			t.Fatalf("%s: tampered plans must not run commands: %d", name, len(runner.commands))
		}
	}
}

func TestAcceptedAdmissionUsesSystemManagerFixedPathsArgumentListsAndHardenedProperties(t *testing.T) {
	plan := nativeTestPlan(t, AdmittedRoleNats, "gru-nats-1")
	runner := newRecordingHostRunner(
		HostCommandResult{ExitCode: 1, StandardOutput: "LoadState=not-found\n", StandardError: "Unit not found"},
		HostCommandResult{ExitCode: 0})
	admission, err := NewNativeSystemdRuntimeAdmissionWithRunner(plan, admittedHostProbe(), runner)
	if err != nil {
		t.Fatalf("admission: %v", err)
	}

	if err := admission.Converge(context.Background()); err != nil {
		t.Fatalf("converge: %v", err)
	}

	observe := runner.commands[0]
	start := runner.commands[1]
	if observe.Executable != "/usr/bin/systemctl" {
		t.Fatal("observe must use systemctl")
	}
	for _, argument := range observe.Arguments {
		if argument == "--user" {
			t.Fatal("the system manager must be used")
		}
	}
	if observe.Arguments[0] != "show" {
		t.Fatal("observe must start with show")
	}
	if !containsArgument(observe.Arguments, plan.Systemd.UnitName) {
		t.Fatal("observe must target the canonical unit")
	}
	if start.Executable != "/usr/bin/systemd-run" {
		t.Fatal("start must use systemd-run")
	}
	for _, argument := range start.Arguments {
		if argument == "--user" {
			t.Fatal("the system manager must be used")
		}
	}
	for _, expected := range []string{
		"--unit", plan.Systemd.UnitName, "--", plan.Systemd.Executable, "--config",
		"Type=exec", "DynamicUser=yes", "NoNewPrivileges=yes", "PrivateTmp=yes",
		"PrivateDevices=yes", "ProtectSystem=strict",
		"ProtectHome=yes", "ProtectKernelTunables=yes", "ProtectKernelModules=yes",
		"ProtectControlGroups=yes", "RestrictSUIDSGID=yes", "LockPersonality=yes",
		"MemoryDenyWriteExecute=yes", "CapabilityBoundingSet=",
		"SystemCallFilter=@system-service", "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
		"ReadWritePaths=/var/lib/terrascale-gru-nats-1",
		"MemorySwapMax=0",
	} {
		if !containsArgument(start.Arguments, expected) {
			t.Fatalf("expected argument %q", expected)
		}
	}
}

func containsArgument(arguments []string, expected string) bool {
	for _, argument := range arguments {
		if argument == expected {
			return true
		}
	}
	return false
}

func intArgumentsContain(value string) bool {
	return strings.Contains(value, ";") || strings.Contains(value, "$(")
}

func TestAdmissionNeverTurnsAllocationInputIntoShellOrPathExecution(t *testing.T) {
	plan := nativeTestPlan(t, AdmittedRoleAutoscaler, "gru-orchestrator-1")
	runner := newRecordingHostRunner(
		HostCommandResult{ExitCode: 1, StandardOutput: "LoadState=not-found\n"},
		HostCommandResult{ExitCode: 0})
	admission, err := NewNativeSystemdRuntimeAdmissionWithRunner(plan, admittedHostProbe(), runner)
	if err != nil {
		t.Fatalf("admission: %v", err)
	}

	if err := admission.Converge(context.Background()); err != nil {
		t.Fatalf("converge: %v", err)
	}

	for _, command := range runner.commands {
		if command.Executable != "/usr/bin/systemctl" && command.Executable != "/usr/bin/systemd-run" {
			t.Fatalf("unexpected executable %q", command.Executable)
		}
		for _, argument := range command.Arguments {
			if argument == "sh" || argument == "bash" || argument == "-c" || intArgumentsContain(argument) {
				t.Fatalf("shell-shaped argument %q must never appear", argument)
			}
		}
	}
}
