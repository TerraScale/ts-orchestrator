// This file tests the process-based rootless-podman client of the
// rootless-hosting and autoscaling lane. The argument vectors are asserted
// element by element (they are the security contract), the uid-0 fail-closed
// preflight is proven before any process spawn, and the inspect parser is fed
// a captured podman inspect document. No podman binary is ever executed here.
package runtime

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func podmanTestRootlessContext() RootlessPodmanContext {
	return RootlessPodmanContext{
		PodmanBinaryPath: "/usr/bin/podman",
		XdgRuntimeDir:    "/run/user/1042",
		RunAsUid:         1042,
	}
}

func podmanTestRunRequest(t *testing.T) PodmanRunRequest {
	t.Helper()
	plan := podmanTestOciPlan(t)
	fingerprint, err := CanonicalPlanFingerprint.Compute(plan)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	request, err := NewPodmanRunRequest(
		plan.Oci.ContainerId,
		plan.Oci.ImageReference,
		plan.Oci.Platform,
		plan.Oci.Security.RunAsUser,
		plan.Oci.Security.RunAsGroup,
		plan.Oci.Security.CgroupParent,
		plan.Oci.Security.DroppedCapabilities,
		plan.Resources.MemoryMaxBytes,
		plan.Resources.TasksMax,
		plan.Resources.CpuQuotaPercent,
		plan.Resources.CpuWeight,
		podmanTestVolumes(),
		map[string]string{
			PodmanLabelAllocation:  plan.AllocationId.Value,
			PodmanLabelFingerprint: fingerprint,
		},
	)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	return request
}

func newPodmanProcessClient(t *testing.T, runner *recordingHostRunner) *ProcessPodmanClient {
	t.Helper()
	client, err := NewProcessPodmanClient(podmanTestRootlessContext(), runner)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	return client
}

func TestNewProcessPodmanClientValidatesItsConfiguration(t *testing.T) {
	asRoot := podmanTestRootlessContext()
	asRoot.RunAsUid = 0
	if _, err := NewProcessPodmanClient(asRoot, newRecordingHostRunner()); !errorsAsParam(err, "RunAsUid") {
		t.Fatalf("uid 0 must fail closed at construction, got %v", err)
	}
	withoutRunner := podmanTestRootlessContext()
	if _, err := NewProcessPodmanClient(withoutRunner, nil); !errorsAsParam(err, "commandRunner") {
		t.Fatalf("a nil runner must be rejected, got %v", err)
	}
	if _, err := NewProcessPodmanClient(podmanTestRootlessContext(), newRecordingHostRunner()); err != nil {
		t.Fatalf("client: %v", err)
	}
}

func TestProcessPodmanClientRefusesToRunWhenTheContextIsNotRootless(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(rootless *RootlessPodmanContext)
		wantParam string
	}{
		{
			name:      "uid 0",
			mutate:    func(c *RootlessPodmanContext) { c.RunAsUid = 0 },
			wantParam: "RunAsUid",
		},
		{
			name:      "empty runtime dir",
			mutate:    func(c *RootlessPodmanContext) { c.XdgRuntimeDir = "" },
			wantParam: "XdgRuntimeDir",
		},
		{
			name:      "relative binary path",
			mutate:    func(c *RootlessPodmanContext) { c.PodmanBinaryPath = "podman" },
			wantParam: "PodmanBinaryPath",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rootless := podmanTestRootlessContext()
			test.mutate(&rootless)
			runner := newRecordingHostRunner()
			client := &ProcessPodmanClient{rootless: rootless, commandRunner: runner}

			for _, invoke := range []func() error{
				func() error { return client.Preflight(context.Background()) },
				func() error { return client.Start(context.Background(), "terrascale-gru-loki-1") },
				func() error { return client.Delete(context.Background(), "terrascale-gru-loki-1") },
			} {
				if err := invoke(); !errorsAsParam(err, test.wantParam) {
					t.Fatalf("expected an error naming %q, got %v", test.wantParam, err)
				}
			}
			if len(runner.commands) != 0 {
				t.Fatalf("no command may spawn before the context is valid: %v", runner.commands)
			}
		})
	}
}

func TestProcessPodmanClientRunEmitsTheExactSecurityArgumentVector(t *testing.T) {
	runner := newRecordingHostRunner()
	client := newPodmanProcessClient(t, runner)
	request := podmanTestRunRequest(t)
	plan := podmanTestOciPlan(t)
	fingerprint, err := CanonicalPlanFingerprint.Compute(plan)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}

	if err := client.Create(context.Background(), request); err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("create must exec exactly one command, got %d", len(runner.commands))
	}
	command := runner.commands[0]
	if command.Executable != podmanTestRootlessContext().PodmanBinaryPath {
		t.Fatalf("executable = %q, want the absolute podman path", command.Executable)
	}
	expected := []string{
		"run", "-d",
		"--name", plan.Oci.ContainerId,
		"--platform", plan.Oci.Platform,
		"--user", "65532:65532",
		"--read-only",
		"--security-opt", "no-new-privileges",
		"--cap-drop", "ALL",
		"--cgroup-parent", "terrascale/gru-loki-1",
		"--memory", "4294967296",
		"--pids-limit", "1024",
		"--cpu-quota", "300",
		"--cpu-shares", "300",
		"--restart=no",
		"--volume", "loki-gru-1:/var/lib/loki:rw",
		"--volume", "loki-gru-1-rules:/etc/loki/rules:ro",
		"--label", PodmanLabelAllocation + "=" + plan.AllocationId.Value,
		"--label", PodmanLabelFingerprint + "=" + fingerprint,
		"registry.terrascale.internal/terrascale/loki@sha256:" + hostRuntimePlanDigest,
	}
	if !stringSlicesEqual(command.Arguments, expected) {
		t.Fatalf("argument vector mismatch:\n got %v\nwant %v", command.Arguments, expected)
	}
	for _, forbidden := range []string{"--privileged", "--cap-add", "--net=host", "--pid=host"} {
		if runnerArgumentsContain(runner, 0, forbidden) {
			t.Fatalf("the security contract forbids %q", forbidden)
		}
	}
}

func TestProcessPodmanClientRePinsTheSafetyEnvelopeOfATamperedRequest(t *testing.T) {
	runner := newRecordingHostRunner()
	client := newPodmanProcessClient(t, runner)
	tampered := podmanTestRunRequest(t)
	tampered.ReadOnlyRootfs = false
	tampered.NoNewPrivileges = false

	if err := client.Create(context.Background(), tampered); err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("create must exec exactly one command, got %d", len(runner.commands))
	}
	if !runnerArgumentsContain(runner, 0, "--read-only") {
		t.Fatal("the read-only root filesystem must be pinned in the argument vector")
	}
	if !runnerArgumentsContain(runner, 0, "no-new-privileges") {
		t.Fatal("no-new-privileges must be pinned in the argument vector")
	}
	if !runnerArgumentsContain(runner, 0, "ALL") {
		t.Fatal("the ALL capability drop must be pinned in the argument vector")
	}

	droppedAll := podmanTestRunRequest(t)
	droppedAll.CapDrop = []string{"NET_BIND_SERVICE"}
	dropRunner := newRecordingHostRunner()
	if err := newPodmanProcessClient(t, dropRunner).Create(context.Background(), droppedAll); err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(dropRunner.commands) != 1 {
		t.Fatalf("create must exec exactly one command, got %d", len(dropRunner.commands))
	}
	if !runnerArgumentsContain(dropRunner, 0, "ALL") {
		t.Fatal("the ALL capability drop must replace any tampered capability list")
	}
	if runnerArgumentsContain(dropRunner, 0, "NET_BIND_SERVICE") {
		t.Fatal("a tampered capability list must not survive the safety pin")
	}

	asRoot := podmanTestRunRequest(t)
	asRoot.RunAsUser = 0
	rootRunner := newRecordingHostRunner()
	if err := newPodmanProcessClient(t, rootRunner).Create(context.Background(), asRoot); !errorsAsParam(err, "runAsUser") {
		t.Fatalf("a root UID must be rejected before any command, got %v", err)
	}
	if len(rootRunner.commands) != 0 {
		t.Fatalf("no command may run for an invalid request: %v", rootRunner.commands)
	}
}

func TestProcessPodmanClientSubcommandsMapToExactArgumentVectors(t *testing.T) {
	plan := podmanTestOciPlan(t)
	image := plan.Oci.ImageReference
	tests := []struct {
		name     string
		invoke   func(client *ProcessPodmanClient) error
		expected []string
	}{
		{
			name:     "preflight",
			invoke:   func(c *ProcessPodmanClient) error { return c.Preflight(context.Background()) },
			expected: []string{"info"},
		},
		{
			name: "pull",
			invoke: func(c *ProcessPodmanClient) error {
				return c.Pull(context.Background(), image, "linux/amd64")
			},
			expected: []string{"pull", "--platform", "linux/amd64", image},
		},
		{
			name: "start",
			invoke: func(c *ProcessPodmanClient) error {
				return c.Start(context.Background(), plan.Oci.ContainerId)
			},
			expected: []string{"start", plan.Oci.ContainerId},
		},
		{
			name: "stop",
			invoke: func(c *ProcessPodmanClient) error {
				return c.Stop(context.Background(), plan.Oci.ContainerId)
			},
			expected: []string{"stop", plan.Oci.ContainerId},
		},
		{
			name: "delete",
			invoke: func(c *ProcessPodmanClient) error {
				return c.Delete(context.Background(), plan.Oci.ContainerId)
			},
			expected: []string{"rm", "-f", plan.Oci.ContainerId},
		},
		{
			name: "ensure volume",
			invoke: func(c *ProcessPodmanClient) error {
				return c.EnsureVolume(context.Background(), "loki-gru-1")
			},
			expected: []string{"volume", "create", "loki-gru-1"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := newRecordingHostRunner()
			if err := test.invoke(newPodmanProcessClient(t, runner)); err != nil {
				t.Fatalf("invoke: %v", err)
			}
			if len(runner.commands) != 1 {
				t.Fatalf("exactly one command expected, got %d", len(runner.commands))
			}
			if runner.commands[0].Executable != podmanTestRootlessContext().PodmanBinaryPath {
				t.Fatalf("executable = %q", runner.commands[0].Executable)
			}
			if !stringSlicesEqual(runner.commands[0].Arguments, test.expected) {
				t.Fatalf("argument vector mismatch:\n got %v\nwant %v",
					runner.commands[0].Arguments, test.expected)
			}
		})
	}
}

// podmanCapturedInspectJson renders one captured `podman container inspect
// --format json` document of the test allocation with the observed status and
// running flag, keeping the surrounding noise fields a real podman emits.
func podmanCapturedInspectJson(t *testing.T, status string, running bool) string {
	t.Helper()
	plan := podmanTestOciPlan(t)
	fingerprint, err := CanonicalPlanFingerprint.Compute(plan)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	return fmt.Sprintf(`[
  {
    "Id": "3f1c9a2447a1b06d5e8f207c9931d4a5b6c7d8e9f0011223344556677889900a",
    "Created": "2026-08-30T06:14:02.58595929+02:00",
    "Pod": "",
    "Image": "registry.terrascale.internal/terrascale/loki@sha256:%[1]s",
    "ImageID": "registry.terrascale.internal/terrascale/loki@sha256:%[1]s",
    "ImageName": "registry.terrascale.internal/terrascale/loki@sha256:%[1]s",
    "ExitCommand": [
      "/usr/bin/podman",
      "--root",
      "/var/home/ts-node/.local/share/containers/storage",
      "--runroot",
      "/run/user/1042/containers",
      "container",
      "cleanup",
      "terrascale-gru-loki-1"
    ],
    "Namespace": "",
    "Rootfs": "",
    "GraphDriver": {"Name": "overlay", "Data": {"LowerDir": "/var/home/ts-node/.local/share/containers/storage/overlay/l", "UpperDir": "/var/home/ts-node/.local/share/containers/storage/overlay/d", "WorkDir": "/var/home/ts-node/.local/share/containers/storage/overlay/w"}},
    "Mounts": [],
    "State": {
      "OciVersion": "1.1.0+dev",
      "Status": %[2]q,
      "Running": %[3]t,
      "Paused": false,
      "Restarting": false,
      "OOMKilled": false,
      "Dead": false,
      "Pid": 21873,
      "ConmonPid": 21863,
      "ExitCode": 0,
      "Error": "",
      "StartedAt": "2026-08-30T06:14:02.61289668+02:00",
      "FinishedAt": "0001-01-01T00:00:00Z",
      "CgroupPath": "/user.slice/user-1042.slice/user@1042.service/terrascale.slice/terrascale-gru-loki-1.scope",
      "Health": {"Status": "", "FailingStreak": 0, "Log": null}
    },
    "Name": "terrascale-gru-loki-1",
    "RestartCount": 0,
    "Driver": "overlay",
    "Platform": "linux",
    "InfraConfig": null,
    "Config": {
      "Image": "registry.terrascale.internal/terrascale/loki@sha256:%[1]s",
      "Labels": {
        "io.containers.capabilities": "CHOWN,DAC_OVERRIDE,FSETID,FOWNER,MKNOD,NET_RAW,SETGID,SETUID,SETFCAP,SETPCAP,NET_BIND_SERVICE,SYS_CHROOT,KILL,AUDIT_WRITE",
        "terrascale.allocation": "gru-loki-1",
        "terrascale.fingerprint": "%[4]s"
      },
      "CreateTime": "2026-08-30T06:14:02.58595929+02:00",
      "Entrypoint": ["/usr/local/bin/loki"],
      "Cmd": ["-config.file=/etc/loki/config.yaml"],
      "User": "65532:65532",
      "SecurityOpt": ["no-new-privileges"],
      "ReadOnlyRootfs": true
    },
    "HostConfig": {
      "CgroupParent": "terrascale/gru-loki-1",
      "CgroupsMode": "host",
      "Memory": 4294967296,
      "PidsLimit": 1024,
      "CpuQuota": 300,
      "CpuShares": 300,
      "CapDrop": ["ALL"],
      "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
      "NetworkMode": "bridge",
      "ReadonlyRootfs": true,
      "SecurityOpt": ["no-new-privileges"]
    }
  }
]`, hostRuntimePlanDigest, status, running, fingerprint)
}

func TestProcessPodmanClientInspectParsesTheCapturedPodmanShape(t *testing.T) {
	plan := podmanTestOciPlan(t)
	runner := newRecordingHostRunner(HostCommandResult{
		ExitCode:       0,
		StandardOutput: podmanCapturedInspectJson(t, "running", true),
	})

	observation, err := newPodmanProcessClient(t, runner).Inspect(context.Background(), plan.Oci.ContainerId)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if !stringSlicesEqual(runner.commands[0].Arguments,
		[]string{"container", "inspect", "--format", "json", plan.Oci.ContainerId}) {
		t.Fatalf("unexpected argument vector %v", runner.commands[0].Arguments)
	}
	if observation.State != PodmanAllocationStateRunning || !observation.Running {
		t.Fatalf("unexpected observation %+v", observation)
	}
	if observation.ImageReference != plan.Oci.ImageReference {
		t.Fatalf("image reference = %q", observation.ImageReference)
	}
	if observation.Labels[PodmanLabelAllocation] != plan.AllocationId.Value {
		t.Fatalf("allocation label missing: %v", observation.Labels)
	}
	fingerprint, err := CanonicalPlanFingerprint.Compute(plan)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	if observation.Labels[PodmanLabelFingerprint] != fingerprint {
		t.Fatalf("fingerprint label missing: %v", observation.Labels)
	}
	if _, present := observation.Labels["io.containers.capabilities"]; !present {
		t.Fatal("foreign labels must pass through untouched for the fence to judge them")
	}
}

func TestProcessPodmanClientInspectMapsEveryKnownPodmanStatus(t *testing.T) {
	tests := []struct {
		status    string
		running   bool
		wantState PodmanAllocationState
	}{
		{status: "created", wantState: PodmanAllocationStateCreating},
		{status: "running", running: true, wantState: PodmanAllocationStateRunning},
		{status: "configured", wantState: PodmanAllocationStateStopped},
		{status: "stopped", wantState: PodmanAllocationStateStopped},
		{status: "exited", wantState: PodmanAllocationStateStopped},
		{status: "stopping", wantState: PodmanAllocationStateStopping},
		{status: "dead", wantState: PodmanAllocationStateFailed},
		{status: "paused", wantState: PodmanAllocationStateFailed},
		{status: "Running", running: true, wantState: PodmanAllocationStateRunning},
	}
	for _, test := range tests {
		t.Run(test.status, func(t *testing.T) {
			runner := newRecordingHostRunner(HostCommandResult{
				ExitCode:       0,
				StandardOutput: podmanCapturedInspectJson(t, test.status, test.running),
			})
			observation, err := newPodmanProcessClient(t, runner).Inspect(
				context.Background(), podmanTestOciPlan(t).Oci.ContainerId)
			if err != nil {
				t.Fatalf("inspect: %v", err)
			}
			if observation.State != test.wantState {
				t.Fatalf("state = %v, want %v", observation.State, test.wantState)
			}
		})
	}
}

func TestProcessPodmanClientInspectFailsClosedOnBadData(t *testing.T) {
	tests := []struct {
		name           string
		standardOutput string
		wantErrorType  string
	}{
		{
			name:           "unrecognized status",
			standardOutput: podmanCapturedInspectJson(t, "restarting", false),
			wantErrorType:  "InvalidDataError",
		},
		{
			name:           "malformed json",
			standardOutput: "not json at all",
			wantErrorType:  "InvalidDataError",
		},
		{
			name:           "more than one document",
			standardOutput: podmanTwoDocumentJson(t),
			wantErrorType:  "InvalidDataError",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := newRecordingHostRunner(HostCommandResult{
				ExitCode:       0,
				StandardOutput: test.standardOutput,
			})
			_, err := newPodmanProcessClient(t, runner).Inspect(
				context.Background(), podmanTestOciPlan(t).Oci.ContainerId)
			if err == nil {
				t.Fatal("expected an error, got a valid observation")
			}
			if !hasPodmanErrorType(err, test.wantErrorType) {
				t.Fatalf("expected %s, got %T: %v", test.wantErrorType, err, err)
			}
		})
	}

	inconsistent := newRecordingHostRunner(HostCommandResult{
		ExitCode:       0,
		StandardOutput: podmanCapturedInspectJson(t, "stopped", true),
	})
	_, err := newPodmanProcessClient(t, inconsistent).Inspect(
		context.Background(), podmanTestOciPlan(t).Oci.ContainerId)
	if err == nil {
		t.Fatal("a running flag that contradicts the status must fail closed")
	}
}

// podmanTwoDocumentJson duplicates the captured inspect document into one
// valid two-document array, the shape a wildcard inspect could return.
func podmanTwoDocumentJson(t *testing.T) string {
	t.Helper()
	single := strings.TrimSpace(podmanCapturedInspectJson(t, "running", true))
	inner := strings.TrimSuffix(strings.TrimPrefix(single, "["), "]")
	return "[" + inner + "," + inner + "]"
}

func TestProcessPodmanClientInspectDistinguishesAbsentFromRealErrors(t *testing.T) {
	absentStderrs := []string{
		`Error: no container with name or ID "terrascale-gru-loki-1": no such container`,
		"Error: inspecting container: no such container",
	}
	for _, stderr := range absentStderrs {
		runner := newRecordingHostRunner(HostCommandResult{ExitCode: 125, StandardError: stderr})
		observation, err := newPodmanProcessClient(t, runner).Inspect(
			context.Background(), podmanTestOciPlan(t).Oci.ContainerId)
		if err != nil {
			t.Fatalf("absence must not be an error, got %v", err)
		}
		if observation.State != PodmanAllocationStateAbsent || observation.Running {
			t.Fatalf("unexpected observation %+v", observation)
		}
	}

	realFailure := newRecordingHostRunner(HostCommandResult{
		ExitCode:      125,
		StandardError: "Error: rootless cgroup v2 delegation is not available for this user",
	})
	_, err := newPodmanProcessClient(t, realFailure).Inspect(
		context.Background(), podmanTestOciPlan(t).Oci.ContainerId)
	var operationError *InvalidOperationError
	if !errors.As(err, &operationError) {
		t.Fatalf("a real failure must surface as InvalidOperationError, got %v", err)
	}
	if !strings.Contains(err.Error(), "container inspect failed with exit code 125") {
		t.Fatalf("unexpected message %q", err.Error())
	}
}

func TestProcessPodmanClientMapsNonZeroExitsToTrimmedStderr(t *testing.T) {
	runner := newRecordingHostRunner(HostCommandResult{
		ExitCode:      125,
		StandardError: "  Error: name is already in use by another container  \n",
	})

	err := newPodmanProcessClient(t, runner).Create(context.Background(), podmanTestRunRequest(t))
	var operationError *InvalidOperationError
	if !errors.As(err, &operationError) {
		t.Fatalf("expected InvalidOperationError, got %v", err)
	}
	expected := "podman run failed with exit code 125. Error: name is already in use by another container"
	if err.Error() != expected {
		t.Fatalf("message = %q, want %q", err.Error(), expected)
	}

	quiet := newRecordingHostRunner(HostCommandResult{ExitCode: 1})
	err = newPodmanProcessClient(t, quiet).Stop(context.Background(), podmanTestOciPlan(t).Oci.ContainerId)
	if !errors.As(err, &operationError) {
		t.Fatalf("expected InvalidOperationError, got %v", err)
	}
	if err.Error() != "podman stop failed with exit code 1." {
		t.Fatalf("unexpected message %q", err.Error())
	}
}

func TestProcessPodmanClientEnsureVolumeTreatsAlreadyPresentAsSuccess(t *testing.T) {
	created := newRecordingHostRunner()
	if err := newPodmanProcessClient(t, created).EnsureVolume(context.Background(), "loki-gru-1"); err != nil {
		t.Fatalf("ensure volume: %v", err)
	}
	if !stringSlicesEqual(created.commands[0].Arguments, []string{"volume", "create", "loki-gru-1"}) {
		t.Fatalf("unexpected argument vector %v", created.commands[0].Arguments)
	}

	alreadyPresent := newRecordingHostRunner(HostCommandResult{
		ExitCode:      1,
		StandardError: "Error: volume loki-gru-1 already exists",
	})
	if err := newPodmanProcessClient(t, alreadyPresent).EnsureVolume(context.Background(), "loki-gru-1"); err != nil {
		t.Fatalf("an already-present volume is success, got %v", err)
	}
}

func TestProcessPodmanClientValidatesTokensBeforeAnyCommandSpawns(t *testing.T) {
	tests := []struct {
		name          string
		invoke        func(client *ProcessPodmanClient) error
		wantParam     string
		wantErrorType string
	}{
		{
			name:          "flag-like container id",
			invoke:        func(c *ProcessPodmanClient) error { return c.Start(context.Background(), "-x") },
			wantParam:     "containerId",
			wantErrorType: "ArgumentError",
		},
		{
			name:          "traversal container id",
			invoke:        func(c *ProcessPodmanClient) error { return c.Delete(context.Background(), "../evil") },
			wantParam:     "containerId",
			wantErrorType: "ArgumentError",
		},
		{
			name:          "uppercase volume name",
			invoke:        func(c *ProcessPodmanClient) error { return c.EnsureVolume(context.Background(), "Loki") },
			wantParam:     "name",
			wantErrorType: "ArgumentError",
		},
		{
			name:          "flag-like image reference",
			invoke:        func(c *ProcessPodmanClient) error { return c.Pull(context.Background(), "--privileged", "linux/amd64") },
			wantParam:     "imageReference",
			wantErrorType: "ArgumentError",
		},
		{
			name: "unknown platform",
			invoke: func(c *ProcessPodmanClient) error {
				return c.Pull(context.Background(), "registry.terrascale.internal/x@sha256:"+hostRuntimePlanDigest, "linux/riscv64")
			},
			wantParam:     "platform",
			wantErrorType: "ArgumentOutOfRangeError",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := newRecordingHostRunner()
			err := test.invoke(newPodmanProcessClient(t, runner))
			if err == nil {
				t.Fatal("expected an error, got success")
			}
			if !hasPodmanErrorType(err, test.wantErrorType) {
				t.Fatalf("expected %s, got %T: %v", test.wantErrorType, err, err)
			}
			if !errorsAsParam(err, test.wantParam) {
				t.Fatalf("error %v does not reference param %q", err, test.wantParam)
			}
			if len(runner.commands) != 0 {
				t.Fatalf("no command may spawn for an invalid identifier: %v", runner.commands)
			}
		})
	}
}

func TestProcessPodmanClientRejectsNilContext(t *testing.T) {
	runner := newRecordingHostRunner()
	client := newPodmanProcessClient(t, runner)
	var argumentError *ArgumentError
	if err := client.Preflight(nil); !errors.As(err, &argumentError) {
		t.Fatalf("expected ArgumentError, got %v", err)
	}
	if err := client.Start(nil, podmanTestOciPlan(t).Oci.ContainerId); !errors.As(err, &argumentError) {
		t.Fatalf("expected ArgumentError, got %v", err)
	}
	if len(runner.commands) != 0 {
		t.Fatalf("no command may spawn for a nil context: %v", runner.commands)
	}
}
