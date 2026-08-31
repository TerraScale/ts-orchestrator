package runtime

import (
	"context"
	"strings"
	"testing"
)

const (
	podmanTestSystemctlBinary  = "/usr/bin/systemctl"
	podmanTestSystemdRunBinary = "/usr/bin/systemd-run"
)

func newPodmanSystemdUserTestClient(
	t *testing.T,
	podman *recordingPodmanClient,
	runner *recordingHostRunner,
) *SystemdUserPodmanClient {
	t.Helper()
	client, err := NewSystemdUserPodmanClient(
		podman,
		podmanTestRootlessContext(),
		podmanTestSystemctlBinary,
		podmanTestSystemdRunBinary,
		runner,
	)
	if err != nil {
		t.Fatalf("systemd user podman client: %v", err)
	}
	return client
}

func podmanSupervisorShow(t *testing.T, activeState string) HostCommandResult {
	t.Helper()
	description, err := podmanSupervisorDescription(
		podmanMatchingLabels(t, podmanTestOciPlan(t)))
	if err != nil {
		t.Fatal(err)
	}
	return HostCommandResult{ExitCode: 0, StandardOutput: strings.Join([]string{
		"LoadState=loaded",
		"ActiveState=" + activeState,
		"Description=" + description,
		"",
	}, "\n")}
}

func podmanSupervisorAbsent() HostCommandResult {
	return HostCommandResult{ExitCode: 1, StandardOutput: "LoadState=not-found\n"}
}

func TestNewSystemdUserPodmanClientValidatesEveryBoundary(t *testing.T) {
	rootless := podmanTestRootlessContext()
	podman := &recordingPodmanClient{}
	runner := newRecordingHostRunner()
	if _, err := NewSystemdUserPodmanClient(nil, rootless, podmanTestSystemctlBinary,
		podmanTestSystemdRunBinary, runner); !errorsAsParam(err, "client") {
		t.Fatalf("nil podman client was accepted: %v", err)
	}
	if _, err := NewSystemdUserPodmanClient(podman, rootless, "systemctl",
		podmanTestSystemdRunBinary, runner); !errorsAsParam(err, "systemctlBinaryPath") {
		t.Fatalf("relative systemctl path was accepted: %v", err)
	}
	if _, err := NewSystemdUserPodmanClient(podman, rootless, "/usr/bin/systemctl --system",
		podmanTestSystemdRunBinary, runner); !errorsAsParam(err, "systemctlBinaryPath") {
		t.Fatalf("injectable systemctl path was accepted: %v", err)
	}
}

func TestSystemdUserPodmanPreflightProvesPodmanAndTheUserManager(t *testing.T) {
	podman := &recordingPodmanClient{}
	runner := newRecordingHostRunner(HostCommandResult{ExitCode: 0})
	client := newPodmanSystemdUserTestClient(t, podman, runner)

	if err := client.Preflight(context.Background()); err != nil {
		t.Fatalf("preflight: %v", err)
	}
	if len(podman.operations) != 1 || podman.operations[0] != "preflight" {
		t.Fatalf("podman operations = %v", podman.operations)
	}
	if len(runner.commands) != 1 || runner.commands[0].Executable != podmanTestSystemctlBinary ||
		!stringSlicesEqual(runner.commands[0].Arguments, []string{"--user", "show-environment"}) {
		t.Fatalf("systemd preflight command = %+v", runner.commands)
	}
}

func TestSystemdUserPodmanStartCreatesTheFencedTransientUnit(t *testing.T) {
	plan := podmanTestOciPlan(t)
	podman := &recordingPodmanClient{observation: podmanFencedObservation(
		t, plan, PodmanAllocationStateCreating, podmanMatchingLabels(t, plan))}
	runner := newRecordingHostRunner(podmanSupervisorAbsent(), HostCommandResult{ExitCode: 0})
	client := newPodmanSystemdUserTestClient(t, podman, runner)

	if err := client.Start(context.Background(), plan.Oci.ContainerId); err != nil {
		t.Fatalf("start: %v", err)
	}
	if len(podman.operations) != 1 || podman.operations[0] != "inspect" {
		t.Fatalf("start must inspect labels without calling raw podman start: %v", podman.operations)
	}
	if len(runner.commands) != 2 {
		t.Fatalf("systemd commands = %+v", runner.commands)
	}
	command := runner.commands[1]
	if command.Executable != podmanTestSystemdRunBinary {
		t.Fatalf("start executable = %q", command.Executable)
	}
	description, err := podmanSupervisorDescription(podmanMatchingLabels(t, plan))
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"--user",
		"--collect",
		"Description=" + description,
		"Restart=always",
		"Delegate=yes",
		"NoNewPrivileges=yes",
		"ExecStop=/usr/bin/podman stop --time 30 " + plan.Oci.ContainerId,
		"--setenv=XDG_RUNTIME_DIR=/run/user/1042",
		plan.Oci.ContainerId + ".service",
		podmanTestRootlessContext().PodmanBinaryPath,
		"--attach",
		plan.Oci.ContainerId,
	} {
		if !runnerArgumentsContain(runner, 1, expected) {
			t.Fatalf("systemd-run omitted %q: %v", expected, command.Arguments)
		}
	}
}

func TestSystemdUserPodmanStartRestartsAnOwnedFailedUnit(t *testing.T) {
	plan := podmanTestOciPlan(t)
	podman := &recordingPodmanClient{observation: podmanFencedObservation(
		t, plan, PodmanAllocationStateStopped, podmanMatchingLabels(t, plan))}
	runner := newRecordingHostRunner(
		podmanSupervisorShow(t, "failed"),
		HostCommandResult{ExitCode: 0},
		HostCommandResult{ExitCode: 0},
	)
	client := newPodmanSystemdUserTestClient(t, podman, runner)

	if err := client.Start(context.Background(), plan.Oci.ContainerId); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if len(runner.commands) != 3 ||
		!stringSlicesEqual(runner.commands[1].Arguments,
			[]string{"--user", "reset-failed", plan.Oci.ContainerId + ".service"}) ||
		!stringSlicesEqual(runner.commands[2].Arguments,
			[]string{"--user", "start", plan.Oci.ContainerId + ".service"}) {
		t.Fatalf("restart commands = %+v", runner.commands)
	}
}

func TestSystemdUserPodmanInspectRequiresTheMatchingLiveSupervisor(t *testing.T) {
	plan := podmanTestOciPlan(t)
	running := podmanFencedObservation(
		t, plan, PodmanAllocationStateRunning, podmanMatchingLabels(t, plan))

	t.Run("owned", func(t *testing.T) {
		client := newPodmanSystemdUserTestClient(t,
			&recordingPodmanClient{observation: running},
			newRecordingHostRunner(podmanSupervisorShow(t, "active")))
		observation, err := client.Inspect(context.Background(), plan.Oci.ContainerId)
		if err != nil || observation.State != PodmanAllocationStateRunning {
			t.Fatalf("observation = %+v, err = %v", observation, err)
		}
	})

	t.Run("unsupervised", func(t *testing.T) {
		client := newPodmanSystemdUserTestClient(t,
			&recordingPodmanClient{observation: running},
			newRecordingHostRunner(podmanSupervisorAbsent()))
		_, err := client.Inspect(context.Background(), plan.Oci.ContainerId)
		if err == nil || !strings.Contains(err.Error(), "without its fenced systemd user supervisor") {
			t.Fatalf("unsupervised container was accepted: %v", err)
		}
	})

	t.Run("wrong fence", func(t *testing.T) {
		wrong := podmanSupervisorShow(t, "active")
		wrong.StandardOutput = strings.Replace(
			wrong.StandardOutput, "Description=TerraScale", "Description=Foreign", 1)
		client := newPodmanSystemdUserTestClient(t,
			&recordingPodmanClient{observation: running}, newRecordingHostRunner(wrong))
		_, err := client.Inspect(context.Background(), plan.Oci.ContainerId)
		if err == nil || !strings.Contains(err.Error(), "not owned by its fencing labels") {
			t.Fatalf("foreign supervisor was accepted: %v", err)
		}
	})
}

func TestSystemdUserPodmanStopUsesTheUserUnitExecStop(t *testing.T) {
	plan := podmanTestOciPlan(t)
	podman := &recordingPodmanClient{observation: podmanFencedObservation(
		t, plan, PodmanAllocationStateRunning, podmanMatchingLabels(t, plan))}
	runner := newRecordingHostRunner(
		podmanSupervisorShow(t, "active"), HostCommandResult{ExitCode: 0})
	client := newPodmanSystemdUserTestClient(t, podman, runner)

	if err := client.Stop(context.Background(), plan.Oci.ContainerId); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if strings.Contains(strings.Join(podman.operations, ","), "stop") {
		t.Fatalf("raw podman stop bypassed systemd: %v", podman.operations)
	}
	if len(runner.commands) != 2 || !stringSlicesEqual(runner.commands[1].Arguments,
		[]string{"--user", "stop", plan.Oci.ContainerId + ".service"}) {
		t.Fatalf("stop commands = %+v", runner.commands)
	}
}

func TestSystemdUserPodmanDeleteRemovesAStoppedUnloadedContainer(t *testing.T) {
	plan := podmanTestOciPlan(t)
	podman := &recordingPodmanClient{observation: podmanFencedObservation(
		t, plan, PodmanAllocationStateStopped, podmanMatchingLabels(t, plan))}
	client := newPodmanSystemdUserTestClient(t, podman,
		newRecordingHostRunner(podmanSupervisorAbsent()))

	if err := client.Delete(context.Background(), plan.Oci.ContainerId); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if !stringSlicesEqual(podman.operations, []string{"inspect", "delete"}) {
		t.Fatalf("podman operations = %v", podman.operations)
	}
}

func TestSystemdUserPodmanRefusesAnOrphanedUnit(t *testing.T) {
	plan := podmanTestOciPlan(t)
	podman := &recordingPodmanClient{observation: podmanFencedObservation(
		t, plan, PodmanAllocationStateAbsent, nil)}
	client := newPodmanSystemdUserTestClient(t, podman,
		newRecordingHostRunner(podmanSupervisorShow(t, "active")))

	_, err := client.Inspect(context.Background(), plan.Oci.ContainerId)
	if err == nil || !strings.Contains(err.Error(), "exists without its container") {
		t.Fatalf("orphaned supervisor was accepted: %v", err)
	}
}

var _ PodmanClient = (*SystemdUserPodmanClient)(nil)
