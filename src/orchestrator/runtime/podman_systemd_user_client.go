// This file binds the rootless Podman client to the host's systemd user
// manager. Podman owns the container boundary; systemd owns restart and stop
// supervision. The two ownership proofs are joined by the allocation and
// canonical-plan labels carried in the transient unit description.
package runtime

import (
	"context"
	"fmt"
	"strings"
	"time"
)

const (
	podmanSupervisorStopTimeoutSeconds = 30
	podmanSupervisorStopTimeout        = "45s"
	podmanSupervisorRestartDelay       = "5s"
	podmanSupervisorCollectionTimeout  = 2 * time.Second
	podmanSupervisorCollectionPoll     = 20 * time.Millisecond
)

// SystemdUserPodmanClient is the production PodmanClient composition used by
// ts-node. It delegates image, container, and volume operations to one
// rootless client, but starts and stops each container through a transient
// systemd user unit. A running container without its matching fenced unit is
// refused as unsupervised and is never adopted.
type SystemdUserPodmanClient struct {
	client               PodmanClient
	rootless             RootlessPodmanContext
	systemctlBinaryPath  string
	systemdRunBinaryPath string
	commandRunner        HostCommandRunner
}

// NewSystemdUserPodmanClient validates the complete user-manager boundary.
// Every executable is an explicit absolute path and the rootless context is
// revalidated again before each host command.
func NewSystemdUserPodmanClient(
	client PodmanClient,
	rootless RootlessPodmanContext,
	systemctlBinaryPath string,
	systemdRunBinaryPath string,
	commandRunner HostCommandRunner,
) (*SystemdUserPodmanClient, error) {
	if client == nil {
		return nil, &ArgumentError{Param: "client", Message: "A rootless podman client is required."}
	}
	if err := ValidateRootlessContext(rootless); err != nil {
		return nil, err
	}
	validatedSystemctl, err := requirePodmanAbsolutePath(systemctlBinaryPath, "systemctlBinaryPath")
	if err != nil {
		return nil, err
	}
	validatedSystemdRun, err := requirePodmanAbsolutePath(systemdRunBinaryPath, "systemdRunBinaryPath")
	if err != nil {
		return nil, err
	}
	if commandRunner == nil {
		return nil, &ArgumentError{Param: "commandRunner", Message: "A host command runner is required."}
	}
	return &SystemdUserPodmanClient{
		client:               client,
		rootless:             rootless,
		systemctlBinaryPath:  validatedSystemctl,
		systemdRunBinaryPath: validatedSystemdRun,
		commandRunner:        commandRunner,
	}, nil
}

// Preflight proves both halves of the runtime before convergence mutates
// anything: rootless Podman must answer info and the systemd user manager must
// answer show-environment.
func (c *SystemdUserPodmanClient) Preflight(ctx context.Context) error {
	if err := c.validate(ctx); err != nil {
		return err
	}
	if err := c.client.Preflight(ctx); err != nil {
		return err
	}
	result, err := c.commandRunner.Run(ctx, c.systemctlBinaryPath,
		[]string{"--user", "show-environment"})
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return systemdUserPodmanCommandError("preflight", result)
	}
	return nil
}

// Pull delegates image resolution after revalidating the supervisor boundary.
func (c *SystemdUserPodmanClient) Pull(
	ctx context.Context,
	imageReference string,
	platform string,
) error {
	if err := c.validate(ctx); err != nil {
		return err
	}
	return c.client.Pull(ctx, imageReference, platform)
}

// Create delegates the already validated and hardened Podman create request.
// Starting stays separate and always goes through systemd-run.
func (c *SystemdUserPodmanClient) Create(ctx context.Context, request PodmanRunRequest) error {
	if err := c.validate(ctx); err != nil {
		return err
	}
	return c.client.Create(ctx, request)
}

// Start starts a created container as the main process of its transient
// systemd user unit. Existing loaded units must carry the exact description
// derived from the container's fencing labels before they may be restarted.
func (c *SystemdUserPodmanClient) Start(ctx context.Context, containerId string) error {
	validated, err := c.validateContainer(ctx, containerId)
	if err != nil {
		return err
	}
	container, err := c.client.Inspect(ctx, validated)
	if err != nil {
		return err
	}
	if container.State == PodmanAllocationStateAbsent {
		return &InvalidOperationError{Message: fmt.Sprintf(
			"Podman container %s cannot be supervised because it is absent.", validated)}
	}
	runtimeId, err := requirePodmanRuntimeId(container.RuntimeId)
	if err != nil {
		return err
	}
	description, err := podmanSupervisorDescription(container.Labels, runtimeId)
	if err != nil {
		return err
	}
	unit, err := c.observeSupervisor(ctx, validated)
	if err != nil {
		return err
	}
	if unit.state != SystemdAllocationStateAbsent && unit.description != description {
		return podmanSupervisorFenceError(validated)
	}
	if container.Running && unit.state != SystemdAllocationStateRunning &&
		unit.state != SystemdAllocationStateStarting && unit.state != SystemdAllocationStateStopping {
		return podmanUnsupervisedError(validated)
	}
	switch unit.state {
	case SystemdAllocationStateRunning, SystemdAllocationStateStarting:
		return nil
	case SystemdAllocationStateStopping:
		return &InvalidOperationError{Message: fmt.Sprintf(
			"Podman supervisor %s is stopping and must settle before it can start.", unit.name)}
	case SystemdAllocationStateStopped, SystemdAllocationStateFailed:
		if unit.state == SystemdAllocationStateFailed {
			if err := c.systemctl(ctx, "reset-failed", unit.name); err != nil {
				return err
			}
		}
		if err := c.awaitSupervisorCollection(ctx, validated, description); err != nil {
			return err
		}
		return c.startTransientUnit(ctx, validated, runtimeId, description)
	case SystemdAllocationStateAbsent:
		return c.startTransientUnit(ctx, validated, runtimeId, description)
	default:
		return &InvalidOperationError{Message: fmt.Sprintf(
			"Podman supervisor %s returned an unsupported state.", unit.name)}
	}
}

// Stop asks the matching systemd user unit to stop. Its fixed ExecStop calls
// rootless podman stop with a bounded grace period. A live container without
// that unit is refused instead of being mutated outside its supervisor.
func (c *SystemdUserPodmanClient) Stop(ctx context.Context, containerId string) error {
	validated, err := c.validateContainer(ctx, containerId)
	if err != nil {
		return err
	}
	container, err := c.client.Inspect(ctx, validated)
	if err != nil {
		return err
	}
	unit, err := c.observeSupervisor(ctx, validated)
	if err != nil {
		return err
	}
	if container.State == PodmanAllocationStateAbsent {
		if unit.state != SystemdAllocationStateAbsent {
			return &InvalidOperationError{Message: fmt.Sprintf(
				"Podman supervisor %s exists without its container.", unit.name)}
		}
		return nil
	}
	runtimeId, err := requirePodmanRuntimeId(container.RuntimeId)
	if err != nil {
		return err
	}
	description, err := podmanSupervisorDescription(container.Labels, runtimeId)
	if err != nil {
		return err
	}
	if unit.state != SystemdAllocationStateAbsent && unit.description != description {
		return podmanSupervisorFenceError(validated)
	}
	switch unit.state {
	case SystemdAllocationStateRunning, SystemdAllocationStateStarting:
		return c.systemctl(ctx, "stop", unit.name)
	case SystemdAllocationStateStopping:
		// systemctl waits for the existing stop job, which keeps Delete from
		// racing podman rm against a still-running ExecStop.
		return c.systemctl(ctx, "stop", unit.name)
	case SystemdAllocationStateStopped, SystemdAllocationStateFailed:
		if container.Running {
			return podmanUnsupervisedError(validated)
		}
		return nil
	case SystemdAllocationStateAbsent:
		if container.Running || container.State == PodmanAllocationStateStarting ||
			container.State == PodmanAllocationStateStopping {
			return podmanUnsupervisedError(validated)
		}
		return nil
	default:
		return &InvalidOperationError{Message: fmt.Sprintf(
			"Podman supervisor %s returned an unsupported state.", unit.name)}
	}
}

// Delete stops through systemd when necessary, then removes the stopped
// container through Podman. A failed transient unit is reset so --collect can
// unload it; deletion never calls podman rm while a fenced supervisor is live.
func (c *SystemdUserPodmanClient) Delete(ctx context.Context, containerId string) error {
	validated, err := c.validateContainer(ctx, containerId)
	if err != nil {
		return err
	}
	container, err := c.client.Inspect(ctx, validated)
	if err != nil {
		return err
	}
	unit, err := c.observeSupervisor(ctx, validated)
	if err != nil {
		return err
	}
	if container.State == PodmanAllocationStateAbsent {
		if unit.state != SystemdAllocationStateAbsent {
			return &InvalidOperationError{Message: fmt.Sprintf(
				"Podman supervisor %s exists without its container.", unit.name)}
		}
		return nil
	}
	runtimeId, err := requirePodmanRuntimeId(container.RuntimeId)
	if err != nil {
		return err
	}
	description, err := podmanSupervisorDescription(container.Labels, runtimeId)
	if err != nil {
		return err
	}
	if unit.state != SystemdAllocationStateAbsent && unit.description != description {
		return podmanSupervisorFenceError(validated)
	}
	if unit.state == SystemdAllocationStateRunning || unit.state == SystemdAllocationStateStarting ||
		unit.state == SystemdAllocationStateStopping || container.Running {
		if err := c.Stop(ctx, validated); err != nil {
			return err
		}
	}
	if unit.state == SystemdAllocationStateFailed {
		if err := c.systemctl(ctx, "reset-failed", unit.name); err != nil {
			return err
		}
	}
	if unit.state != SystemdAllocationStateAbsent {
		if err := c.awaitSupervisorCollection(ctx, validated, description); err != nil {
			return err
		}
	}
	return c.client.Delete(ctx, runtimeId)
}

// Inspect joins the Podman observation with its supervisor observation. A
// systemd restart in progress maps a stopped or created container to Starting;
// a live container whose unit disappeared fails closed as unsupervised.
func (c *SystemdUserPodmanClient) Inspect(
	ctx context.Context,
	containerId string,
) (PodmanAllocationObservation, error) {
	validated, err := c.validateContainer(ctx, containerId)
	if err != nil {
		return PodmanAllocationObservation{}, err
	}
	container, err := c.client.Inspect(ctx, validated)
	if err != nil {
		return PodmanAllocationObservation{}, err
	}
	unit, err := c.observeSupervisor(ctx, validated)
	if err != nil {
		return PodmanAllocationObservation{}, err
	}
	if container.State == PodmanAllocationStateAbsent {
		if unit.state != SystemdAllocationStateAbsent {
			return PodmanAllocationObservation{}, &InvalidOperationError{Message: fmt.Sprintf(
				"Podman supervisor %s exists without its container.", unit.name)}
		}
		return container, nil
	}
	runtimeId, err := requirePodmanRuntimeId(container.RuntimeId)
	if err != nil {
		return PodmanAllocationObservation{}, err
	}
	description, err := podmanSupervisorDescription(container.Labels, runtimeId)
	if err != nil {
		return PodmanAllocationObservation{}, err
	}
	if unit.state != SystemdAllocationStateAbsent && unit.description != description {
		return PodmanAllocationObservation{}, podmanSupervisorFenceError(validated)
	}
	switch unit.state {
	case SystemdAllocationStateRunning:
		if container.Running {
			return container, nil
		}
		return podmanObservationWithState(container, PodmanAllocationStateStarting)
	case SystemdAllocationStateStarting:
		return podmanObservationWithState(container, PodmanAllocationStateStarting)
	case SystemdAllocationStateStopping:
		return podmanObservationWithState(container, PodmanAllocationStateStopping)
	case SystemdAllocationStateFailed:
		if container.Running {
			return PodmanAllocationObservation{}, podmanUnsupervisedError(validated)
		}
		return podmanObservationWithState(container, PodmanAllocationStateFailed)
	case SystemdAllocationStateStopped:
		if container.Running {
			return PodmanAllocationObservation{}, podmanUnsupervisedError(validated)
		}
		return container, nil
	case SystemdAllocationStateAbsent:
		if container.Running || container.State == PodmanAllocationStateStarting ||
			container.State == PodmanAllocationStateStopping {
			return PodmanAllocationObservation{}, podmanUnsupervisedError(validated)
		}
		return container, nil
	default:
		return PodmanAllocationObservation{}, &InvalidOperationError{Message: fmt.Sprintf(
			"Podman supervisor %s returned an unsupported state.", unit.name)}
	}
}

// EnsureVolume delegates named-volume creation after boundary validation.
func (c *SystemdUserPodmanClient) EnsureVolume(ctx context.Context, name string) error {
	if err := c.validate(ctx); err != nil {
		return err
	}
	return c.client.EnsureVolume(ctx, name)
}

func (c *SystemdUserPodmanClient) startTransientUnit(
	ctx context.Context,
	containerId string,
	runtimeId string,
	description string,
) error {
	unitName := podmanSupervisorUnitName(containerId)
	arguments := []string{
		"--user",
		"--unit", unitName,
		"--collect",
		"--property", "Description=" + description,
		"--property", "Type=exec",
		"--property", "Restart=always",
		"--property", "RestartSec=" + podmanSupervisorRestartDelay,
		"--property", "TimeoutStopSec=" + podmanSupervisorStopTimeout,
		"--property", "KillMode=mixed",
		"--property", "Delegate=yes",
		"--property", "NoNewPrivileges=yes",
		"--property", fmt.Sprintf("ExecStop=%s stop --time %d %s",
			c.rootless.PodmanBinaryPath, podmanSupervisorStopTimeoutSeconds, runtimeId),
		"--setenv=XDG_RUNTIME_DIR=" + c.rootless.XdgRuntimeDir,
		"--",
		c.rootless.PodmanBinaryPath,
		"start", "--attach", runtimeId,
	}
	result, err := c.commandRunner.Run(ctx, c.systemdRunBinaryPath, arguments)
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return systemdUserPodmanCommandError("start", result)
	}
	return nil
}

func (c *SystemdUserPodmanClient) awaitSupervisorCollection(
	ctx context.Context,
	containerId string,
	description string,
) error {
	timer := time.NewTimer(podmanSupervisorCollectionTimeout)
	defer timer.Stop()
	ticker := time.NewTicker(podmanSupervisorCollectionPoll)
	defer ticker.Stop()
	for {
		unit, err := c.observeSupervisor(ctx, containerId)
		if err != nil {
			return err
		}
		if unit.state == SystemdAllocationStateAbsent {
			return nil
		}
		if unit.description != description {
			return podmanSupervisorFenceError(containerId)
		}
		if unit.state == SystemdAllocationStateRunning || unit.state == SystemdAllocationStateStarting {
			return &InvalidOperationError{Message: fmt.Sprintf(
				"Podman supervisor %s restarted while collection was pending.", unit.name)}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return &InvalidOperationError{Message: fmt.Sprintf(
				"Podman supervisor %s was not collected within %s.", unit.name,
				podmanSupervisorCollectionTimeout)}
		case <-ticker.C:
		}
	}
}

func (c *SystemdUserPodmanClient) systemctl(ctx context.Context, operation string, unitName string) error {
	result, err := c.commandRunner.Run(ctx, c.systemctlBinaryPath,
		[]string{"--user", operation, unitName})
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return systemdUserPodmanCommandError(operation, result)
	}
	return nil
}

type podmanSupervisorObservation struct {
	name        string
	state       SystemdAllocationState
	description string
}

func (c *SystemdUserPodmanClient) observeSupervisor(
	ctx context.Context,
	containerId string,
) (podmanSupervisorObservation, error) {
	unitName := podmanSupervisorUnitName(containerId)
	result, err := c.commandRunner.Run(ctx, c.systemctlBinaryPath, []string{
		"--user", "show", unitName,
		"--property=LoadState",
		"--property=ActiveState",
		"--property=Description",
	})
	if err != nil {
		return podmanSupervisorObservation{}, err
	}
	values := make(map[string]string, 3)
	for _, line := range strings.Split(result.StandardOutput, "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return podmanSupervisorObservation{}, &InvalidDataError{Message: fmt.Sprintf(
				"Systemd returned malformed supervisor data for container %s.", containerId)}
		}
		if _, duplicate := values[parts[0]]; duplicate {
			return podmanSupervisorObservation{}, &InvalidDataError{Message: fmt.Sprintf(
				"Systemd returned duplicate supervisor data for container %s.", containerId)}
		}
		values[parts[0]] = parts[1]
	}
	if values["LoadState"] == "not-found" {
		return podmanSupervisorObservation{
			name: unitName, state: SystemdAllocationStateAbsent,
		}, nil
	}
	if result.ExitCode != 0 {
		return podmanSupervisorObservation{}, systemdUserPodmanCommandError("inspect", result)
	}
	if values["LoadState"] != "loaded" {
		return podmanSupervisorObservation{}, &InvalidDataError{Message: fmt.Sprintf(
			"Systemd returned an unsupported load state for Podman supervisor %s.", unitName)}
	}
	var state SystemdAllocationState
	switch values["ActiveState"] {
	case "active":
		state = SystemdAllocationStateRunning
	case "activating", "reloading":
		state = SystemdAllocationStateStarting
	case "deactivating":
		state = SystemdAllocationStateStopping
	case "inactive":
		state = SystemdAllocationStateStopped
	case "failed":
		state = SystemdAllocationStateFailed
	default:
		return podmanSupervisorObservation{}, &InvalidDataError{Message: fmt.Sprintf(
			"Systemd returned an unknown active state for Podman supervisor %s.", unitName)}
	}
	return podmanSupervisorObservation{
		name: unitName, state: state, description: values["Description"],
	}, nil
}

func (c *SystemdUserPodmanClient) validate(ctx context.Context) error {
	if ctx == nil {
		return &ArgumentError{Param: "ctx", Message: "The podman supervisor context must not be nil."}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if c == nil || c.client == nil || c.commandRunner == nil {
		return &InvalidOperationError{Message: "The systemd user podman client is unavailable."}
	}
	if err := ValidateRootlessContext(c.rootless); err != nil {
		return err
	}
	if _, err := requirePodmanAbsolutePath(c.systemctlBinaryPath, "systemctlBinaryPath"); err != nil {
		return err
	}
	if _, err := requirePodmanAbsolutePath(c.systemdRunBinaryPath, "systemdRunBinaryPath"); err != nil {
		return err
	}
	return nil
}

func (c *SystemdUserPodmanClient) validateContainer(
	ctx context.Context,
	containerId string,
) (string, error) {
	if err := c.validate(ctx); err != nil {
		return "", err
	}
	return requirePodmanToken(containerId, "containerId",
		"Container ID must be a lowercase DNS-style token.")
}

func podmanSupervisorDescription(labels map[string]string, runtimeId string) (string, error) {
	if err := requirePodmanFencingLabels(labels); err != nil {
		return "", err
	}
	validatedRuntimeId, err := requirePodmanRuntimeId(runtimeId)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("TerraScale rootless Podman allocation %s plan %s container %s",
		labels[PodmanLabelAllocation], labels[PodmanLabelFingerprint], validatedRuntimeId), nil
}

func podmanSupervisorUnitName(containerId string) string { return containerId + ".service" }

func podmanObservationWithState(
	observation PodmanAllocationObservation,
	state PodmanAllocationState,
) (PodmanAllocationObservation, error) {
	if observation.Platform == "" {
		return NewPodmanAllocationObservation(
			state, observation.RuntimeId, observation.ImageReference,
			observation.Labels, state == PodmanAllocationStateRunning)
	}
	return NewPodmanAllocationObservation(
		state, observation.RuntimeId, observation.ImageReference,
		observation.Labels, state == PodmanAllocationStateRunning,
		observation.Platform)
}

func podmanSupervisorFenceError(containerId string) error {
	return &InvalidOperationError{Message: fmt.Sprintf(
		"Existing Podman supervisor for container %s is not owned by its fencing labels.", containerId)}
}

func podmanUnsupervisedError(containerId string) error {
	return &InvalidOperationError{Message: fmt.Sprintf(
		"Podman container %s is running without its fenced systemd user supervisor.", containerId)}
}

func systemdUserPodmanCommandError(operation string, result HostCommandResult) error {
	message := fmt.Sprintf("systemd user Podman %s failed with exit code %d.", operation, result.ExitCode)
	if trimmed := strings.TrimSpace(result.StandardError); trimmed != "" {
		message += " " + trimmed
	}
	return &InvalidOperationError{Message: message}
}

var _ PodmanClient = (*SystemdUserPodmanClient)(nil)
