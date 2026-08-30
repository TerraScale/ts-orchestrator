// This file implements the process-based rootless-podman client of the
// rootless-hosting and autoscaling lane. It execs the podman binary named by
// the validated RootlessPodmanContext through the injectable HostCommandRunner
// seam (never a shell, never a PATH lookup) and fails closed unless the
// context proves the invocation is rootless.
package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
)

// ProcessPodmanClient implements PodmanClient by exec-ing the podman binary
// named by the rootless context. Before every command the client revalidates
// the fail-closed rootless context (nonzero UID, bounded absolute XDG runtime
// directory, bounded absolute binary path) and invokes the absolute binary
// path, so no command can resolve a different executable through PATH and no
// command can run as uid 0. The HostCommandRunner seam carries no environment
// of its own: the composition root must run this client under the
// unprivileged account whose XDG_RUNTIME_DIR equals the validated context
// value.
type ProcessPodmanClient struct {
	rootless      RootlessPodmanContext
	commandRunner HostCommandRunner
}

// NewProcessPodmanClient validates the rootless context and composes the
// client with its command runner. The configuration is fully explicit; no
// ambient environment is read.
func NewProcessPodmanClient(
	rootless RootlessPodmanContext,
	commandRunner HostCommandRunner,
) (*ProcessPodmanClient, error) {
	if err := ValidateRootlessContext(rootless); err != nil {
		return nil, err
	}
	if commandRunner == nil {
		return nil, &ArgumentError{Param: "commandRunner", Message: "A host command runner is required."}
	}
	return &ProcessPodmanClient{rootless: rootless, commandRunner: commandRunner}, nil
}

// Preflight proves the rootless podman environment is usable by running one
// podman info command; a nonzero exit fails closed with the trimmed stderr.
func (c *ProcessPodmanClient) Preflight(ctx context.Context) error {
	result, err := c.podman(ctx, []string{"info"})
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return podmanCommandError("info", result.ExitCode, result.StandardError)
	}
	return nil
}

// Pull resolves one image reference for one platform.
func (c *ProcessPodmanClient) Pull(ctx context.Context, imageReference string, platform string) error {
	validatedImage, err := requirePodmanImageReference(imageReference, "imageReference")
	if err != nil {
		return err
	}
	if err := requirePodmanPlatform(platform); err != nil {
		return err
	}
	result, err := c.podman(ctx, []string{"pull", "--platform", platform, validatedImage})
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return podmanCommandError("pull", result.ExitCode, result.StandardError)
	}
	return nil
}

// Create creates the container described by the request with one
// `podman create` and does not start it; Start starts the created container.
// The request is revalidated and re-pinned through NewPodmanRunRequest first,
// so a hand-built struct cannot widen the safety envelope: the read-only root
// filesystem, no-new-privileges, and the ALL capability drop stay fixed no
// matter what the caller passed in. The seccomp profile path is not
// caller-controlled either: it always comes from the validated rootless
// context, so no request can strip the profile the canonical plan attests.
func (c *ProcessPodmanClient) Create(ctx context.Context, request PodmanRunRequest) error {
	// The rootless safety fields are invariants, not caller-controlled options.
	// Pin them before revalidation so a hand-built request cannot widen the
	// container's privilege envelope.
	request.ReadOnlyRootfs = true
	request.NoNewPrivileges = true
	request.CapDrop = []string{"ALL"}
	normalized, err := NewPodmanRunRequest(
		request.ContainerId,
		request.ImageReference,
		request.Platform,
		request.RunAsUser,
		request.RunAsGroup,
		request.CgroupParent,
		request.CapDrop,
		request.MemoryMaxBytes,
		request.PidsLimit,
		request.CpuQuotaPercent,
		request.CpuWeight,
		request.Volumes,
		request.Labels,
	)
	if err != nil {
		return err
	}
	result, err := c.podman(ctx, podmanCreateArguments(normalized, c.rootless.SeccompProfilePath))
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return podmanCommandError("create", result.ExitCode, result.StandardError)
	}
	return nil
}

// Start starts one created container.
func (c *ProcessPodmanClient) Start(ctx context.Context, containerId string) error {
	validated, err := requirePodmanToken(containerId, "containerId",
		"Container ID must be a lowercase DNS-style token.")
	if err != nil {
		return err
	}
	result, err := c.podman(ctx, []string{"start", validated})
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return podmanCommandError("start", result.ExitCode, result.StandardError)
	}
	return nil
}

// Stop stops one running container.
func (c *ProcessPodmanClient) Stop(ctx context.Context, containerId string) error {
	validated, err := requirePodmanToken(containerId, "containerId",
		"Container ID must be a lowercase DNS-style token.")
	if err != nil {
		return err
	}
	result, err := c.podman(ctx, []string{"stop", validated})
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return podmanCommandError("stop", result.ExitCode, result.StandardError)
	}
	return nil
}

// Delete removes one container with `podman rm -f`, which force-stops it
// first when a process is still attached.
func (c *ProcessPodmanClient) Delete(ctx context.Context, containerId string) error {
	validated, err := requirePodmanToken(containerId, "containerId",
		"Container ID must be a lowercase DNS-style token.")
	if err != nil {
		return err
	}
	result, err := c.podman(ctx, []string{"rm", "-f", validated})
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return podmanCommandError("rm", result.ExitCode, result.StandardError)
	}
	return nil
}

// Inspect returns one fenced observation of one container, parsed from the
// `podman container inspect --format json` document. A no-such-container
// failure maps to the Absent state and stays distinguishable from every other
// nonzero exit, which fails closed as an invalid operation.
func (c *ProcessPodmanClient) Inspect(ctx context.Context, containerId string) (PodmanAllocationObservation, error) {
	validated, err := requirePodmanToken(containerId, "containerId",
		"Container ID must be a lowercase DNS-style token.")
	if err != nil {
		return PodmanAllocationObservation{}, err
	}
	result, err := c.podman(ctx, []string{"container", "inspect", "--format", "json", validated})
	if err != nil {
		return PodmanAllocationObservation{}, err
	}
	if result.ExitCode != 0 {
		if isPodmanNoSuchContainer(result.StandardError) {
			return NewPodmanAllocationObservation(PodmanAllocationStateAbsent, "", nil, false)
		}
		return PodmanAllocationObservation{}, podmanCommandError(
			"container inspect", result.ExitCode, result.StandardError)
	}
	var documents []podmanContainerInspectDocument
	if err := json.Unmarshal([]byte(result.StandardOutput), &documents); err != nil {
		return PodmanAllocationObservation{}, &InvalidDataError{
			Message: fmt.Sprintf("Podman inspect returned malformed JSON for container %s.", validated),
		}
	}
	if len(documents) != 1 {
		return PodmanAllocationObservation{}, &InvalidDataError{
			Message: fmt.Sprintf("Podman inspect must return exactly one document for container %s.", validated),
		}
	}
	state, err := podmanAllocationStateFrom(documents[0].State.Status, validated)
	if err != nil {
		return PodmanAllocationObservation{}, err
	}
	observedPlatform := podmanObservedPlatform(documents[0])
	if observedPlatform == "" {
		return NewPodmanAllocationObservation(
			state, documents[0].Config.Image, documents[0].Config.Labels, documents[0].State.Running)
	}
	return NewPodmanAllocationObservation(
		state, documents[0].Config.Image, documents[0].Config.Labels, documents[0].State.Running,
		observedPlatform)
}

// EnsureVolume creates one named volume when absent. Creating an existing
// volume is success: podman volume create is idempotent, and an
// already-exists diagnostic is treated the same way.
func (c *ProcessPodmanClient) EnsureVolume(ctx context.Context, name string) error {
	validated, err := requirePodmanToken(name, "name",
		"Volume name must be a lowercase DNS-style token.")
	if err != nil {
		return err
	}
	result, err := c.podman(ctx, []string{"volume", "create", validated})
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		if isPodmanVolumeAlreadyPresent(result.StandardError) {
			return nil
		}
		return podmanCommandError("volume create", result.ExitCode, result.StandardError)
	}
	return nil
}

// podman executes one podman argument vector through the command runner. The
// rootless context is revalidated before ANY command so a tampered context
// (uid 0, empty runtime directory, relative binary path) fails closed before
// a process is ever spawned.
func (c *ProcessPodmanClient) podman(ctx context.Context, arguments []string) (HostCommandResult, error) {
	if ctx == nil {
		return HostCommandResult{}, &ArgumentError{Param: "ctx", Message: "The podman context must not be nil."}
	}
	if c == nil || c.commandRunner == nil {
		return HostCommandResult{}, &InvalidOperationError{Message: "The podman command runner is unavailable."}
	}
	if err := ValidateRootlessContext(c.rootless); err != nil {
		return HostCommandResult{}, err
	}
	return c.commandRunner.Run(ctx, c.rootless.PodmanBinaryPath, arguments)
}

// podmanContainerInspectDocument is the bounded local view of one
// `podman container inspect --format json` document. Unknown fields are
// ignored; only the state, the image, and the labels feed the observation.
type podmanContainerInspectDocument struct {
	Platform     string `json:"Platform"`
	Architecture string `json:"Architecture"`
	State        struct {
		Status  string `json:"Status"`
		Running bool   `json:"Running"`
	} `json:"State"`
	Config struct {
		Image    string            `json:"Image"`
		Platform string            `json:"Platform"`
		Labels   map[string]string `json:"Labels"`
	} `json:"Config"`
}

func podmanObservedPlatform(document podmanContainerInspectDocument) string {
	if document.Platform == "linux" && document.Architecture != "" {
		return "linux/" + document.Architecture
	}
	if document.Platform == "linux/amd64" || document.Platform == "linux/arm64" {
		return document.Platform
	}
	if document.Config.Platform == "linux/amd64" || document.Config.Platform == "linux/arm64" {
		return document.Config.Platform
	}
	return ""
}

// podmanAllocationStateFrom maps one observed podman State.Status onto the
// closed allocation vocabulary, case-insensitively because podman reports
// lowercase statuses: created maps to Creating; configured, stopped, and
// docker-style exited map to Stopped; stopping maps to Stopping; dead and
// paused map to Failed; and every unrecognized status fails closed as invalid
// data. A status whose Running flag disagrees with its mapped state is
// rejected by NewPodmanAllocationObservation.
func podmanAllocationStateFrom(status string, containerId string) (PodmanAllocationState, error) {
	switch {
	case strings.EqualFold(status, "created"):
		return PodmanAllocationStateCreating, nil
	case strings.EqualFold(status, "running"):
		return PodmanAllocationStateRunning, nil
	case strings.EqualFold(status, "configured"),
		strings.EqualFold(status, "stopped"),
		strings.EqualFold(status, "exited"):
		return PodmanAllocationStateStopped, nil
	case strings.EqualFold(status, "stopping"):
		return PodmanAllocationStateStopping, nil
	case strings.EqualFold(status, "dead"), strings.EqualFold(status, "paused"):
		return PodmanAllocationStateFailed, nil
	default:
		return PodmanAllocationStateAbsent, &InvalidDataError{
			Message: fmt.Sprintf(
				"Podman inspect returned the unrecognized state %q for container %s.", status, containerId),
		}
	}
}

// podmanCreateArguments renders the exact argument vector of one validated
// `podman create` invocation. The order is fixed, capability drops keep their
// validated order, volumes keep their validated order, and labels are emitted
// in sorted key order so the vector is fully deterministic. Every dynamic
// value occupies its own argument, so no value can smuggle an extra flag.
//
// The vector applies the plan's memory, PID, and CPU limits but deliberately
// omits three resource dimensions this podman surface cannot express: podman
// has no --nice for the plan's Nice, no --memory-high for the derived memory
// high watermark, and its --blkio-weight domain (10..1000, device-relative,
// often without an io controller under rootless cgroup v2) differs from the
// plan's IoWeight, so forwarding it could reject valid plans or silently
// mis-scale them. Those three dimensions are enforced only by the native
// systemd driver; the seccomp profile, in contrast, is always loaded from the
// context's validated absolute path.
func podmanCreateArguments(request PodmanRunRequest, seccompProfilePath string) []string {
	arguments := make([]string, 0, 28+2*len(request.CapDrop)+2*len(request.Volumes)+2*len(request.Labels))
	arguments = append(arguments,
		"create",
		"--name", request.ContainerId,
		"--platform", request.Platform,
		"--user", strconv.FormatUint(uint64(request.RunAsUser), 10)+":"+
			strconv.FormatUint(uint64(request.RunAsGroup), 10),
		// The safety envelope is unconditional: the validated request always
		// carries a read-only root filesystem, no-new-privileges, and the ALL
		// capability drop, and the vector never omits them. The seccomp
		// profile path always comes from the validated rootless context, and
		// podman fails the create when its document is absent, so a container
		// can never fall back to the built-in default profile unnoticed.
		"--read-only",
		"--security-opt", "no-new-privileges",
		"--security-opt", "seccomp="+seccompProfilePath)
	for _, capability := range request.CapDrop {
		arguments = append(arguments, "--cap-drop", capability)
	}
	arguments = append(arguments,
		"--cgroup-parent", podmanSystemdSliceName(request.CgroupParent),
		"--memory", strconv.FormatInt(request.MemoryMaxBytes, 10),
		"--pids-limit", strconv.Itoa(request.PidsLimit),
		// --cpu-quota is microseconds per --cpu-period (default 100000us), so
		// the plan's percent converts by one thousand: 100 percent is exactly
		// one CPU per period, and the runtime rejects every sub-millisecond
		// quota (crun: write to cpu.max: Invalid argument).
		"--cpu-quota", strconv.Itoa(request.CpuQuotaPercent*1000),
		"--cpu-shares", strconv.Itoa(request.CpuWeight),
		"--restart=no")
	for _, mount := range request.Volumes {
		permissions := "rw"
		if mount.ReadOnly {
			permissions = "ro"
		}
		arguments = append(arguments, "--volume", mount.VolumeName+":"+mount.Destination+":"+permissions)
	}
	for _, key := range slices.Sorted(maps.Keys(request.Labels)) {
		arguments = append(arguments, "--label", key+"="+request.Labels[key])
	}
	arguments = append(arguments, request.ImageReference)
	return arguments
}

// podmanSystemdSliceName maps one validated canonical cgroup parent path onto
// the systemd slice name rootless podman's cgroup manager requires on cgroup
// v2: slash separators become dashes and the slice suffix is appended, so
// terrascale/<allocation> becomes terrascale-<allocation>.slice. Podman
// rejects every other spelling ("did not receive systemd slice as cgroup
// parent"), and the slice is created under the caller's own user manager, so
// the canonical path keeps meaning "under the user's slice, never a system
// slice".
func podmanSystemdSliceName(cgroupParent string) string {
	return strings.ReplaceAll(cgroupParent, "/", "-") + ".slice"
}

// requirePodmanPlatform enforces the closed platform vocabulary shared with
// NewPodmanRunRequest.
func requirePodmanPlatform(platform string) error {
	if platform != "linux/amd64" && platform != "linux/arm64" {
		return &ArgumentOutOfRangeError{
			Param:   "platform",
			Message: "Platform must be linux/amd64 or linux/arm64.",
		}
	}
	return nil
}

// isPodmanNoSuchContainer recognizes the stderr of a podman inspect against a
// container that does not exist, so absence stays distinguishable from real
// failures.
func isPodmanNoSuchContainer(standardError string) bool {
	normalized := strings.ToLower(strings.TrimSpace(standardError))
	return strings.Contains(normalized, "no such container") ||
		strings.Contains(normalized, "no container with name")
}

// isPodmanVolumeAlreadyPresent recognizes the stderr of a failed volume
// create that reports the volume is already present.
func isPodmanVolumeAlreadyPresent(standardError string) bool {
	normalized := strings.ToLower(strings.TrimSpace(standardError))
	return strings.Contains(normalized, "already exist") ||
		strings.Contains(normalized, "already in use")
}

// podmanCommandError renders one nonzero podman exit as a deterministic
// invalid-operation error carrying the trimmed stderr; it never panics and
// never includes anything beyond the subcommand, the exit code, and podman's
// own diagnostic.
func podmanCommandError(subcommand string, exitCode int, standardError string) error {
	message := fmt.Sprintf("podman %s failed with exit code %d.", subcommand, exitCode)
	if trimmed := strings.TrimSpace(standardError); trimmed != "" {
		message = fmt.Sprintf("%s %s", message, trimmed)
	}
	return &InvalidOperationError{Message: message}
}
