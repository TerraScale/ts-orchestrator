// This file defines the rootless-podman hosting contracts of the
// rootless-hosting and autoscaling lane: the podman allocation observation
// vocabulary, the validated run request, the PodmanClient seam, and the
// fail-closed rootless execution context.
package runtime

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// PodmanAllocationState is the observed rootless-podman allocation state.
type PodmanAllocationState int

const (
	PodmanAllocationStateAbsent PodmanAllocationState = iota
	PodmanAllocationStateCreating
	PodmanAllocationStateStarting
	PodmanAllocationStateRunning
	PodmanAllocationStateStopped
	PodmanAllocationStateStopping
	PodmanAllocationStateFailed
)

func (s PodmanAllocationState) defined() bool {
	return s >= PodmanAllocationStateAbsent && s <= PodmanAllocationStateFailed
}

func (s PodmanAllocationState) String() string {
	names := [...]string{"Absent", "Creating", "Starting", "Running", "Stopped", "Stopping", "Failed"}
	if s >= 0 && int(s) < len(names) {
		return names[s]
	}
	return fmt.Sprintf("PodmanAllocationState(%d)", int(s))
}

// AllPodmanAllocationStates lists every allocation state in declared order.
var AllPodmanAllocationStates = []PodmanAllocationState{
	PodmanAllocationStateAbsent,
	PodmanAllocationStateCreating,
	PodmanAllocationStateStarting,
	PodmanAllocationStateRunning,
	PodmanAllocationStateStopped,
	PodmanAllocationStateStopping,
	PodmanAllocationStateFailed,
}

const (
	podmanMaximumImageReferenceLength = 512
	podmanMaximumLabelCount           = 32
	podmanMaximumLabelValueLength     = 128
	podmanMaximumLabelKeyLength       = 253
	podmanMaximumVolumeCount          = 64
	podmanMaximumCgroupParentDepth    = 8
	podmanMaximumPathLength           = 4096
	podmanMaximumCpuQuotaPercent      = 1000
	podmanMaximumCpuWeight            = 10000
	podmanMaximumCapabilityLength     = 32
	podmanMinimumPidsLimit            = 16
)

// podmanLabelKeyPattern accepts dot-separated bounded canonical tokens, the
// shape of the terrascale.* fencing labels.
var podmanLabelKeyPattern = regexp.MustCompile(
	`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$`)

// podmanCapabilityPattern accepts uppercase capability tokens such as ALL,
// NET_BIND_SERVICE, or CAP_NET_RAW.
var podmanCapabilityPattern = regexp.MustCompile(`^[A-Z0-9_]+$`)

// PodmanLabelAllocation is the podman label carrying the owning allocation ID.
const PodmanLabelAllocation = "terrascale.allocation"

// PodmanLabelFingerprint is the podman label carrying the canonical plan
// fingerprint of the owning plan.
const PodmanLabelFingerprint = "terrascale.fingerprint"

// requirePodmanToken enforces the shared bounded canonical token vocabulary
// (the same DNS-style token RuntimeAllocationId admits).
func requirePodmanToken(value, param, message string) (string, error) {
	if len(value) < 1 || len(value) > 63 || !runtimeAllocationTokenPattern.MatchString(value) {
		return "", &ArgumentError{Param: param, Message: message}
	}
	return value, nil
}

// requirePodmanAbsolutePath enforces a bounded absolute host path with no
// empty, dot, or dot-dot segments; the filesystem root itself is rejected.
func requirePodmanAbsolutePath(value, param string) (string, error) {
	if len(value) < 2 || len(value) > podmanMaximumPathLength || !strings.HasPrefix(value, "/") {
		return "", &ArgumentError{
			Param:   param,
			Message: "A bounded absolute path is required.",
		}
	}
	for _, segment := range strings.Split(value[1:], "/") {
		if segment == "" || segment == "." || segment == ".." {
			return "", &ArgumentError{
				Param:   param,
				Message: "Path segments must be nonempty and cannot traverse upward.",
			}
		}
	}
	return value, nil
}

// requirePodmanImageReference enforces a bounded, whitespace-free image
// reference that cannot be mistaken for a podman command flag.
func requirePodmanImageReference(value, param string) (string, error) {
	if value == "" || len(value) > podmanMaximumImageReferenceLength ||
		strings.HasPrefix(value, "-") || strings.ContainsFunc(value, isSpaceOrControlRune) {
		return "", &ArgumentError{
			Param:   param,
			Message: "Image reference must be bounded, whitespace-free, and flag-safe.",
		}
	}
	return value, nil
}

func isSpaceOrControlRune(r rune) bool { return r <= 0x20 || r == 0x7f }

// requirePodmanLabels snapshots and validates one label set. Keys are
// dot-separated canonical tokens and values are bounded, control-free, and
// flag-safe.
func requirePodmanLabels(labels map[string]string) (map[string]string, error) {
	snapshot := make(map[string]string, len(labels))
	if len(labels) > podmanMaximumLabelCount {
		return nil, &ArgumentError{
			Param: "labels",
			Message: fmt.Sprintf("Label input exceeds the bound of %d entries.",
				podmanMaximumLabelCount),
		}
	}
	for key, value := range labels {
		if len(key) < 1 || len(key) > podmanMaximumLabelKeyLength || !podmanLabelKeyPattern.MatchString(key) {
			return nil, &ArgumentError{
				Param:   "labels",
				Message: "Label keys must be dot-separated lowercase DNS-style tokens.",
			}
		}
		if value == "" || len(value) > podmanMaximumLabelValueLength ||
			strings.HasPrefix(value, "-") || strings.ContainsFunc(value, isSpaceOrControlRune) {
			return nil, &ArgumentError{
				Param:   "labels",
				Message: "Label values must be nonempty, bounded, and control-free.",
			}
		}
		snapshot[key] = value
	}
	return snapshot, nil
}

// requirePodmanCgroupParent enforces a bounded slash-separated token path
// under the user slice, for example terrascale/<allocation>.
func requirePodmanCgroupParent(value, param string) (string, error) {
	if value == "" {
		return "", &ArgumentError{Param: param, Message: "A cgroup parent is required."}
	}
	segments := strings.Split(value, "/")
	if len(segments) > podmanMaximumCgroupParentDepth {
		return "", &ArgumentError{
			Param: param,
			Message: fmt.Sprintf("Cgroup parent depth must not exceed %d segments.",
				podmanMaximumCgroupParentDepth),
		}
	}
	for _, segment := range segments {
		if _, err := requirePodmanToken(segment, param,
			"Cgroup parent segments must be lowercase DNS-style tokens."); err != nil {
			return "", err
		}
	}
	return value, nil
}

// PodmanAllocationObservation is one fenced rootless-podman observation.
type PodmanAllocationObservation struct {
	State          PodmanAllocationState
	ImageReference string
	Labels         map[string]string
	Running        bool
}

// NewPodmanAllocationObservation validates one observation. The state comes
// from the closed vocabulary, Running is true only for a Running allocation,
// and an Absent allocation carries no image and no labels.
func NewPodmanAllocationObservation(
	state PodmanAllocationState,
	imageReference string,
	labels map[string]string,
	running bool,
) (PodmanAllocationObservation, error) {
	if !state.defined() {
		return PodmanAllocationObservation{}, &ArgumentOutOfRangeError{Param: "state"}
	}
	if running != (state == PodmanAllocationStateRunning) {
		return PodmanAllocationObservation{}, &ArgumentError{
			Param:   "running",
			Message: "Running must be true exactly when the allocation state is Running.",
		}
	}
	if state == PodmanAllocationStateAbsent {
		if imageReference != "" || len(labels) > 0 {
			return PodmanAllocationObservation{}, &ArgumentError{
				Param:   "state",
				Message: "An absent allocation carries no image reference and no labels.",
			}
		}
		return PodmanAllocationObservation{State: state}, nil
	}
	validatedImage, err := requirePodmanImageReference(imageReference, "imageReference")
	if err != nil {
		return PodmanAllocationObservation{}, err
	}
	validatedLabels, err := requirePodmanLabels(labels)
	if err != nil {
		return PodmanAllocationObservation{}, err
	}
	return PodmanAllocationObservation{
		State:          state,
		ImageReference: validatedImage,
		Labels:         validatedLabels,
		Running:        running,
	}, nil
}

// PodmanVolumeMount mounts one named podman volume at one container path.
type PodmanVolumeMount struct {
	VolumeName  string
	Destination string
	ReadOnly    bool
}

// NewPodmanVolumeMount validates one volume mount. The volume name is a
// bounded canonical token and the destination is a bounded absolute container
// path other than the filesystem root.
func NewPodmanVolumeMount(volumeName string, destination string, readOnly bool) (PodmanVolumeMount, error) {
	validatedVolume, err := requirePodmanToken(volumeName, "volumeName",
		"Volume name must be a lowercase DNS-style token.")
	if err != nil {
		return PodmanVolumeMount{}, err
	}
	validatedDestination, err := requirePodmanAbsolutePath(destination, "destination")
	if err != nil {
		return PodmanVolumeMount{}, err
	}
	return PodmanVolumeMount{
		VolumeName:  validatedVolume,
		Destination: validatedDestination,
		ReadOnly:    readOnly,
	}, nil
}

// PodmanRunRequest is the exact rootless podman run envelope of one
// allocation. The read-only root filesystem, no-new-privileges, nonzero UID
// and GID, and the ALL capability drop are not caller-negotiable; the
// constructor fixes them so no caller can widen the safety envelope.
type PodmanRunRequest struct {
	ContainerId     string
	ImageReference  string
	Platform        string
	RunAsUser       uint32
	RunAsGroup      uint32
	ReadOnlyRootfs  bool
	NoNewPrivileges bool
	CapDrop         []string
	CgroupParent    string
	MemoryMaxBytes  int64
	PidsLimit       int
	CpuQuotaPercent int
	CpuWeight       int
	Volumes         []PodmanVolumeMount
	Labels          map[string]string
}

// NewPodmanRunRequest validates every field of one run request. Identifiers
// are bounded canonical tokens, the platform comes from the closed
// linux/amd64 and linux/arm64 vocabulary, the memory floor and task floor
// mirror the catalog resource policy, and volume destinations are unique.
func NewPodmanRunRequest(
	containerId string,
	imageReference string,
	platform string,
	runAsUser uint32,
	runAsGroup uint32,
	cgroupParent string,
	capDrop []string,
	memoryMaxBytes int64,
	pidsLimit int,
	cpuQuotaPercent int,
	cpuWeight int,
	volumes []PodmanVolumeMount,
	labels map[string]string,
) (PodmanRunRequest, error) {
	validatedContainer, err := requirePodmanToken(containerId, "containerId",
		"Container ID must be a lowercase DNS-style token.")
	if err != nil {
		return PodmanRunRequest{}, err
	}
	validatedImage, err := requirePodmanImageReference(imageReference, "imageReference")
	if err != nil {
		return PodmanRunRequest{}, err
	}
	if platform != "linux/amd64" && platform != "linux/arm64" {
		return PodmanRunRequest{}, &ArgumentOutOfRangeError{
			Param:   "platform",
			Message: "Platform must be linux/amd64 or linux/arm64.",
		}
	}
	if runAsUser == 0 {
		return PodmanRunRequest{}, &ArgumentError{
			Param:   "runAsUser",
			Message: "The rootless container must run as a nonzero UID.",
		}
	}
	if runAsGroup == 0 {
		return PodmanRunRequest{}, &ArgumentError{
			Param:   "runAsGroup",
			Message: "The rootless container must run as a nonzero GID.",
		}
	}
	validatedCgroupParent, err := requirePodmanCgroupParent(cgroupParent, "cgroupParent")
	if err != nil {
		return PodmanRunRequest{}, err
	}
	if len(capDrop) == 0 {
		return PodmanRunRequest{}, &ArgumentError{
			Param:   "capDrop",
			Message: "At least one capability drop is required.",
		}
	}
	dropped := make([]string, 0, len(capDrop))
	droppedAll := false
	for _, capability := range capDrop {
		if len(capability) < 1 || len(capability) > podmanMaximumCapabilityLength ||
			!podmanCapabilityPattern.MatchString(capability) {
			return PodmanRunRequest{}, &ArgumentError{
				Param:   "capDrop",
				Message: "Dropped capabilities must be uppercase tokens.",
			}
		}
		if capability == "ALL" {
			droppedAll = true
		}
		dropped = append(dropped, capability)
	}
	if !droppedAll {
		return PodmanRunRequest{}, &ArgumentError{
			Param:   "capDrop",
			Message: "The ALL capability drop is required.",
		}
	}
	if memoryMaxBytes < runtimeMinimumMemoryBytes {
		return PodmanRunRequest{}, &ArgumentOutOfRangeError{
			Param: "memoryMaxBytes",
			Message: fmt.Sprintf("Memory limit must be at least %d bytes.",
				runtimeMinimumMemoryBytes),
		}
	}
	if pidsLimit < podmanMinimumPidsLimit {
		return PodmanRunRequest{}, &ArgumentOutOfRangeError{
			Param:   "pidsLimit",
			Message: fmt.Sprintf("PID limit must be at least %d.", podmanMinimumPidsLimit),
		}
	}
	if cpuQuotaPercent < 10 || cpuQuotaPercent > podmanMaximumCpuQuotaPercent {
		return PodmanRunRequest{}, &ArgumentOutOfRangeError{
			Param: "cpuQuotaPercent",
			Message: fmt.Sprintf("CPU quota must be between 10 and %d percent.",
				podmanMaximumCpuQuotaPercent),
		}
	}
	if cpuWeight < 1 || cpuWeight > podmanMaximumCpuWeight {
		return PodmanRunRequest{}, &ArgumentOutOfRangeError{
			Param:   "cpuWeight",
			Message: fmt.Sprintf("CPU weight must be between 1 and %d.", podmanMaximumCpuWeight),
		}
	}
	if len(volumes) > podmanMaximumVolumeCount {
		return PodmanRunRequest{}, &ArgumentError{
			Param: "volumes",
			Message: fmt.Sprintf("Volume input exceeds the bound of %d entries.",
				podmanMaximumVolumeCount),
		}
	}
	volumeSnapshot := make([]PodmanVolumeMount, 0, len(volumes))
	seenVolumeNames := make(map[string]struct{}, len(volumes))
	seenDestinations := make(map[string]struct{}, len(volumes))
	for _, mount := range volumes {
		validated, err := NewPodmanVolumeMount(mount.VolumeName, mount.Destination, mount.ReadOnly)
		if err != nil {
			return PodmanRunRequest{}, err
		}
		if _, duplicate := seenVolumeNames[validated.VolumeName]; duplicate {
			return PodmanRunRequest{}, &ArgumentError{
				Param:   "volumes",
				Message: "A named volume may be mounted only once per allocation.",
			}
		}
		if _, duplicate := seenDestinations[validated.Destination]; duplicate {
			return PodmanRunRequest{}, &ArgumentError{
				Param:   "volumes",
				Message: "Volume destinations must be unique.",
			}
		}
		seenVolumeNames[validated.VolumeName] = struct{}{}
		seenDestinations[validated.Destination] = struct{}{}
		volumeSnapshot = append(volumeSnapshot, validated)
	}
	labelSnapshot, err := requirePodmanLabels(labels)
	if err != nil {
		return PodmanRunRequest{}, err
	}
	return PodmanRunRequest{
		ContainerId:     validatedContainer,
		ImageReference:  validatedImage,
		Platform:        platform,
		RunAsUser:       runAsUser,
		RunAsGroup:      runAsGroup,
		ReadOnlyRootfs:  true,
		NoNewPrivileges: true,
		CapDrop:         dropped,
		CgroupParent:    validatedCgroupParent,
		MemoryMaxBytes:  memoryMaxBytes,
		PidsLimit:       pidsLimit,
		CpuQuotaPercent: cpuQuotaPercent,
		CpuWeight:       cpuWeight,
		Volumes:         volumeSnapshot,
		Labels:          labelSnapshot,
	}, nil
}

// PodmanClient ports the internal rootless-podman client seam. Every
// implementation must fail closed: it refuses to run as uid 0 and fences
// existing containers by the terrascale.allocation and
// terrascale.fingerprint labels.
type PodmanClient interface {
	// Preflight proves the rootless podman environment is usable.
	Preflight(ctx context.Context) error
	// Pull resolves one image reference for one platform.
	Pull(ctx context.Context, imageReference string, platform string) error
	// Create creates the container described by the request without
	// starting it.
	Create(ctx context.Context, request PodmanRunRequest) error
	// Start starts one created container.
	Start(ctx context.Context, containerId string) error
	// Stop stops one running container.
	Stop(ctx context.Context, containerId string) error
	// Delete removes one stopped container.
	Delete(ctx context.Context, containerId string) error
	// Inspect returns one fenced observation of one container.
	Inspect(ctx context.Context, containerId string) (PodmanAllocationObservation, error)
	// EnsureVolume creates one named volume when absent.
	EnsureVolume(ctx context.Context, name string) error
}

// RootlessPodmanContext is the explicit rootless execution context of one
// podman client. RunAsUid 0 is forbidden: rootless safety is the point of
// this lane, so validation fails closed on it.
type RootlessPodmanContext struct {
	PodmanBinaryPath string
	XdgRuntimeDir    string
	RunAsUid         uint32
}

// ValidateRootlessContext fails closed unless the context names a bounded
// absolute podman binary, a bounded absolute XDG runtime directory, and a
// nonzero run UID.
func ValidateRootlessContext(rootless RootlessPodmanContext) error {
	if rootless.RunAsUid == 0 {
		return &ArgumentError{
			Param:   "RunAsUid",
			Message: "Rootless podman must never run as uid 0.",
		}
	}
	if _, err := requirePodmanAbsolutePath(rootless.PodmanBinaryPath, "PodmanBinaryPath"); err != nil {
		return err
	}
	if _, err := requirePodmanAbsolutePath(rootless.XdgRuntimeDir, "XdgRuntimeDir"); err != nil {
		return err
	}
	return nil
}

// NewRootlessPodmanContext validates and snapshots one rootless context.
func NewRootlessPodmanContext(podmanBinaryPath string, xdgRuntimeDir string, runAsUid uint32) (RootlessPodmanContext, error) {
	candidate := RootlessPodmanContext{
		PodmanBinaryPath: podmanBinaryPath,
		XdgRuntimeDir:    xdgRuntimeDir,
		RunAsUid:         runAsUid,
	}
	if err := ValidateRootlessContext(candidate); err != nil {
		return RootlessPodmanContext{}, err
	}
	return candidate, nil
}
